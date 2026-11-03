"""疑似 PCDN 风险评分引擎：滑动窗口 + 规则 + 白名单折算 + 连续确认。

- 所有阈值/分值来自 config.json 的 rules 段，未配置时使用内置默认值。
- 每条规则必须连续 consecutive_cycles 个评估周期命中才计入分数，避免瞬时误报。
- 白名单进程按 weight(0~1) 折算该进程可归属规则的得分；weight=0 表示忽略。
  白名单只影响评分，不影响原始数据记录。
- 结论统一使用"疑似风险"措辞，本引擎不输出确定性判断。
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from models import MonitorSample, ProcessSnapshot, RiskAssessment, RuleResult
from utils import SampleWindow, format_bytes, longest_sustained, network_of

log = logging.getLogger("pcdn.detector")

LEVEL_LOW, LEVEL_SUSPICIOUS, LEVEL_HIGH, LEVEL_CRITICAL = "低", "可疑", "高", "严重"
LEVEL_ORDER = {LEVEL_LOW: 0, LEVEL_SUSPICIOUS: 1, LEVEL_HIGH: 2, LEVEL_CRITICAL: 3}


def min_score_for_level(level: str, score_levels: dict) -> int:
    """把等级名称换算成达到该等级所需的最低分数。"""
    table = {
        LEVEL_LOW: 0,
        LEVEL_SUSPICIOUS: int(score_levels.get("low_max", 29)) + 1,
        LEVEL_HIGH: int(score_levels.get("suspicious_max", 59)) + 1,
        LEVEL_CRITICAL: int(score_levels.get("high_max", 79)) + 1,
    }
    return table.get(level, 30)


# ---------------------------------------------------------------- 白名单

@dataclass
class WhitelistEntry:
    weight: float = 0.0
    reason: str = "whitelist"
    name: Optional[str] = None       # 进程名（不含路径，忽略大小写）
    path: Optional[str] = None       # 可执行目录前缀（忽略大小写）
    pid: Optional[int] = None
    remote_ip: Optional[str] = None
    port: Optional[int] = None


class Whitelist:
    """按 进程名/路径/PID/远端IP/端口 匹配的白名单。"""

    def __init__(self, entries: Optional[list] = None):
        self.entries: List[WhitelistEntry] = []
        for raw in entries or []:
            if not isinstance(raw, dict):
                continue
            path = raw.get("path")
            self.entries.append(WhitelistEntry(
                name=str(raw["name"]).lower() if raw.get("name") else None,
                path=normalize_win(path) if path else None,
                pid=int(raw["pid"]) if raw.get("pid") is not None else None,
                remote_ip=str(raw["remote_ip"]) if raw.get("remote_ip") else None,
                port=int(raw["port"]) if raw.get("port") is not None else None,
                weight=float(raw.get("weight", 0.0)),
                reason=str(raw.get("reason") or "whitelist"),
            ))

    def match_process(self, snap: Optional[ProcessSnapshot]) -> Optional[WhitelistEntry]:
        if snap is None:
            return None
        for e in self.entries:
            if e.pid is not None and snap.pid == e.pid:
                return e
            if e.name and snap.name and snap.name.lower() == e.name:
                return e
            if e.path and snap.exe:
                exe = normalize_win(snap.exe)
                if exe == e.path or exe.startswith(e.path + "\\"):
                    return e
        return None

    def match_remote(self, ip: Optional[str], port: Optional[int]) -> Optional[WhitelistEntry]:
        for e in self.entries:
            if e.remote_ip and ip and e.remote_ip == ip:
                return e
            if e.port is not None and port is not None and e.remote_ip is None and e.port == port:
                return e
        return None


def normalize_win(path: str) -> str:
    return str(path).replace("/", "\\").lower().rstrip("\\")


# ---------------------------------------------------------------- 规则

@dataclass
class RuleFire:
    evidence: str
    pids: List[int] = field(default_factory=list)


@dataclass(frozen=True)
class RuleDef:
    rule_id: str
    description: str
    default_points: int
    check: Callable[[List[MonitorSample], dict, float, Whitelist], Optional[RuleFire]]


def _filtered_public_ips(samples: List[MonitorSample], wl: Whitelist) -> set:
    """窗口内出现过的远端公网 IP 并集，剔除白名单 IP/端口目标。"""
    ips: set = set()
    for s in samples:
        ips |= s.total.remote_public_ips
    return {ip for ip in ips if not wl.match_remote(ip, None)}


def _filtered_remote_ports(samples: List[MonitorSample], wl: Whitelist) -> set:
    ports: set = set()
    for s in samples:
        ports |= s.total.remote_ports
    return {p for p in ports if not wl.match_remote(None, p)}


def _check_sustained_upload(samples, cfg, interval, wl):
    thr = float(cfg.get("mbps", 1.0)) * 1e6
    need = float(cfg.get("minutes", 10)) * 60
    dur = longest_sustained(
        samples, thr, max_gap=max(5.0, interval * 3),
        value=lambda s: s.traffic.up_bps, ts=lambda s: s.timestamp)
    if dur >= need:
        return RuleFire(f"上传≥{cfg.get('mbps', 1.0)}Mbps 最长持续 {dur / 60:.1f} 分钟")
    return None


def _check_upload_ratio(samples, cfg, interval, wl):
    up = sum(s.traffic.up_delta_bytes for s in samples)
    down = sum(s.traffic.down_delta_bytes for s in samples)
    if up < float(cfg.get("min_upload_mbytes", 10)) * 1024 * 1024:
        return None
    ratio_cfg = float(cfg.get("ratio", 2.0))
    ratio = (up / down) if down > 0 else float("inf")
    if ratio >= ratio_cfg:
        shown = "∞" if ratio == float("inf") else f"{ratio:.1f}"
        return RuleFire(f"窗口内上传 {format_bytes(up)} / 下载 {format_bytes(down)}，比例 {shown}")
    return None


def _check_many_public_ips(samples, cfg, interval, wl):
    thr = int(cfg.get("distinct_ips", 100))
    ips = _filtered_public_ips(samples, wl)
    if len(ips) >= thr:
        return RuleFire(f"窗口内连接了 {len(ips)} 个不同远端公网 IP")
    return None


def _check_dispersed_networks(samples, cfg, interval, wl):
    thr = int(cfg.get("distinct_networks", 50))
    nets = {network_of(ip) for ip in _filtered_public_ips(samples, wl)}
    nets.discard(None)
    if len(nets) >= thr:
        return RuleFire(f"远端 IP 分布在 {len(nets)} 个不同 /24(或/64) 网段")
    return None


def _check_dispersed_ports(samples, cfg, interval, wl):
    thr = int(cfg.get("distinct_ports", 200))
    ports = _filtered_remote_ports(samples, wl)
    if len(ports) >= thr:
        return RuleFire(f"远端端口高度分散：{len(ports)} 个不同端口")
    return None


def _check_udp_anomaly(samples, cfg, interval, wl):
    thr = int(cfg.get("udp_endpoints", 150))
    mx = max((s.total.udp_endpoints for s in samples), default=0)
    if mx >= thr:
        return RuleFire(f"UDP 端点数量异常：峰值 {mx} 个")
    return None


def _check_process_conns(samples, cfg, interval, wl):
    if not samples:
        return None
    latest = samples[-1]
    thr = int(cfg.get("connections", 80))
    pids, names = [], []
    for pid, st in latest.stats_by_pid.items():
        if not pid:  # 跳过未知 PID 与内核(pid 0)持有的套接字
            continue
        if st.tcp_connections >= thr:
            pids.append(pid)
            snap = latest.processes.get(pid)
            names.append(f"{snap.name if snap else '?'}(PID {pid}, {st.tcp_connections} 条TCP)")
    if not pids:
        return None
    return RuleFire("；".join(names[:5]) + ("…" if len(names) > 5 else ""), pids)


def _check_public_listeners(samples, cfg, interval, wl):
    if not samples:
        return None
    latest = samples[-1]
    thr = int(cfg.get("ports", 3))
    if latest.public_listener_ports >= thr:
        return RuleFire(
            f"{latest.public_listener_ports} 个对外(非回环)监听端口",
            sorted(pid for pid in latest.listener_pids if pid))
    return None


def _check_suspicious_path(samples, cfg, interval, wl):
    if not samples:
        return None
    latest = samples[-1]
    minc = int(cfg.get("min_connections", 3))
    pids, names = [], []
    for pid, snap in latest.processes.items():
        if not pid or not snap.path_suspicious:
            continue
        st = latest.stats_by_pid.get(pid)
        if st is not None and st.total_endpoints >= minc:
            pids.append(pid)
            names.append(f"{snap.name}(PID {pid})")
    if not pids:
        return None
    return RuleFire("；".join(names[:5]) + " 位于临时/缓存目录且有网络连接", pids)


def _check_autostart_activity(samples, cfg, interval, wl):
    if not samples:
        return None
    latest = samples[-1]
    minc = int(cfg.get("min_connections", 20))
    pids, names = [], []
    for pid, snap in latest.processes.items():
        if not pid or not snap.autostart:
            continue
        st = latest.stats_by_pid.get(pid)
        if st is not None and st.total_endpoints >= minc:
            pids.append(pid)
            names.append(f"{snap.name}(PID {pid})")
    if not pids:
        return None
    return RuleFire("；".join(names[:5]) + " 配置为开机自启且存在外连", pids)


RULES: List[RuleDef] = [
    RuleDef("sustained_upload", "持续高速上传", 20, _check_sustained_upload),
    RuleDef("upload_ratio", "上传/下载比例异常", 15, _check_upload_ratio),
    RuleDef("many_public_ips", "连接大量不同公网IP", 15, _check_many_public_ips),
    RuleDef("dispersed_networks", "远端网段高度分散", 10, _check_dispersed_networks),
    RuleDef("dispersed_ports", "远端端口高度分散", 10, _check_dispersed_ports),
    RuleDef("udp_anomaly", "UDP 会话数量异常", 10, _check_udp_anomaly),
    RuleDef("process_many_conns", "单进程大量外连", 10, _check_process_conns),
    RuleDef("public_listeners", "存在多个公网监听端口", 5, _check_public_listeners),
    RuleDef("suspicious_path", "可执行文件位于异常目录", 10, _check_suspicious_path),
    RuleDef("autostart_activity", "自启动进程存在异常外连", 5, _check_autostart_activity),
]


# ---------------------------------------------------------------- 评估器

class Detector:
    def __init__(self, config: dict, whitelist: Optional[Whitelist] = None):
        self.config = config
        self.rules_config = config.get("rules", {}) or {}
        self.whitelist = whitelist if whitelist is not None else Whitelist(config.get("whitelist"))
        self.window = SampleWindow(float(config.get("window_minutes", 12)) * 60)
        self.confirm_cycles = max(1, int(config.get("consecutive_cycles", 3)))
        self.interval = float(config.get("interval_seconds", 2) or 2)
        levels = config.get("score_levels", {}) or {}
        self.low_max = int(levels.get("low_max", 29))
        self.susp_max = int(levels.get("suspicious_max", 59))
        self.high_max = int(levels.get("high_max", 79))
        self._streaks: dict = {}
        self.last_assessment = None

    def add_sample(self, sample: MonitorSample) -> None:
        self.window.add(sample)

    def __len__(self) -> int:
        return len(self.window)

    def level_of(self, score: int) -> str:
        if score <= self.low_max:
            return LEVEL_LOW
        if score <= self.susp_max:
            return LEVEL_SUSPICIOUS
        if score <= self.high_max:
            return LEVEL_HIGH
        return LEVEL_CRITICAL

    def _apply_whitelist(self, pids: List[int], latest: Optional[MonitorSample],
                         points: float) -> tuple:
        """按命中白名单的进程权重折算得分；返回 (折算分, 命中说明列表)。

        规则命中多个进程时取其中最小权重折算；权重 0 表示整条规则忽略。
        """
        hits, weights = [], []
        for pid in pids:
            snap = latest.processes.get(pid) if latest is not None else None
            if snap is None:
                continue
            entry = self.whitelist.match_process(snap)
            if entry is not None:
                hits.append(f"{snap.name}({entry.reason}, 权重{entry.weight:g})")
                weights.append(entry.weight)
        if not weights:
            return points, hits
        eff = points * min(weights)
        if eff < 0.05:
            eff = 0.0
        return eff, hits

    def evaluate(self, force_confirm: bool = False):
        samples = self.window.samples()
        results = []
        total = 0.0
        for rule in RULES:
            rcfg = self.rules_config.get(rule.rule_id, {}) or {}
            fire = None
            error = False
            try:
                fire = rule.check(samples, rcfg, self.interval, self.whitelist)
            except Exception:
                error = True
                log.exception("规则 %s 评估失败，本周期按未命中处理", rule.rule_id)
            fired = fire is not None and not error
            streak = (self._streaks.get(rule.rule_id, 0) + 1) if fired else 0
            self._streaks[rule.rule_id] = streak
            confirmed = fired and (force_confirm or streak >= self.confirm_cycles)
            points = float(rcfg.get("points", rule.default_points))
            eff, hits = 0.0, []
            if fired:
                eff = points
                if fire.pids:
                    eff, hits = self._apply_whitelist(fire.pids,
                                                      samples[-1] if samples else None, points)
                if not confirmed:
                    eff = 0.0
            results.append(RuleResult(rule.rule_id, rule.description, points,
                                      fired, confirmed, round(eff, 1),
                                      fire.evidence if fire else "", hits))
            total += eff
        score = int(min(100, round(total)))
        assessment = RiskAssessment(time.time(), score, self.level_of(score), results)
        self.last_assessment = assessment
        return assessment
