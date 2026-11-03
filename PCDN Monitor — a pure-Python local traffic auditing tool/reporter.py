"""输出层：日志、样本 CSV、告警 JSONL、报告 JSON 与高风险提醒。

- 报告统一使用"疑似PCDN风险"措辞，并附局限性说明。
- 公网 IP 默认脱敏（config mask_public_ips）。
- 提醒仅弹窗/蜂鸣，绝不自动结束进程、封禁 IP 或修改防火墙。
"""
from __future__ import annotations

import csv
import json
import logging
import logging.handlers
import os
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Optional

from models import MonitorSample, RiskAssessment
from detector import LEVEL_SUSPICIOUS, min_score_for_level
from utils import format_bits, format_bytes, mask_ip, network_of

log = logging.getLogger("pcdn.reporter")

LIMITATION_NOTES = [
    "本报告为“疑似PCDN风险”启发式评估，不能作为确定性结论，请人工复核。",
    "psutil 无法精确统计每个进程的字节数流量：进程级数据仅为连接行为统计，"
    "上传/下载速率来自网卡计数器，二者不一一对应。",
    "仅采集流量与连接元数据，不记录任何数据包内容；数据只保存在本机。",
]


def setup_logging(log_file: Optional[Path], level: str = "INFO", console: bool = True):
    logger = logging.getLogger("pcdn")
    logger.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    logger.handlers.clear()
    logger.propagate = False
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    if log_file is not None:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.handlers.RotatingFileHandler(
                log_file, maxBytes=1024 * 1024, backupCount=3, encoding="utf-8")
            fh.setFormatter(fmt)
            logger.addHandler(fh)
        except OSError as exc:
            print(f"无法创建日志文件 {log_file}: {exc}", flush=True)
    if console:
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        sh.setLevel(logging.WARNING)
        logger.addHandler(sh)
    return logger


# ---------------------------------------------------------------- 会话统计

class ProcessAgg:
    """单个进程在整个会话期间的累计画像。"""

    _IP_CAP = 5000  # 防御性上限，避免极端情况下集合无限膨胀

    def __init__(self, pid):
        self.pid = pid
        self.name = "(未知)"
        self.exe: Optional[str] = None
        self.cmdline: Optional[list] = None
        self.username: Optional[str] = None
        self.max_tcp = 0
        self.max_udp = 0
        self.max_conns = 0
        self.public_ips: set = set()
        self.listening: set = set()
        self.path_suspicious = False
        self.autostart = False

    def update(self, snap, stats) -> None:
        if snap is not None:
            if snap.name and snap.name not in ("(未知PID)", "(未知)"):
                self.name = snap.name
            self.exe = self.exe or snap.exe
            self.cmdline = self.cmdline or snap.cmdline
            self.username = self.username or snap.username
            self.path_suspicious = self.path_suspicious or snap.path_suspicious
            self.autostart = self.autostart or snap.autostart
        self.max_tcp = max(self.max_tcp, stats.tcp_connections)
        self.max_udp = max(self.max_udp, stats.udp_endpoints)
        self.max_conns = max(self.max_conns, stats.total_endpoints)
        if len(self.public_ips) < self._IP_CAP:
            self.public_ips |= stats.remote_public_ips
        self.listening |= stats.listening_ports

    def to_dict(self, include_cmdline: bool = True) -> dict:
        d = {
            "pid": self.pid,
            "name": self.name,
            "exe": self.exe,
            "username": self.username,
            "max_tcp_connections": self.max_tcp,
            "max_udp_endpoints": self.max_udp,
            "distinct_public_ips": len(self.public_ips),
            "listening_ports": sorted(self.listening),
            "path_suspicious": self.path_suspicious,
            "autostart": self.autostart,
        }
        if include_cmdline:
            d["cmdline"] = self.cmdline
        return d


class SessionStats:
    """整个运行周期的累计统计，用于汇总报告。"""

    def __init__(self):
        self.start_ts = time.time()
        self.up_bytes = 0
        self.down_bytes = 0
        self.peak_up_bps = 0.0
        self.peak_down_bps = 0.0
        self.ip_counter: Counter = Counter()
        self.port_counter: Counter = Counter()
        self.processes: dict = {}
        self.listening_ports: set = set()
        self.max_public_listeners = 0
        self.max_tcp = 0
        self.max_udp = 0
        self.whitelist_hits: set = set()
        self.samples = 0
        self.connections_unavailable = False
        self.counter_resets = 0

    @property
    def elapsed(self) -> float:
        return max(0.0, time.time() - self.start_ts)

    def update(self, sample: MonitorSample) -> None:
        self.samples += 1
        t = sample.traffic
        self.up_bytes += t.up_delta_bytes
        self.down_bytes += t.down_delta_bytes
        self.peak_up_bps = max(self.peak_up_bps, t.up_bps)
        self.peak_down_bps = max(self.peak_down_bps, t.down_bps)
        self.ip_counter.update(sample.total.remote_public_ips)
        self.port_counter.update(sample.total.remote_ports)
        self.listening_ports |= sample.total.listening_ports
        self.max_public_listeners = max(self.max_public_listeners,
                                        sample.public_listener_ports)
        self.max_tcp = max(self.max_tcp, sample.total.tcp_connections)
        self.max_udp = max(self.max_udp, sample.total.udp_endpoints)
        if not sample.connections_available:
            self.connections_unavailable = True
        for pid, stats in sample.stats_by_pid.items():
            agg = self.processes.get(pid)
            if agg is None:
                agg = self.processes[pid] = ProcessAgg(pid)
            agg.update(sample.processes.get(pid), stats)

    def note_whitelist_hits(self, hits) -> None:
        for h in hits or ():
            self.whitelist_hits.add(h)


# ---------------------------------------------------------------- 写出器

class SampleCsvWriter:
    HEADER = ["time", "up_bps", "down_bps", "up_bytes_session", "down_bytes_session",
              "tcp", "udp", "public_ips", "public_networks", "public_listeners",
              "unknown_pid_conns", "score", "level"]

    def __init__(self, path):
        self._f = open(path, "w", newline="", encoding="utf-8-sig")
        self._w = csv.writer(self._f)
        self._w.writerow(self.HEADER)

    def write(self, sample: MonitorSample, assessment: Optional[RiskAssessment]) -> None:
        self._w.writerow([
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(sample.timestamp)),
            round(sample.traffic.up_bps, 1),
            round(sample.traffic.down_bps, 1),
            sample.traffic.session_up_bytes,
            sample.traffic.session_down_bytes,
            sample.total.tcp_connections,
            sample.total.udp_endpoints,
            len(sample.total.remote_public_ips),
            len(sample.total.remote_networks),
            sample.public_listener_ports,
            sample.unknown_pid_connections,
            assessment.score if assessment else "",
            assessment.level if assessment else "",
        ])
        self._f.flush()

    def close(self) -> None:
        try:
            self._f.close()
        except Exception:
            pass


class AlertJsonlWriter:
    """等级/分数抬升或距上次超过 repeat_seconds 时追加一条告警。"""

    REPEAT_SECONDS = 600.0

    def __init__(self, path, min_score: int = 30):
        self._f = open(path, "a", encoding="utf-8")
        self.min_score = int(min_score)
        self._last_level: Optional[str] = None
        self._last_score = -10**9
        self._last_ts = 0.0

    def maybe_alert(self, assessment: RiskAssessment, session: Optional[SessionStats] = None) -> bool:
        if assessment.score < self.min_score:
            self._last_level = None  # 回落后重置，再次抬升会重新告警
            return False
        now = assessment.timestamp
        changed = (assessment.level != self._last_level
                   or assessment.score >= self._last_score + 10)
        repeat = (now - self._last_ts) >= self.REPEAT_SECONDS
        if self._last_ts == 0.0 or changed or repeat:
            entry = {
                "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
                "score": assessment.score,
                "level": assessment.level,
                "note": "疑似PCDN风险，非确定性结论",
                "rules": [
                    {
                        "id": r.rule_id,
                        "description": r.description,
                        "effective_points": r.effective_points,
                        "evidence": r.evidence,
                        "whitelist_hits": r.whitelist_hits,
                    }
                    for r in assessment.confirmed_rules
                ],
            }
            if session is not None:
                top = sorted(session.processes.values(),
                             key=lambda a: (len(a.public_ips), a.max_tcp), reverse=True)[:5]
                entry["top_processes"] = [{"pid": a.pid, "name": a.name} for a in top]
            self._f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self._f.flush()
            self._last_ts = now
            self._last_level = assessment.level
            self._last_score = assessment.score
            return True
        return False

    def close(self) -> None:
        try:
            self._f.close()
        except Exception:
            pass


def build_report(session: SessionStats, assessment: Optional[RiskAssessment],
                 config: dict, meta: Optional[dict] = None) -> dict:
    mask = bool(config.get("mask_public_ips", True))
    include_cmd = bool(config.get("include_cmdline", True))
    elapsed = max(1e-9, session.elapsed)
    top_aggs = sorted(session.processes.values(),
                      key=lambda a: (len(a.public_ips), a.max_tcp), reverse=True)[:10]

    report = {
        "tool": "pcdn_monitor",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "run_seconds": round(session.elapsed, 1),
        "samples": session.samples,
        "meta": meta or {},
        "totals": {
            "upload_bytes": session.up_bytes,
            "download_bytes": session.down_bytes,
            "upload_human": format_bytes(session.up_bytes),
            "download_human": format_bytes(session.down_bytes),
            "avg_up_bps": round(session.up_bytes * 8 / elapsed, 1),
            "peak_up_bps": round(session.peak_up_bps, 1),
            "avg_down_bps": round(session.down_bytes * 8 / elapsed, 1),
            "peak_down_bps": round(session.peak_down_bps, 1),
        },
        "connections": {
            "max_tcp_connections": session.max_tcp,
            "max_udp_endpoints": session.max_udp,
            "max_public_listeners": session.max_public_listeners,
            "distinct_public_ips": len(session.ip_counter),
            "distinct_public_networks": len({network_of(ip) for ip in session.ip_counter}),
            "top_remote_ips": [
                {"ip": mask_ip(ip, mask), "samples": n}
                for ip, n in session.ip_counter.most_common(20)
            ],
            "top_remote_ports": [
                {"port": p, "samples": n}
                for p, n in session.port_counter.most_common(20)
            ],
            "listening_ports": sorted(session.listening_ports),
        },
        "risk": {
            "score": assessment.score if assessment else 0,
            "level": assessment.level if assessment else "低",
            "note": "本评分为“疑似PCDN风险”启发式评估，不能作为确定性结论。",
            "rules": [
                {
                    "id": r.rule_id,
                    "description": r.description,
                    "points": r.points,
                    "effective_points": r.effective_points,
                    "fired": r.fired,
                    "confirmed": r.confirmed,
                    "evidence": r.evidence,
                    "whitelist_hits": r.whitelist_hits,
                }
                for r in (assessment.results if assessment else [])
            ],
        },
        "top_processes": [a.to_dict(include_cmdline=include_cmd) for a in top_aggs],
        "whitelist_hits": sorted(session.whitelist_hits),
        "rules_config": config.get("rules", {}),
        "limitations": LIMITATION_NOTES,
        "suggestions": [
            "复核 top_processes 中命令行与安装路径是否为已知软件。",
            "用资源监视器/任务管理器观察可疑进程的磁盘与网络行为。",
            "如需五元组级字节统计，可启用第二阶段 pktmon/tshark 抓包（仅元数据）。",
            "确认后再人工处理；本工具不会自动结束进程或修改系统设置。",
        ],
    }
    if session.connections_unavailable:
        report["limitations"].append(
            "运行期间连接表读取受限（权限不足）：连接类指标可能不完整，建议以管理员身份重跑。")
    return report


class ReportWriter:
    def __init__(self, path):
        self.path = Path(path)

    def write(self, session: SessionStats, assessment: Optional[RiskAssessment],
              config: dict, meta: Optional[dict] = None) -> Path:
        data = build_report(session, assessment, config, meta)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)
        return self.path


# ---------------------------------------------------------------- 提醒

def notify_user(title: str, message: str, beep: bool = True) -> None:
    """非阻塞弹窗 + 蜂鸣提醒（仅 Windows；失败静默）。不会执行任何处置动作。"""
    if beep:
        try:
            import winsound

            threading.Thread(target=lambda: winsound.Beep(1000, 400), daemon=True).start()
        except Exception:
            pass

    def _box():
        try:
            import ctypes
            # MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST
            ctypes.windll.user32.MessageBoxW(None, message, title, 0x30 | 0x10000 | 0x40000)
        except Exception:
            pass

    threading.Thread(target=_box, daemon=True).start()


def alert_min_score(config: dict) -> int:
    """根据配置的告警最低等级换算最低分数。"""
    level = (config.get("output", {}) or {}).get("alert_min_level", LEVEL_SUSPICIOUS)
    return min_score_for_level(level, config.get("score_levels", {}) or {})
