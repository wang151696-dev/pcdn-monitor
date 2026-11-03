"""pcdn_monitor 入口：Windows 本机疑似 PCDN / 异常后台上传行为审计工具。

定位：只读的防御性本机监控。不会攻击或扫描外部设备、不上传任何数据、
不会自动结束进程、删除文件或修改防火墙；所有结论均为“疑似风险”提示。
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

try:
    import psutil  # noqa: F401  提前给出友好错误
except ImportError:
    print("缺少依赖 psutil，请先执行: python -m pip install -r requirements.txt",
          file=sys.stderr)
    raise SystemExit(2)

from collector import ConnectionCollector, NicClassifier, TrafficCollector
from detector import LEVEL_ORDER, Detector, Whitelist, min_score_for_level
from models import MonitorSample, RiskAssessment
from process_inspector import ProcessInspector
from reporter import (AlertJsonlWriter, ReportWriter, SampleCsvWriter,
                      SessionStats, alert_min_score, notify_user, setup_logging)
from utils import (DEFAULT_CONFIG, deep_merge, format_bits, format_bytes,
                   format_duration, is_admin)

log = logging.getLogger("pcdn.main")
PROJECT_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------------- 参数与配置

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="pcdn_monitor",
        description="Windows 本机疑似 PCDN / 异常上传行为审计工具（只读监控，不含任何处置动作）")
    p.add_argument("--interval", type=float, default=None,
                   help="采样间隔秒数（默认取配置 interval_seconds=2）")
    p.add_argument("--duration", type=float, default=None,
                   help="运行时长（秒）；缺省一直运行直到 Ctrl+C")
    p.add_argument("--config", default=None,
                   help="配置文件路径（默认使用脚本目录下 config.json）")
    p.add_argument("--output", default=None,
                   help="输出目录（默认取配置 output.dir）")
    p.add_argument("--once", action="store_true",
                   help="只采集一次并立即生成报告（跳过连续确认）")
    p.add_argument("--no-ui", action="store_true",
                   help="关闭实时面板，仅写文件")
    return p.parse_args(argv)


def load_config(path) -> dict:
    cfg = DEFAULT_CONFIG
    candidates = [Path(path)] if path else [PROJECT_DIR / "config.json"]
    for p in candidates:
        if not p.exists():
            if path:
                raise SystemExit(f"配置文件不存在: {p}")
            return cfg  # 未显式指定且默认文件不存在 → 用内置默认值
        try:
            user = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SystemExit(f"配置文件解析失败 {p}: {exc}")
        cfg = deep_merge(cfg, user)
        return cfg
    return cfg


# ---------------------------------------------------------------- 界面

class NullUI:
    def render(self, *a, **k):  # noqa: D401
        pass

    def close(self):
        pass


class PlainUI:
    """无 rich 时的纯文本面板；每个采样周期打印一行，规则变化时打印明细。"""

    def __init__(self, whitelist=None, admin=False):
        self.whitelist = whitelist
        self.admin = admin
        self._last_key = None

    def render(self, sample: MonitorSample, assessment, session: SessionStats) -> None:
        t, tot = sample.traffic, sample.total
        parts = [
            time.strftime("%H:%M:%S"),
            f"↑{format_bits(t.up_bps)}(峰{format_bits(session.peak_up_bps)})",
            f"↓{format_bits(t.down_bps)}",
            f"累计↑{format_bytes(session.up_bytes)}/↓{format_bytes(session.down_bytes)}",
            f"TCP {tot.tcp_connections} UDP {tot.udp_endpoints} "
            f"公网IP {len(tot.remote_public_ips)}",
        ]
        if not sample.connections_available:
            parts.append("[连接表不可用,建议管理员运行]")
        if assessment is not None:
            parts.append(f"风险 {assessment.score}/100【{assessment.level}】")
        print(" | ".join(parts), flush=True)
        if assessment is not None:
            key = (assessment.timestamp, assessment.score)
            if key != self._last_key:
                self._last_key = key
                for r in assessment.confirmed_rules:
                    print(f"    ⚠ {r.description} +{r.effective_points:g}分：{r.evidence}")

    def close(self):
        pass


class RichUI:
    """rich 实时面板：速度、连接、风险等级、Top 进程、已确认规则。"""

    LEVEL_STYLE = {"低": "green", "可疑": "yellow", "高": "dark_orange", "严重": "bold red"}

    def __init__(self, whitelist: Whitelist, admin: bool = False):
        from rich.console import Console, Group  # noqa: F401
        from rich.live import Live

        self.whitelist = whitelist
        self.admin = admin
        self.console = Console()
        self._live = Live(console=self.console, refresh_per_second=2, transient=True)
        self._live.start()

    def render(self, sample: MonitorSample, assessment, session: SessionStats) -> None:
        from rich.console import Group
        from rich.table import Table
        from rich.text import Text

        t, tot = sample.traffic, sample.total

        head = Text()
        head.append(" PCDN 疑似风险监控 ", style="bold white on dark_blue")
        head.append(f" {time.strftime('%H:%M:%S')}  运行 {format_duration(session.elapsed)}  ")
        head.append("管理员" if self.admin else "普通用户(建议管理员)",
                    style="green" if self.admin else "dim")

        speed = Text()
        speed.append(f"  ↑ 上传 {format_bits(t.up_bps)}", style="red bold")
        speed.append(f"（峰值 {format_bits(session.peak_up_bps)} / 累计 "
                     f"{format_bytes(session.up_bytes)}）\n", style="dim")
        speed.append(f"  ↓ 下载 {format_bits(t.down_bps)}", style="cyan")
        speed.append(f"（峰值 {format_bits(session.peak_down_bps)} / 累计 "
                     f"{format_bytes(session.down_bytes)}）", style="dim")

        conns = Text(f"  TCP {tot.tcp_connections} | UDP {tot.udp_endpoints} | "
                     f"公网远端IP {len(tot.remote_public_ips)} | "
                     f"网段 {len(tot.remote_networks)} | 公网监听 {sample.public_listener_ports}")
        if not sample.connections_available:
            conns.append("  [连接表不可用：权限不足]", style="bold yellow")
        if sample.unknown_pid_connections:
            conns.append(f"  [未知PID连接 {sample.unknown_pid_connections}]", style="yellow")

        risk = Text("  风险评分 ")
        if assessment is not None:
            style = self.LEVEL_STYLE.get(assessment.level, "white")
            risk.append(f"{assessment.score}/100【{assessment.level}】", style=style)
            risk.append("（疑似PCDN风险，非确定性结论）", style="dim")
        else:
            risk.append("评估中…", style="dim")

        table = Table(show_header=True, header_style="bold", pad_edge=False)
        for col, justify in (("PID", "right"), ("进程", "left"), ("TCP", "right"),
                             ("UDP", "right"), ("公网IP", "right"), ("端口", "right"),
                             ("网段", "right"), ("监听", "left"), ("标记", "left")):
            table.add_column(col, justify=justify, no_wrap=True)
        rows = sorted(sample.stats_by_pid.items(),
                      key=lambda kv: (len(kv[1].remote_public_ips), kv[1].tcp_connections),
                      reverse=True)[:10]
        for pid, st in rows:
            snap = sample.processes.get(pid)
            name = snap.name if snap is not None else "?"
            marks = []
            if snap is not None:
                if snap.path_suspicious:
                    marks.append("⚠异常目录")
                if snap.autostart:
                    marks.append("自启")
                entry = self.whitelist.match_process(snap)
                if entry is not None:
                    marks.append(f"白名单:{entry.reason}")
            listening = ",".join(str(p) for p in sorted(st.listening_ports)[:4]) or "-"
            table.add_row(str(pid), name[:26], str(st.tcp_connections),
                          str(st.udp_endpoints), str(len(st.remote_public_ips)),
                          str(len(st.remote_ports)), str(len(st.remote_networks)),
                          listening, " ".join(marks))

        rules = Text()
        if assessment is not None:
            confirmed = assessment.confirmed_rules
            if confirmed:
                rules.append("  已确认规则:\n", style="bold")
                for r in confirmed:
                    rules.append(f"    ⚠ {r.description} +{r.effective_points:g}分: "
                                 f"{r.evidence}\n", style="yellow")
            else:
                rules.append("  已确认规则: 无（需连续多个周期命中才计分）", style="dim")

        self._live.update(Group(head, Text(""), speed, conns, risk, Text(""), table, rules))

    def close(self):
        try:
            self._live.stop()
        except Exception:
            pass


def make_ui(args, whitelist: Whitelist, admin: bool):
    if args.no_ui:
        return NullUI()
    if not sys.stdout.isatty():
        return PlainUI(whitelist, admin)
    try:
        return RichUI(whitelist, admin)
    except Exception as exc:
        log.info("rich 面板不可用(%s)，改用纯文本界面", exc)
        return PlainUI(whitelist, admin)


# ---------------------------------------------------------------- 主循环

def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    config = load_config(args.config)
    if args.interval:
        if args.interval < 0.5:
            raise SystemExit("--interval 最小 0.5 秒")
        config["interval_seconds"] = float(args.interval)
    interval = float(config["interval_seconds"])
    out_dir = Path(args.output or config["output"]["dir"])
    ocfg = config["output"]
    out_dir.mkdir(parents=True, exist_ok=True)

    setup_logging(out_dir / ocfg["log_file"], config.get("log_level", "INFO"))
    admin = is_admin()
    log.info("pcdn_monitor 启动 interval=%.1fs 输出目录=%s 管理员=%s",
             interval, out_dir.resolve(), admin)
    if not admin:
        log.warning("非管理员权限：部分系统进程的连接可能无法归属到进程（显示为未知PID连接）")

    net_cfg = config["network"]
    classifier = NicClassifier(net_cfg.get("ignore_nics", []),
                               net_cfg.get("virtual_nic_patterns", []),
                               net_cfg.get("count_virtual_nics", False))
    traffic_collector = TrafficCollector(classifier)
    inspector = ProcessInspector(config)
    conn_collector = ConnectionCollector(inspector)
    whitelist = Whitelist(config.get("whitelist"))
    detector = Detector(config, whitelist)
    session = SessionStats()

    # 配置合理性提示：持续上传规则的时长必须能被窗口覆盖
    window_seconds = float(config.get("window_minutes", 12)) * 60
    sustained_minutes = float(config.get("rules", {}).get(
        "sustained_upload", {}).get("minutes", 10))
    if sustained_minutes * 60 > window_seconds + 1e-6:
        log.warning("rules.sustained_upload.minutes(%.1f) 超过 window_minutes 窗口，"
                    "该规则将永远无法触发，请调整 config.json", sustained_minutes)

    csv_writer = SampleCsvWriter(out_dir / ocfg["samples_csv"])
    alert_writer = AlertJsonlWriter(out_dir / ocfg["alerts_jsonl"],
                                    min_score=alert_min_score(config))
    report_writer = ReportWriter(out_dir / ocfg["report_json"])
    ui = make_ui(args, whitelist, admin)

    eval_every = max(1, int(float(config.get("eval_every_seconds", 10)) / interval))
    report_every = float(ocfg.get("report_every_minutes", 5)) * 60
    notify_cfg = config.get("notify", {}) or {}
    notify_min_rank = LEVEL_ORDER.get(notify_cfg.get("min_level", "高"), 2)
    notify_sustain = float(notify_cfg.get("sustain_minutes", 5)) * 60
    notify_cooldown = float(notify_cfg.get("cooldown_minutes", 10)) * 60

    stop_at = (time.monotonic() + args.duration) if args.duration else None
    if args.once:
        # 首次采样只建立网卡基线；--once 模式先取基线再短暂等待，
        # 让单次报告也能包含真实的速率与流量增量
        traffic_collector.sample()
        time.sleep(min(3.0, max(1.0, interval)))
    last_report = 0.0
    high_since = None
    last_notify = float("-inf")
    report_path = None
    final_assessment = None
    n = 0

    try:
        while stop_at is None or time.monotonic() < stop_at:
            t0 = time.monotonic()
            sample = conn_collector.sample(traffic_collector.sample())
            session.update(sample)
            session.counter_resets = traffic_collector.reset_count
            detector.add_sample(sample)
            n += 1

            if args.once or n % eval_every == 0:
                try:
                    assessment = detector.evaluate(force_confirm=bool(args.once))
                except Exception:
                    log.exception("风险评估失败，本周期跳过")
                    assessment = detector.last_assessment
                session.note_whitelist_hits(
                    hit for r in assessment.results for hit in r.whitelist_hits)
                try:
                    alert_writer.maybe_alert(assessment, session)
                except Exception:
                    log.exception("写告警失败")

                if notify_cfg.get("enabled", True):
                    rank = LEVEL_ORDER.get(assessment.level, 0)
                    mono = time.monotonic()
                    if rank >= notify_min_rank:
                        if high_since is None:
                            high_since = mono
                        if (mono - high_since >= notify_sustain
                                and mono - last_notify >= notify_cooldown):
                            notify_user(
                                "疑似PCDN风险警告",
                                f"风险评分 {assessment.score}/100（{assessment.level}）已持续 "
                                f"{int((mono - high_since) / 60)} 分钟。\n"
                                "本提示仅为疑似风险评估，请查看报告确认后手动处理。\n"
                                f"报告目录: {out_dir.resolve()}",
                                beep=bool(notify_cfg.get("beep", True)))
                            last_notify = mono
                    else:
                        high_since = None

            try:
                csv_writer.write(sample, detector.last_assessment)
            except Exception:
                log.exception("写样本 CSV 失败")

            try:
                ui.render(sample, detector.last_assessment, session)
            except Exception:
                # 界面异常不影响监控本身：降级为纯文本并继续
                log.exception("界面渲染失败，切换到纯文本模式")
                try:
                    ui.close()
                except Exception:
                    pass
                ui = PlainUI(whitelist, admin)

            mono = time.monotonic()
            if mono - last_report >= report_every:
                try:
                    report_path = report_writer.write(
                        session, detector.last_assessment, config,
                        meta={"admin": admin, "interval_seconds": interval,
                              "window_minutes": config.get("window_minutes")})
                    last_report = mono
                except Exception:
                    log.exception("周期性写报告失败")

            if args.once:
                break
            remain = interval - (time.monotonic() - t0)
            if remain > 0:
                time.sleep(remain)
    except KeyboardInterrupt:
        log.info("收到 Ctrl+C，正在生成最终报告…")
    finally:
        try:
            if len(detector) > 0:
                final_assessment = detector.evaluate(force_confirm=bool(args.once))
                session.note_whitelist_hits(
                    hit for r in final_assessment.results for hit in r.whitelist_hits)
        except Exception:
            log.exception("最终评估失败")
        try:
            report_path = report_writer.write(
                session, final_assessment or detector.last_assessment, config,
                meta={"admin": admin, "interval_seconds": interval,
                      "window_minutes": config.get("window_minutes")})
        except Exception:
            log.exception("写最终报告失败")
        csv_writer.close()
        alert_writer.close()
        ui.close()

    shown = final_assessment or detector.last_assessment
    if shown is not None:
        print(f"\n最终风险评分: {shown.score}/100【{shown.level}】"
              f"（疑似PCDN风险，非确定性结论）")
    if report_path is not None:
        print(f"报告已写入: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
