"""采集层：网卡流量速率 + 系统连接表聚合。

- 流量：psutil.net_io_counters(pernic=True)，按网卡过滤虚拟/回环网卡，
  处理计数器清零（睡眠唤醒、禁用再启用网卡）与网卡消失。
- 连接：psutil.net_connections(kind="inet")，仅取元组信息，不涉及任何包内容。
  权限不足时降级为空表并置 connections_available=False，程序继续运行。
"""
from __future__ import annotations

import logging
import socket
import time
from typing import Iterable, Optional

import psutil

from models import ConnRecord, EndpointStats, MonitorSample, ProcessSnapshot, TrafficSample
from process_inspector import ProcessInspector
from utils import is_public_ip, network_of

log = logging.getLogger("pcdn.collector")


class NicClassifier:
    """按名称把网卡分为 monitor / virtual / loopback / ignored 四类。"""

    def __init__(self, ignore_nics: Iterable[str] = (), virtual_patterns: Iterable[str] = (),
                 count_virtual: bool = False):
        self.ignore = {str(n).lower() for n in ignore_nics}
        self.virtual_patterns = [str(p).lower() for p in virtual_patterns if p]
        self.count_virtual = bool(count_virtual)

    def classify(self, name: str) -> str:
        low = name.lower()
        if low in self.ignore:
            return "ignored"
        if "loopback" in low or low == "lo":
            return "loopback"
        if any(p in low for p in self.virtual_patterns):
            return "virtual"
        return "monitor"

    def counted(self, kind: str) -> bool:
        return kind == "monitor" or (kind == "virtual" and self.count_virtual)


def compute_deltas(prev: Optional[tuple], sent: int, recv: int) -> tuple:
    """根据上次计数器计算增量；计数器回绕/清零时按当前值重新起算。

    返回 (d_sent, d_recv, reset)。
    """
    if prev is None:
        return 0, 0, False
    reset = sent < prev[0] or recv < prev[1]
    d_sent = sent if sent < prev[0] else sent - prev[0]
    d_recv = recv if recv < prev[1] else recv - prev[1]
    return d_sent, d_recv, reset


class TrafficCollector:
    """网卡流量采集器（保留会话累计值）。"""

    def __init__(self, classifier: NicClassifier):
        self.classifier = classifier
        self._prev: dict = {}          # name -> (sent, recv)
        self._last_ts: Optional[float] = None
        self.session_up_bytes = 0
        self.session_down_bytes = 0
        self.reset_count = 0           # 计数器清零次数（诊断用）

    def sample(self, now: Optional[float] = None, counters: Optional[dict] = None) -> TrafficSample:
        now = time.time() if now is None else now
        if counters is None:
            try:
                counters = psutil.net_io_counters(pernic=True)
            except Exception:
                log.exception("读取网卡计数器失败，本周期速率记为 0")
                counters = {}
        dt = 0.0 if self._last_ts is None else max(1e-6, now - self._last_ts)

        up = down = 0
        counted: set = set()
        for name, st in counters.items():
            if not self.classifier.counted(self.classifier.classify(name)):
                continue
            counted.add(name)
            sent, recv = int(st.bytes_sent), int(st.bytes_recv)
            d_sent, d_recv, reset = compute_deltas(self._prev.get(name), sent, recv)
            if reset:
                self.reset_count += 1
                log.info("网卡 %s 计数器清零，按当前值重新起算", name)
            up += d_sent
            down += d_recv
            self._prev[name] = (sent, recv)
        # 网卡消失后清掉旧基线，避免其重新出现时产生巨量假增量
        self._prev = {k: v for k, v in self._prev.items() if k in counted}

        self._last_ts = now
        self.session_up_bytes += up
        self.session_down_bytes += down
        return TrafficSample(
            timestamp=now,
            interval=dt,
            up_bps=(up * 8 / dt) if dt > 0 else 0.0,
            down_bps=(down * 8 / dt) if dt > 0 else 0.0,
            up_delta_bytes=up,
            down_delta_bytes=down,
            session_up_bytes=self.session_up_bytes,
            session_down_bytes=self.session_down_bytes,
        )


def is_public_bind(ip: str) -> bool:
    """监听地址是否对外：通配地址与非回环绑定都视为可被外部访问。"""
    if not ip:
        return True
    if ip == "::1" or ip.startswith("127."):
        return False
    return True


def aggregate_connections(records: Iterable[ConnRecord], timestamp: float,
                          traffic: TrafficSample, inspector,
                          connections_available: bool = True) -> MonitorSample:
    """把连接记录聚合成按 PID / 全系统两级统计（纯函数，便于测试）。"""
    stats_by_pid: dict = {}
    processes: dict = {}
    total = EndpointStats()
    public_listeners = 0
    listener_pids: set = set()
    unknown = 0

    for rec in records:
        pid = rec.pid
        if pid is None:
            unknown += 1
        st = stats_by_pid.get(pid)
        if st is None:
            st = stats_by_pid[pid] = EndpointStats()
        if rec.kind == "tcp":
            st.tcp_connections += 1
            if rec.status == "LISTEN":
                st.listening_ports.add(rec.local_port)
                if is_public_bind(rec.local_ip):
                    public_listeners += 1
                    if pid is not None:
                        listener_pids.add(pid)
        else:
            st.udp_endpoints += 1
        if rec.remote_ip and is_public_ip(rec.remote_ip):
            st.remote_public_ips.add(rec.remote_ip)
            if rec.remote_port:
                st.remote_ports.add(rec.remote_port)
            net = network_of(rec.remote_ip)
            if net:
                st.remote_networks.add(net)

    for pid, st in stats_by_pid.items():
        processes[pid] = _snapshot_for(pid, inspector)
        total.merge(st)

    return MonitorSample(
        timestamp=timestamp,
        traffic=traffic,
        processes=processes,
        stats_by_pid=stats_by_pid,
        total=total,
        public_listener_ports=public_listeners,
        listener_pids=listener_pids,
        unknown_pid_connections=unknown,
        connections_available=connections_available,
    )


def _snapshot_for(pid: Optional[int], inspector) -> ProcessSnapshot:
    if pid is None:
        return ProcessSnapshot(pid=None, name="(未知PID)", inspect_error="pid_unavailable")
    if pid == 0:
        # Windows 上 pid 0 的连接多为内核持有的 TIME_WAIT 等残余套接字，
        # 归到 "System Idle Process" 名下具有误导性
        return ProcessSnapshot(pid=0, name="(系统内核连接)")
    try:
        return inspector.inspect(pid)
    except Exception as exc:  # 双保险：inspect 自身已保证不抛
        log.debug("进程 %s 信息获取失败: %s", pid, exc)
        return ProcessSnapshot(pid=pid, name=f"(PID {pid})", inspect_error=str(exc))


class ConnectionCollector:
    """系统连接表采集 + 聚合。权限不足时自动降级。"""

    def __init__(self, inspector: Optional[ProcessInspector] = None):
        self.inspector = inspector if inspector is not None else ProcessInspector()
        self.available = True
        self._denied_warned = False

    def fetch(self) -> list:
        try:
            rows = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            self.available = False
            if not self._denied_warned:
                log.warning("无权限读取系统连接表(psutil.AccessDenied)，连接类规则将失效；"
                            "建议以管理员身份运行。")
                self._denied_warned = True
            return []
        except Exception:
            log.exception("读取系统连接表失败，本周期跳过连接采集")
            self.available = False
            return []
        self.available = True
        records = []
        for r in rows:
            if r.family not in (socket.AF_INET, socket.AF_INET6):
                continue
            if r.type == socket.SOCK_STREAM:
                kind = "tcp"
            elif r.type == socket.SOCK_DGRAM:
                kind = "udp"
            else:
                continue
            lip, lport = _split_addr(r.laddr)
            rip, rport = _split_addr(r.raddr)
            records.append(ConnRecord(kind, lip, lport, rip, rport,
                                      str(r.status or ""), r.pid))
        return records

    def sample(self, traffic: TrafficSample) -> MonitorSample:
        records = self.fetch()
        return aggregate_connections(records, traffic.timestamp, traffic,
                                     self.inspector, self.available)


def _split_addr(addr) -> tuple:
    if not addr:
        return "", 0
    return addr.ip, addr.port
