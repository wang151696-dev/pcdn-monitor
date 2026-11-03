"""测试用数据工厂：构造纯内存的采样/连接/进程对象，不依赖 psutil 真实状态。"""
from __future__ import annotations

from types import SimpleNamespace

from models import (ConnRecord, EndpointStats, MonitorSample, ProcessSnapshot,
                    TrafficSample)


def traffic(ts=0.0, up_bps=0.0, down_bps=0.0, up=0, down=0, interval=2.0):
    return TrafficSample(timestamp=ts, interval=interval, up_bps=up_bps,
                         down_bps=down_bps, up_delta_bytes=up, down_delta_bytes=down)


def snap(pid=1, name="proc.exe", exe=None, **kw):
    return ProcessSnapshot(pid=pid, name=name, exe=exe, **kw)


def conn(kind="tcp", lip="192.168.1.2", lport=50000, rip=None, rport=None,
         status="ESTABLISHED", pid=1):
    return ConnRecord(kind, lip, lport, rip, rport, status, pid)


def stats(tcp=0, udp=0, ips=(), ports=(), networks=(), listening=()):
    st = EndpointStats()
    st.tcp_connections = tcp
    st.udp_endpoints = udp
    st.remote_public_ips = set(ips)
    st.remote_ports = set(ports)
    st.remote_networks = set(networks)
    st.listening_ports = set(listening)
    return st


def mon_sample(ts=0.0, traffic_sample=None, stats=None, processes=None,
               total=None, listeners=0, listener_pids=None, unknown=0):
    stats = stats or {}
    processes = processes if processes is not None else {}
    if total is None:
        total = EndpointStats()
        for st in stats.values():
            total.merge(st)
    return MonitorSample(
        timestamp=ts,
        traffic=traffic_sample if traffic_sample is not None else traffic(ts),
        processes=processes,
        stats_by_pid=stats,
        total=total,
        public_listener_ports=listeners,
        listener_pids=set(listener_pids or ()),
        unknown_pid_connections=unknown,
    )


def nic(name, sent, recv):
    return name, SimpleNamespace(bytes_sent=sent, bytes_recv=recv)


def make_counters(*pairs):
    return dict(pairs)
