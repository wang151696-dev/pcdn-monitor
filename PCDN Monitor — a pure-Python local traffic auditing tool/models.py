"""数据模型：流量采样、连接记录、进程画像、规则与评估结果。

本模块只承载数据结构，不包含任何采集或判定逻辑。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class TrafficSample:
    """一次网卡流量采样（已过滤虚拟/回环网卡并折算速率）。"""

    timestamp: float
    interval: float            # 距上次采样的秒数
    up_bps: float              # 上传速率 bits/s
    down_bps: float            # 下载速率 bits/s
    up_delta_bytes: int        # 本周期上传字节数
    down_delta_bytes: int      # 本周期下载字节数
    session_up_bytes: int = 0    # 本次运行累计上传
    session_down_bytes: int = 0  # 本次运行累计下载


@dataclass(frozen=True)
class ConnRecord:
    """从系统连接表提炼的一条连接/端点元数据（不含任何包内容）。"""

    kind: str                        # "tcp" | "udp"
    local_ip: str
    local_port: int
    remote_ip: Optional[str]
    remote_port: Optional[int]
    status: str                      # LISTEN / ESTABLISHED / NONE ...
    pid: Optional[int]


@dataclass
class EndpointStats:
    """按 PID 或全系统聚合的连接统计。"""

    tcp_connections: int = 0
    udp_endpoints: int = 0
    listening_ports: set = field(default_factory=set)
    remote_public_ips: set = field(default_factory=set)
    remote_ports: set = field(default_factory=set)
    remote_networks: set = field(default_factory=set)   # /24 (IPv4) 或 /64 (IPv6)

    @property
    def total_endpoints(self) -> int:
        return self.tcp_connections + self.udp_endpoints

    def merge(self, other: "EndpointStats") -> None:
        self.tcp_connections += other.tcp_connections
        self.udp_endpoints += other.udp_endpoints
        self.listening_ports |= other.listening_ports
        self.remote_public_ips |= other.remote_public_ips
        self.remote_ports |= other.remote_ports
        self.remote_networks |= other.remote_networks


@dataclass
class ProcessSnapshot:
    """进程画像。读取失败时字段保持缺省并记录 inspect_error，绝不抛异常。"""

    pid: Optional[int]
    name: str = "(未知)"
    exe: Optional[str] = None
    cmdline: Optional[list] = None
    create_time: Optional[float] = None
    username: Optional[str] = None
    autostart: bool = False
    path_suspicious: bool = False
    inspect_error: Optional[str] = None


@dataclass
class MonitorSample:
    """一次完整采集：流量 + 连接聚合 + 进程画像。"""

    timestamp: float
    traffic: TrafficSample
    processes: dict              # Optional[int] -> ProcessSnapshot
    stats_by_pid: dict           # Optional[int] -> EndpointStats
    total: EndpointStats
    public_listener_ports: int
    listener_pids: set           # 拥有公网监听端口的 PID
    unknown_pid_connections: int  # 无法归属到进程的连接数（常见于权限不足）
    connections_available: bool = True


@dataclass
class RuleResult:
    rule_id: str
    description: str
    points: float                # 规则满分
    fired: bool                  # 本周期条件是否命中
    confirmed: bool              # 是否连续命中达到确认次数
    effective_points: float      # 白名单折算后的实际得分
    evidence: str
    whitelist_hits: list


@dataclass
class RiskAssessment:
    timestamp: float
    score: int
    level: str
    results: list

    @property
    def confirmed_rules(self) -> list:
        return [r for r in self.results if r.confirmed]

    @property
    def fired_rules(self) -> list:
        return [r for r in self.results if r.fired]
