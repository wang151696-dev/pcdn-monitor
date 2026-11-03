"""通用工具：IP 判断与脱敏、格式化、滑动窗口、配置合并、默认配置。

所有阈值均集中在 DEFAULT_CONFIG，config.json 中的同名键会覆盖默认值。
"""
from __future__ import annotations

import copy
import ipaddress
import os
import time
from collections import deque
from typing import Any, Callable, Iterable, List, Optional

_CGNAT = ipaddress.ip_network("100.64.0.0/10")  # 运营商 CGNAT 共享地址段，不算公网


# ---------------------------------------------------------------- IP 工具

def parse_ip(value) -> Optional[Any]:
    """解析 IP 字符串；非法输入返回 None。IPv4 映射的 IPv6 会还原成 IPv4。"""
    if not value:
        return None
    try:
        addr = ipaddress.ip_address(str(value))
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def is_public_ip(value: str) -> bool:
    """判断是否为可路由的公网单播地址。

    排除：回环、私有、链路本地、组播/广播、保留、未指定、CGNAT(100.64/10)、
    IPv4 映射地址会先还原成 IPv4 再判断。
    """
    addr = parse_ip(value)
    if addr is None:
        return False
    if addr.version == 4 and addr in _CGNAT:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def mask_ip(value: str, mask: bool = True) -> str:
    """公网 IP 脱敏：IPv4 末段替换为 xxx，IPv6 末组替换为 xxxx。"""
    if not mask:
        return value
    s = str(value)
    addr = parse_ip(s)
    if addr is None:
        return s
    if addr.version == 4:
        parts = s.split(".")
        if len(parts) == 4:
            parts[3] = "xxx"
            return ".".join(parts)
        return s
    parts = s.split(":")
    if len(parts) > 1:
        parts[-1] = "xxxx"
    return ":".join(parts)


def network_of(value: str) -> Optional[str]:
    """返回 IP 所属网段：IPv4 取 /24，IPv6 取 /64。"""
    addr = parse_ip(value)
    if addr is None:
        return None
    bits = 24 if addr.version == 4 else 64
    return str(ipaddress.ip_network(f"{addr}/{bits}", strict=False))


# ---------------------------------------------------------------- 格式化

def format_bits(value: float) -> str:
    v = float(value or 0)
    for unit, scale in (("Gbps", 1e9), ("Mbps", 1e6), ("Kbps", 1e3)):
        if abs(v) >= scale:
            return f"{v / scale:.1f} {unit}"
    return f"{v:.0f} bps"


def format_bytes(value) -> str:
    v = float(value or 0)
    for unit, scale in (("TiB", 1 << 40), ("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if abs(v) >= scale:
            return f"{v / scale:.1f} {unit}"
    return f"{v:.0f} B"


def format_duration(seconds: float) -> str:
    s = int(max(0, seconds))
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


# ---------------------------------------------------------------- 滑动窗口

class SampleWindow:
    """按 timestamp 淘汰的滑动窗口（存放 MonitorSample）。"""

    def __init__(self, seconds: float):
        self._seconds = float(seconds)
        self._items: deque = deque()

    def add(self, item) -> None:
        self._items.append(item)
        self._evict()

    def _evict(self) -> None:
        if not self._items:
            return
        now = getattr(self._items[-1], "timestamp", None)
        if now is None:
            return
        while self._items and now - self._items[0].timestamp > self._seconds:
            self._items.popleft()

    def __len__(self) -> int:
        return len(self._items)

    def samples(self) -> List[Any]:
        return list(self._items)


def longest_sustained(
    samples: Iterable[Any],
    threshold: float,
    max_gap: float,
    value: Callable[[Any], float],
    ts: Callable[[Any], float],
) -> float:
    """计算指标连续不低于 threshold 的最长持续秒数。

    相邻样本间隔超过 max_gap 视为断流，连续段重新计算；
    段时长 = 段内最后样本时间 - 段内第一样本时间。
    """
    best = 0.0
    run_start: Optional[float] = None
    last_ok: Optional[float] = None
    for s in samples:
        t = ts(s)
        if value(s) >= threshold:
            if run_start is None or (last_ok is not None and t - last_ok > max_gap):
                if run_start is not None and last_ok is not None:
                    best = max(best, last_ok - run_start)
                run_start = t
            last_ok = t
        else:
            if run_start is not None and last_ok is not None:
                best = max(best, last_ok - run_start)
            run_start = None
            last_ok = None
    if run_start is not None and last_ok is not None:
        best = max(best, last_ok - run_start)
    return best


# ---------------------------------------------------------------- 配置

def deep_merge(base: dict, override: dict) -> dict:
    """递归合并配置字典；override 优先，列表整体替换。"""
    out = copy.deepcopy(base)
    for key, val in (override or {}).items():
        if isinstance(val, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], val)
        else:
            out[key] = copy.deepcopy(val)
    return out


def is_admin() -> bool:
    """当前进程是否具有管理员/root 权限（用于提示，不影响运行）。"""
    try:
        if os.name == "nt":
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


DEFAULT_CONFIG: dict = {
    "interval_seconds": 2.0,
    "eval_every_seconds": 10,
    "window_minutes": 12,
    "consecutive_cycles": 3,
    "mask_public_ips": True,
    "include_cmdline": True,
    "log_level": "INFO",
    "score_levels": {"low_max": 29, "suspicious_max": 59, "high_max": 79},
    "network": {
        "ignore_nics": [],
        "count_virtual_nics": False,
        "virtual_nic_patterns": [
            "loopback", "hyper-v", "vethernet", "vmware", "virtualbox", "vagrant",
            "wsl", "tailscale", "zerotier", "openvpn", "wireguard", "tap-", "tun",
            "bluetooth", "wi-fi direct", "isatap", "teredo", "microsoft km-test",
            "wan miniport", "npcap", "npf",
        ],
    },
    "suspicious_path_patterns": [
        "\\temp\\", "\\tmp\\", "\\windows\\temp\\", "\\appdata\\local\\temp\\", "\\cache\\",
    ],
    "rules": {
        "sustained_upload": {"mbps": 1.0, "minutes": 10, "points": 20},
        "upload_ratio": {"ratio": 2.0, "min_upload_mbytes": 10, "points": 15},
        "many_public_ips": {"distinct_ips": 100, "points": 15},
        "dispersed_networks": {"distinct_networks": 50, "points": 10},
        "dispersed_ports": {"distinct_ports": 200, "points": 10},
        "udp_anomaly": {"udp_endpoints": 150, "points": 10},
        "process_many_conns": {"connections": 80, "points": 10},
        "public_listeners": {"ports": 3, "points": 5},
        "suspicious_path": {"min_connections": 3, "points": 10},
        "autostart_activity": {"min_connections": 20, "points": 5},
    },
    "whitelist": [
        {"name": "onedrive.exe", "weight": 0.3, "reason": "云盘同步"},
        {"name": "dropbox.exe", "weight": 0.3, "reason": "云盘同步"},
        {"name": "baidunetdisk.exe", "weight": 0.3, "reason": "网盘同步"},
        {"name": "googledrivesync.exe", "weight": 0.3, "reason": "云盘同步"},
        {"name": "nutstore.exe", "weight": 0.3, "reason": "云盘同步"},
        {"name": "obs64.exe", "weight": 0.3, "reason": "直播推流"},
        {"name": "qbittorrent.exe", "weight": 0.3, "reason": "BT下载"},
        {"name": "utorrent.exe", "weight": 0.3, "reason": "BT下载"},
        {"name": "bitcomet.exe", "weight": 0.3, "reason": "BT下载"},
        {"name": "transmission-qt.exe", "weight": 0.3, "reason": "BT下载"},
        {"name": "tailscale-ipn.exe", "weight": 0.2, "reason": "组网VPN"},
        {"name": "tailscaled.exe", "weight": 0.2, "reason": "组网VPN"},
        {"name": "zerotier one.exe", "weight": 0.2, "reason": "组网VPN"},
        {"name": "clash.exe", "weight": 0.3, "reason": "代理客户端"},
        {"name": "clashmiService.exe", "weight": 0.3, "reason": "代理客户端"},
        {"name": "clash-verge.exe", "weight": 0.3, "reason": "代理客户端"},
        {"name": "clash-verge-service.exe", "weight": 0.3, "reason": "代理客户端"},
        {"name": "verge-mihomo.exe", "weight": 0.3, "reason": "代理客户端"},
        {"name": "mihomo.exe", "weight": 0.3, "reason": "代理客户端"},
        {"name": "v2ray.exe", "weight": 0.3, "reason": "代理客户端"},
        {"name": "xray.exe", "weight": 0.3, "reason": "代理客户端"},
        {"name": "sing-box.exe", "weight": 0.3, "reason": "代理客户端"},
        {"name": "shadowsocks.exe", "weight": 0.3, "reason": "代理客户端"},
    ],
    "notify": {"enabled": True, "min_level": "高", "sustain_minutes": 5,
               "cooldown_minutes": 10, "beep": True},
    "output": {
        "dir": "output",
        "samples_csv": "samples.csv",
        "alerts_jsonl": "alerts.jsonl",
        "report_json": "report.json",
        "log_file": "app.log",
        "report_every_minutes": 5,
        "alert_min_level": "可疑",
    },
}


if __name__ == "__main__":  # pragma: no cover
    print(format_bits(1_250_000), format_bytes(3 * 1 << 20), format_duration(3725))
