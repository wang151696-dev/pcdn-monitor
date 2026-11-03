"""collector 单元测试：网卡分类、速率计算、计数器清零、连接聚合、权限降级。"""
import psutil

import collector
from collector import (ConnectionCollector, NicClassifier, TrafficCollector,
                       _snapshot_for, aggregate_connections)
from models import ProcessSnapshot
from tests.helpers import conn, make_counters, nic, traffic


class FakeInspector:
    def __init__(self, mapping=None):
        self.mapping = mapping or {}

    def inspect(self, pid):
        return self.mapping.get(pid, ProcessSnapshot(pid=pid, name=f"p{pid}"))


class TestNicClassifier:
    def setup_method(self):
        self.c = NicClassifier(
            ignore_nics=["VPN-X"],
            virtual_patterns=["vethernet", "hyper-v", "tailscale"],
        )

    def test_kinds(self):
        assert self.c.classify("Ethernet") == "monitor"
        assert self.c.classify("Wi-Fi") == "monitor"
        assert self.c.classify("vEthernet (Default Switch)") == "virtual"
        assert self.c.classify("Tailscale") == "virtual"
        assert self.c.classify("Loopback Pseudo-Interface 1") == "loopback"
        assert self.c.classify("vpn-x") == "ignored"  # 忽略大小写

    def test_counted(self):
        assert self.c.counted("monitor") is True
        assert self.c.counted("virtual") is False
        assert NicClassifier(count_virtual=True).counted("virtual") is True
        assert self.c.counted("loopback") is False


class TestTrafficCollector:
    def test_rates_and_exclusion(self):
        c = TrafficCollector(NicClassifier(virtual_patterns=["vethernet", "loopback"]))
        s1 = c.sample(now=100.0, counters=make_counters(
            nic("Ethernet", 1000, 2000),
            nic("vEthernet (DS)", 5000, 5000),
            nic("Loopback Pseudo-Interface 1", 1, 1),
        ))
        assert s1.up_bps == 0 and s1.up_delta_bytes == 0  # 首次采样建立基线

        s2 = c.sample(now=102.0, counters=make_counters(
            nic("Ethernet", 3000, 4000),      # +2000 / +2000
            nic("vEthernet (DS)", 99999, 99999),  # 虚拟网卡不计
            nic("Loopback Pseudo-Interface 1", 777, 777),
        ))
        assert s2.up_delta_bytes == 2000 and s2.down_delta_bytes == 2000
        assert s2.up_bps == 8000.0  # 2000B * 8 / 2s
        assert s2.session_up_bytes == 2000

    def test_counter_reset(self):
        c = TrafficCollector(NicClassifier())
        c.sample(now=0.0, counters=make_counters(nic("Ethernet", 5000, 6000)))
        s = c.sample(now=2.0, counters=make_counters(nic("Ethernet", 500, 700)))
        # 清零后按当前值起算，不产生负速率
        assert s.up_delta_bytes == 500 and s.down_delta_bytes == 700
        assert s.up_bps > 0 and c.reset_count == 1

    def test_empty_counters_no_crash(self):
        c = TrafficCollector(NicClassifier())
        s = c.sample(now=1.0, counters={})
        assert s.up_bps == 0 and s.up_delta_bytes == 0

    def test_removed_nic_baseline_dropped(self):
        c = TrafficCollector(NicClassifier())
        c.sample(now=0.0, counters=make_counters(nic("Ethernet", 100, 100),
                                                 nic("USB LAN", 100, 100)))
        # USB 网卡移除后重新出现，不应把两次的差值算成巨量上传
        s = c.sample(now=2.0, counters=make_counters(nic("Ethernet", 200, 200)))
        assert s.up_delta_bytes == 100
        s3 = c.sample(now=4.0, counters=make_counters(nic("Ethernet", 300, 300),
                                                      nic("USB LAN", 50, 50)))
        assert s3.up_delta_bytes == 100  # USB LAN 重新出现按新基线 0 增量


class TestAggregateConnections:
    def test_aggregation(self):
        records = [
            conn(rip="8.8.8.8", rport=443, pid=10),
            conn(rip="1.1.1.1", rport=53, kind="udp", status="NONE", pid=10),
            conn(kind="udp", rip=None, rport=None, status="NONE", pid=10),
            conn(lip="0.0.0.0", lport=8080, rip=None, rport=None, status="LISTEN", pid=20),
            conn(lip="127.0.0.1", lport=9000, rip=None, rport=None, status="LISTEN", pid=20),
            conn(rip="192.168.1.7", rport=445, pid=30),  # 私网远端不计
            conn(kind="udp", rip="9.9.9.9", rport=53, status="NONE", pid=None),
        ]
        sample = aggregate_connections(records, 1.0, traffic(1.0), FakeInspector())
        st10 = sample.stats_by_pid[10]
        assert st10.tcp_connections == 1 and st10.udp_endpoints == 2
        assert st10.remote_public_ips == {"8.8.8.8", "1.1.1.1"}
        assert st10.remote_ports == {443, 53}
        assert st10.remote_networks == {"8.8.8.0/24", "1.1.1.0/24"}

        st20 = sample.stats_by_pid[20]
        assert st20.listening_ports == {8080, 9000}
        assert sample.public_listener_ports == 1  # 127.0.0.1 绑定不算公网监听
        assert sample.listener_pids == {20}

        st30 = sample.stats_by_pid[30]
        assert st30.remote_public_ips == set()

        assert sample.unknown_pid_connections == 1
        assert sample.total.tcp_connections == 4 and sample.total.udp_endpoints == 3
        assert sample.total.remote_public_ips == {"8.8.8.8", "1.1.1.1", "9.9.9.9"}

    def test_empty_records(self):
        sample = aggregate_connections([], 1.0, traffic(1.0), FakeInspector())
        assert sample.total.tcp_connections == 0
        assert sample.stats_by_pid == {}
        assert sample.connections_available is True

    def test_kernel_pid0_named_without_inspector(self):
        # pid 0 多为内核持有的 TIME_WAIT 套接字，不应归到任何真实进程
        snap = _snapshot_for(0, FakeInspector())
        assert snap.pid == 0
        assert snap.name == "(系统内核连接)"


class TestConnectionCollectorDegrade:
    def test_access_denied_degrades(self, monkeypatch):
        def denied(*a, **k):
            raise psutil.AccessDenied()

        monkeypatch.setattr(collector.psutil, "net_connections", denied)
        c = ConnectionCollector(FakeInspector())
        sample = c.sample(traffic(1.0))
        assert sample.connections_available is False
        assert sample.total.tcp_connections == 0  # 不抛异常，继续运行

    def test_process_exit_during_collect(self, monkeypatch):
        class VanishingInspector:
            def inspect(self, pid):
                raise psutil.NoSuchProcess(pid)

        monkeypatch.setattr(collector.psutil, "net_connections",
                            lambda *a, **k: [])
        # aggregate 对 inspect 抛异常也应有占位画像
        sample = aggregate_connections([conn(rip="8.8.8.8", rport=443, pid=42)],
                                       1.0, traffic(1.0), VanishingInspector())
        snap = sample.processes[42]
        assert snap.inspect_error is not None
        assert sample.total.remote_public_ips == {"8.8.8.8"}
