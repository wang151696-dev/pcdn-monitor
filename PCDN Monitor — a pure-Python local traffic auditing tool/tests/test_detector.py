"""detector 单元测试：评分、连续确认、各规则、白名单折算、等级映射。"""
import pytest

from detector import Detector, Whitelist, min_score_for_level
from tests.helpers import mon_sample, snap, stats, traffic
from utils import DEFAULT_CONFIG, deep_merge


def make_config(rules=None, whitelist=None, **over):
    cfg = deep_merge(DEFAULT_CONFIG, {
        "interval_seconds": 2,
        "window_minutes": 5,
        "consecutive_cycles": 3,
        "score_levels": {"low_max": 29, "suspicious_max": 59, "high_max": 79},
    })
    if rules:
        cfg = deep_merge(cfg, {"rules": rules})
    if whitelist is not None:
        cfg["whitelist"] = whitelist
    cfg = deep_merge(cfg, over)
    return cfg


def add_and_eval(detector, samples, times=3):
    for s in samples:
        detector.add_sample(s)
    last = None
    for _ in range(times):
        last = detector.evaluate()
    return last


def result_of(assessment, rule_id):
    return next(r for r in assessment.results if r.rule_id == rule_id)


class TestSustainedUpload:
    @staticmethod
    def _good(i):
        ts = 1000 + i * 2
        return mon_sample(ts=ts, traffic_sample=traffic(ts=ts, up_bps=5e6,
                                                        up=10**6, down=10**6))

    def test_fires_after_confirmation(self):
        cfg = make_config(rules={"sustained_upload": {"mbps": 1.0, "minutes": 0.1}})
        d = Detector(cfg)
        for i in range(7):  # 持续 12 秒 >= 6 秒阈值
            d.add_sample(self._good(i))
        a1 = d.evaluate()
        assert result_of(a1, "sustained_upload").fired is True
        assert a1.score == 0  # 第 1 次命中，未达连续 3 次
        a2 = d.evaluate()
        assert a2.score == 0  # 第 2 次命中仍不计分
        a3 = d.evaluate()
        assert result_of(a3, "sustained_upload").confirmed is True
        assert a3.score == 20

    def test_broken_streak_resets(self):
        cfg = make_config(rules={"sustained_upload": {"minutes": 0.1}})
        d = Detector(cfg)  # window_minutes=5 → 300s 窗口
        for i in range(7):
            d.add_sample(self._good(i))          # ts 1000..1012
        d.evaluate()
        d.evaluate()
        assert d.evaluate().score == 20
        # 平静期样本推进时间，把持续上传段逐出窗口
        d.add_sample(mon_sample(ts=1400, traffic_sample=traffic(ts=1400, up_bps=0,
                                                               up=1, down=1)))
        a = d.evaluate()
        assert result_of(a, "sustained_upload").fired is False
        assert a.score == 0
        # 条件恢复后需重新连续 3 次才计分
        for i in range(10):
            d.add_sample(self._good(200 + i))    # ts 1400..1418
        assert d.evaluate().score == 0
        d.evaluate()
        assert d.evaluate().score == 20

    def test_not_fired_when_below_threshold(self):
        cfg = make_config(rules={"sustained_upload": {"minutes": 0.1}})
        samples = [mon_sample(ts=1000 + i * 2,
                              traffic_sample=traffic(ts=1000 + i * 2, up_bps=1e5,
                                                     up=10**4, down=10**4))
                   for i in range(7)]
        a = add_and_eval(Detector(cfg), samples)
        assert result_of(a, "sustained_upload").fired is False
        assert a.score == 0


class TestUploadRatio:
    def test_ratio_fires(self):
        cfg = make_config(rules={"upload_ratio": {"ratio": 2.0, "min_upload_mbytes": 0.001}})
        samples = [mon_sample(ts=1000 + i * 2,
                              traffic_sample=traffic(ts=1000 + i * 2, up_bps=0,
                                                     up=3_000_000, down=1_000_000))
                   for i in range(5)]
        a = add_and_eval(Detector(cfg), samples)
        r = result_of(a, "upload_ratio")
        assert r.confirmed is True and a.score == 15
        assert "3.0" in r.evidence

    def test_small_upload_ignored(self):
        cfg = make_config(rules={"upload_ratio": {"ratio": 2.0, "min_upload_mbytes": 10}})
        samples = [mon_sample(ts=1000 + i * 2,
                              traffic_sample=traffic(ts=1000 + i * 2, up=100, down=1))
                   for i in range(5)]
        a = add_and_eval(Detector(cfg), samples)
        assert result_of(a, "upload_ratio").fired is False

    def test_zero_download_counts_as_infinite(self):
        cfg = make_config(rules={"upload_ratio": {"ratio": 2.0, "min_upload_mbytes": 0.001}})
        samples = [mon_sample(ts=1000 + i,
                              traffic_sample=traffic(ts=1000 + i, up=2_000_000, down=0))
                   for i in range(3)]
        a = add_and_eval(Detector(cfg), samples)
        assert result_of(a, "upload_ratio").confirmed is True


class TestIpDispersal:
    def test_many_public_ips(self):
        cfg = make_config(rules={"many_public_ips": {"distinct_ips": 5}})
        ips = {f"8.8.8.{i}" for i in range(1, 7)}
        samples = [mon_sample(ts=1000 + i * 2, stats={1: stats(ips=ips)})
                   for i in range(3)]
        a = add_and_eval(Detector(cfg), samples)
        r = result_of(a, "many_public_ips")
        assert r.confirmed is True and a.score == 15

    def test_remote_ip_whitelist_excludes(self):
        wl = [{"remote_ip": f"8.8.8.{i}", "weight": 0, "reason": "已知服务"} for i in range(1, 5)]
        cfg = make_config(rules={"many_public_ips": {"distinct_ips": 5}}, whitelist=wl)
        ips = {f"8.8.8.{i}" for i in range(1, 7)}  # 6 个 IP，其中 4 个白名单
        samples = [mon_sample(ts=1000 + i * 2, stats={1: stats(ips=ips)})
                   for i in range(3)]
        a = add_and_eval(Detector(cfg), samples)
        assert result_of(a, "many_public_ips").fired is False  # 只剩 2 个

    def test_remote_port_whitelist_excludes_ports(self):
        wl = [{"port": 443, "weight": 0, "reason": "https"}]
        cfg = make_config(rules={"dispersed_ports": {"distinct_ports": 3}}, whitelist=wl)
        samples = [mon_sample(ts=1000 + i * 2,
                              stats={1: stats(ips={"8.8.8.1"}, ports={80, 443, 8080})})
                   for i in range(3)]
        a = add_and_eval(Detector(cfg), samples)
        assert result_of(a, "dispersed_ports").fired is False  # 443 被排除，剩 2 个


class TestProcessRules:
    def test_process_many_conns(self):
        cfg = make_config(rules={"process_many_conns": {"connections": 3}})
        samples = [mon_sample(ts=1000 + i * 2,
                              stats={10: stats(tcp=5, ips={"8.8.8.1"})},
                              processes={10: snap(10, "sus.exe", "C:\\x\\sus.exe")})
                   for i in range(3)]
        a = add_and_eval(Detector(cfg), samples)
        r = result_of(a, "process_many_conns")
        assert r.confirmed and a.score == 10 and "sus.exe" in r.evidence

    def test_process_whitelist_reduces_points(self):
        cfg = make_config(
            rules={"process_many_conns": {"connections": 3}},
            whitelist=[{"name": "onedrive.exe", "weight": 0.3, "reason": "云盘同步"}])
        samples = [mon_sample(ts=1000 + i * 2,
                              stats={10: stats(tcp=5, ips={"8.8.8.1"})},
                              processes={10: snap(10, "OneDrive.exe", "C:\\x\\OneDrive.exe")})
                   for i in range(3)]
        a = add_and_eval(Detector(cfg), samples)
        r = result_of(a, "process_many_conns")
        assert r.confirmed is True
        assert r.effective_points == pytest.approx(3.0)
        assert r.whitelist_hits and "云盘同步" in r.whitelist_hits[0]
        assert a.score == 3

    def test_process_whitelist_zero_ignores_rule(self):
        cfg = make_config(
            rules={"process_many_conns": {"connections": 3}},
            whitelist=[{"name": "onedrive.exe", "weight": 0, "reason": "云盘同步"}])
        samples = [mon_sample(ts=1000 + i * 2,
                              stats={10: stats(tcp=5, ips={"8.8.8.1"})},
                              processes={10: snap(10, "onedrive.exe")})
                   for i in range(3)]
        a = add_and_eval(Detector(cfg), samples)
        r = result_of(a, "process_many_conns")
        assert r.fired is True and r.effective_points == 0 and a.score == 0

    def test_kernel_pid0_excluded(self):
        # 内核(pid 0)持有的大量 TIME_WAIT 套接字不应触发进程级规则
        cfg = make_config(rules={"process_many_conns": {"connections": 3}})
        samples = [mon_sample(ts=1000 + i * 2,
                              stats={0: stats(tcp=500), 10: stats(tcp=2)},
                              processes={0: snap(0, "(系统内核连接)"),
                                         10: snap(10, "app.exe")})
                   for i in range(3)]
        a = add_and_eval(Detector(cfg), samples)
        assert result_of(a, "process_many_conns").fired is False
        # 但 pid 0 的连接仍计入系统级统计
        assert samples[0].total.tcp_connections == 502

    def test_suspicious_path_rule(self):
        cfg = make_config(rules={"suspicious_path": {"min_connections": 1}})
        exe = "C:\\Users\\u\\AppData\\Local\\Temp\\evil.exe"
        samples = [mon_sample(ts=1000 + i * 2,
                              stats={66: stats(tcp=1)},
                              processes={66: snap(66, "evil.exe", exe, path_suspicious=True)})
                   for i in range(3)]
        a = add_and_eval(Detector(cfg), samples)
        assert result_of(a, "suspicious_path").confirmed is True

    def test_autostart_rule(self):
        cfg = make_config(rules={"autostart_activity": {"min_connections": 1}})
        samples = [mon_sample(ts=1000 + i * 2,
                              stats={66: stats(tcp=2)},
                              processes={66: snap(66, "boot.exe", "C:\\b\\boot.exe", autostart=True)})
                   for i in range(3)]
        a = add_and_eval(Detector(cfg), samples)
        assert result_of(a, "autostart_activity").confirmed is True


class TestListenersAndUdp:
    def test_public_listeners(self):
        cfg = make_config(rules={"public_listeners": {"ports": 2}})
        samples = [mon_sample(ts=1000 + i * 2, listeners=2, listener_pids=[5],
                              stats={5: stats(listening=(9000, 9001))},
                              processes={5: snap(5, "srv.exe")})
                   for i in range(3)]
        a = add_and_eval(Detector(cfg), samples)
        assert result_of(a, "public_listeners").confirmed is True

    def test_udp_anomaly(self):
        cfg = make_config(rules={"udp_anomaly": {"udp_endpoints": 10}})
        samples = [mon_sample(ts=1000 + i * 2, stats={7: stats(udp=12)},
                              processes={7: snap(7, "u.exe")})
                   for i in range(3)]
        a = add_and_eval(Detector(cfg), samples)
        assert result_of(a, "udp_anomaly").confirmed is True


class TestScoring:
    def test_score_capped_at_100(self):
        cfg = make_config(rules={
            "sustained_upload": {"minutes": 0.01, "mbps": 1.0},
            "upload_ratio": {"ratio": 2, "min_upload_mbytes": 0.001},
            "many_public_ips": {"distinct_ips": 3},
            "dispersed_networks": {"distinct_networks": 2},
            "dispersed_ports": {"distinct_ports": 3},
            "udp_anomaly": {"udp_endpoints": 1},
            "process_many_conns": {"connections": 1},
            "public_listeners": {"ports": 1},
            "suspicious_path": {"min_connections": 1},
            "autostart_activity": {"min_connections": 1},
        })
        exe = "C:\\Users\\u\\AppData\\Local\\Temp\\pcdn.exe"
        samples = [mon_sample(
            ts=1000 + i * 2,
            traffic_sample=traffic(ts=1000 + i * 2, up_bps=5e6, down_bps=1e5,
                                   up=5_000_000, down=1_000_000),
            stats={10: stats(tcp=2, udp=1, ips={"8.8.8.1", "8.8.9.1", "8.8.10.1"},
                             ports={1, 2, 3}, listening=(6666,))},
            processes={10: snap(10, "pcdn.exe", exe, autostart=True, path_suspicious=True)},
            listeners=1, listener_pids=[10])
            for i in range(4)]
        a = add_and_eval(Detector(cfg), samples)
        raw = sum(r.effective_points for r in a.results)
        assert raw > 100
        assert a.score == 100
        assert a.level == "严重"
        assert len(a.confirmed_rules) == 10

    def test_levels(self):
        d = Detector(make_config())
        for score, level in ((0, "低"), (29, "低"), (30, "可疑"), (59, "可疑"),
                             (60, "高"), (79, "高"), (80, "严重"), (100, "严重")):
            assert d.level_of(score) == level

    def test_empty_window_no_crash(self):
        a = Detector(make_config()).evaluate()
        assert a.score == 0 and a.level == "低"
        assert all(r.fired is False for r in a.results)

    def test_min_score_for_level(self):
        levels = {"low_max": 29, "suspicious_max": 59, "high_max": 79}
        assert min_score_for_level("低", levels) == 0
        assert min_score_for_level("可疑", levels) == 30
        assert min_score_for_level("高", levels) == 60
        assert min_score_for_level("严重", levels) == 80


class TestWhitelistMatching:
    def test_match_by_name_path_pid(self):
        wl = Whitelist([
            {"name": "a.exe", "weight": 0.3},
            {"path": "C:\\Tools", "weight": 0.5},
            {"pid": 4242, "weight": 0.1},
        ])
        assert wl.match_process(snap(1, "A.EXE")) is not None          # 忽略大小写
        assert wl.match_process(snap(2, "x.exe", "C:\\tools\\sub\\x.exe")) is not None
        assert wl.match_process(snap(4242, "whatever.exe")) is not None
        assert wl.match_process(snap(3, "b.exe", "C:\\Windows\\b.exe")) is None

    def test_match_remote(self):
        wl = Whitelist([
            {"remote_ip": "1.2.3.4", "weight": 0},
            {"port": 53, "weight": 0},
        ])
        assert wl.match_remote("1.2.3.4", 9999) is not None
        assert wl.match_remote("5.6.7.8", 53) is not None
        assert wl.match_remote("5.6.7.8", 443) is None

    def test_whitelist_does_not_touch_raw_stats(self):
        # 白名单只影响评分，不影响样本里的原始统计
        cfg = make_config(
            rules={"many_public_ips": {"distinct_ips": 3}},
            whitelist=[{"remote_ip": "8.8.8.1", "weight": 0}])
        sample = mon_sample(ts=1.0, stats={1: stats(ips={"8.8.8.1", "8.8.8.2"})})
        d = Detector(cfg)
        d.add_sample(sample)
        d.evaluate()
        assert sample.total.remote_public_ips == {"8.8.8.1", "8.8.8.2"}
