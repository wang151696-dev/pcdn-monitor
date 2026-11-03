"""utils 单元测试：公网 IP 判定、脱敏、网段、格式化、滑动窗口、持续时长、配置合并。"""
from types import SimpleNamespace

from utils import (SampleWindow, deep_merge, format_bits, format_bytes,
                   format_duration, is_public_ip, longest_sustained, mask_ip,
                   network_of)


class TestPublicIp:
    def test_public_ipv4(self):
        for ip in ("8.8.8.8", "1.1.1.1", "223.5.5.5", "114.114.114.114"):
            assert is_public_ip(ip) is True

    def test_private_ipv4(self):
        for ip in ("192.168.1.5", "10.0.0.1", "172.16.0.1", "172.31.255.255"):
            assert is_public_ip(ip) is False

    def test_special_ipv4(self):
        for ip in ("127.0.0.1", "169.254.1.1", "224.0.0.9", "255.255.255.255",
                   "0.0.0.0", "100.64.1.1", "100.127.255.254"):
            assert is_public_ip(ip) is False, ip

    def test_ipv6(self):
        assert is_public_ip("2606:4700::1111") is True
        for ip in ("::1", "fe80::1", "fd00::1", "2001:db8::1", "ff02::1"):
            assert is_public_ip(ip) is False, ip

    def test_mapped_ipv6_reduced_to_ipv4(self):
        assert is_public_ip("::ffff:8.8.8.8") is True
        assert is_public_ip("::ffff:192.168.1.1") is False

    def test_invalid(self):
        for ip in ("", "not-an-ip", "999.1.1.1", None):
            assert is_public_ip(ip) is False


class TestMaskIp:
    def test_mask_ipv4(self):
        assert mask_ip("123.45.67.89") == "123.45.67.xxx"

    def test_mask_ipv6(self):
        assert mask_ip("2606:4700:1111:2222:33:44:55:66").endswith(":xxxx")

    def test_no_mask(self):
        assert mask_ip("123.45.67.89", mask=False) == "123.45.67.89"

    def test_invalid_untouched(self):
        assert mask_ip("abc") == "abc"


class TestNetworkOf:
    def test_ipv4_slash24(self):
        assert network_of("123.45.67.89") == "123.45.67.0/24"

    def test_ipv6_slash64(self):
        assert network_of("2606:4700:1111:2222::1") == "2606:4700:1111:2222::/64"

    def test_invalid(self):
        assert network_of("bad") is None


class TestFormat:
    def test_bits(self):
        assert format_bits(0) == "0 bps"
        assert format_bits(1_280_000) == "1.3 Mbps"

    def test_bytes(self):
        assert format_bytes(0) == "0 B"
        assert format_bytes(2 * 1024 * 1024) == "2.0 MiB"

    def test_duration(self):
        assert format_duration(3725) == "01:02:05"
        assert format_duration(0) == "00:00:00"


class TestSampleWindow:
    def test_eviction(self):
        w = SampleWindow(10)
        for ts in (0, 5, 11):
            w.add(SimpleNamespace(timestamp=ts))
        assert len(w) == 2
        assert [s.timestamp for s in w.samples()] == [5, 11]


class TestLongestSustained:
    SAMPLES = [SimpleNamespace(ts=t, v=v) for t, v in
               [(0, 10), (2, 10), (4, 1), (6, 10), (8, 10), (10, 10)]]

    def test_basic_run(self):
        # 6-10 秒连续 >=10，段长 = 10-6 = 4 秒
        dur = longest_sustained(self.SAMPLES, 5, max_gap=3,
                                value=lambda s: s.v, ts=lambda s: s.ts)
        assert dur == 4.0

    def test_gap_breaks_run(self):
        samples = [SimpleNamespace(ts=t, v=10) for t in (0, 2, 30, 32)]
        dur = longest_sustained(samples, 5, max_gap=3,
                                value=lambda s: s.v, ts=lambda s: s.ts)
        assert dur == 2.0

    def test_empty(self):
        assert longest_sustained([], 5, 3, value=lambda s: 0, ts=lambda s: 0) == 0.0


class TestDeepMerge:
    def test_nested(self):
        base = {"a": {"b": 1, "c": 2}, "l": [1], "k": 0}
        out = deep_merge(base, {"a": {"c": 3}, "l": [2], "n": 9})
        assert out == {"a": {"b": 1, "c": 3}, "l": [2], "k": 0, "n": 9}
        assert base["a"]["c"] == 2  # 原字典不被修改
