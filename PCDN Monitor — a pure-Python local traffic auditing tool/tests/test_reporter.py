"""reporter 单元测试：IP 脱敏、报告结构、告警 JSONL、样本 CSV、提醒安全降级。"""
import json
import time

from models import RiskAssessment, RuleResult
from reporter import (AlertJsonlWriter, ReportWriter, SampleCsvWriter,
                      SessionStats, build_report, notify_user)
from tests.helpers import mon_sample, snap, stats, traffic


def make_assessment(score=65, level="高"):
    rules = [
        RuleResult("many_public_ips", "连接大量不同公网IP", 15, True, True, 15,
                   "窗口内连接了 120 个不同远端公网 IP", []),
        RuleResult("process_many_conns", "单进程大量外连", 10, True, True, 10,
                   "x.exe(PID 9)", ["onedrive.exe(云盘同步, 权重0.3)"]),
    ]
    return RiskAssessment(time.time(), score, level, rules)


def feed_session(session, n=3):
    for i in range(n):
        sample = mon_sample(
            ts=1000 + i * 2,
            traffic_sample=traffic(ts=1000 + i * 2, up_bps=2e6, down_bps=1e5,
                                   up=500_000, down=25_000),
            stats={10: stats(tcp=50, ips={"123.45.67.89", "98.76.54.32"}, ports={443})},
            processes={10: snap(10, "sus.exe", "C:\\Temp\\sus.exe")},
        )
        session.update(sample)
    session.note_whitelist_hits(["onedrive.exe(云盘同步, 权重0.3)"])
    return session


class TestSessionStats:
    def test_accumulation(self):
        s = SessionStats()
        feed_session(s, n=3)
        assert s.up_bytes == 1_500_000
        assert s.down_bytes == 75_000
        assert s.peak_up_bps == 2e6
        assert s.ip_counter["123.45.67.89"] == 3
        assert len(s.processes) == 1
        assert s.processes[10].name == "sus.exe"
        assert s.whitelist_hits


class TestBuildReport:
    def test_masked_by_default(self, tmp_path):
        session = feed_session(SessionStats())
        report = build_report(session, make_assessment(),
                              {"mask_public_ips": True})
        top_ips = [e["ip"] for e in report["connections"]["top_remote_ips"]]
        assert "123.45.67.xxx" in top_ips
        assert not any("123.45.67.89" in ip for ip in top_ips)

    def test_unmasked_when_disabled(self):
        session = feed_session(SessionStats())
        report = build_report(session, make_assessment(),
                              {"mask_public_ips": False})
        top_ips = [e["ip"] for e in report["connections"]["top_remote_ips"]]
        assert "123.45.67.89" in top_ips

    def test_structure_and_wording(self):
        session = feed_session(SessionStats())
        report = build_report(session, make_assessment(35, "可疑"),
                              {"mask_public_ips": True}, meta={"admin": False})
        assert report["risk"]["score"] == 35 and report["risk"]["level"] == "可疑"
        assert "疑似" in report["risk"]["note"]
        assert report["top_processes"][0]["name"] == "sus.exe"
        assert report["whitelist_hits"]
        assert any("无法精确统计" in n for n in report["limitations"])
        assert report["meta"]["admin"] is False
        # 序列化完整（无不可转 JSON 的对象）
        json.dumps(report, ensure_ascii=False)

    def test_report_writer_atomic(self, tmp_path):
        session = feed_session(SessionStats())
        path = ReportWriter(tmp_path / "sub" / "report.json").write(
            session, make_assessment(), {"mask_public_ips": True})
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["risk"]["score"] == 65
        assert not (tmp_path / "sub" / "report.json.tmp").exists()


class TestAlertJsonl:
    def test_write_and_dedupe(self, tmp_path):
        w = AlertJsonlWriter(tmp_path / "alerts.jsonl", min_score=30)
        session = feed_session(SessionStats())
        a = make_assessment(65, "高")
        assert w.maybe_alert(a, session) is True
        assert w.maybe_alert(a, session) is False          # 同级同分不重复
        assert w.maybe_alert(make_assessment(76, "高"), session) is True   # +10 抬升
        assert w.maybe_alert(make_assessment(20, "低"), session) is False  # 低于阈值
        assert w.maybe_alert(make_assessment(45, "可疑"), session) is True  # 回落后再抬升
        w.close()
        lines = (tmp_path / "alerts.jsonl").read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 3
        entries = [json.loads(line) for line in lines]
        assert entries[0]["level"] == "高"
        assert entries[0]["rules"][0]["id"] == "many_public_ips"
        assert entries[2]["level"] == "可疑"


class TestSampleCsv:
    def test_rows(self, tmp_path):
        w = SampleCsvWriter(tmp_path / "samples.csv")
        sample = mon_sample(ts=1000.0,
                            traffic_sample=traffic(ts=1000.0, up_bps=1.0, down_bps=2.0,
                                                   up=3, down=4),
                            stats={1: stats(tcp=9, ips={"1.1.1.1"})})
        w.write(sample, make_assessment(45, "可疑"))
        w.write(sample, None)
        w.close()
        lines = (tmp_path / "samples.csv").read_text(encoding="utf-8-sig").strip().splitlines()
        assert len(lines) == 3  # 表头 + 2 行
        assert "可疑" in lines[1] and lines[2].endswith(",")


class TestNotify:
    def test_never_raises(self):
        # 弹窗/蜂鸣在非 Windows 或无显示环境必须静默失败
        notify_user("t", "m", beep=False)
        notify_user("t", "m", beep=True)
