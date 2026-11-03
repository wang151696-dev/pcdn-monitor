"""端到端集成测试：--once 模式真实采集一轮，校验全部输出文件落盘。"""
import json

from reporter import setup_logging


def test_once_end_to_end(tmp_path, monkeypatch):
    import main

    out = tmp_path / "out"
    rc = main.main(["--once", "--no-ui", "--output", str(out)])
    assert rc == 0

    # samples.csv：表头 + 1 行数据
    csv_text = (out / "samples.csv").read_text(encoding="utf-8-sig").strip()
    lines = csv_text.splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("time,up_bps")

    # report.json：结构完整且可解析
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["samples"] == 1
    assert 0 <= report["risk"]["score"] <= 100
    assert report["risk"]["level"] in ("低", "可疑", "高", "严重")
    assert report["totals"]["upload_bytes"] >= 0
    assert report["limitations"]

    # 日志与告警文件存在（告警可为空文件）
    assert (out / "app.log").exists()
    assert (out / "alerts.jsonl").exists()

    setup_logging(None, console=False)  # 清理日志 handler，避免影响其他测试
