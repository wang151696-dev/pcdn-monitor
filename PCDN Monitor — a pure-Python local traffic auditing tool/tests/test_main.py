"""main 模块轻量测试：配置加载/合并、参数（不运行主循环）。"""
import json

import pytest

import main
from utils import DEFAULT_CONFIG


class TestLoadConfig:
    def test_missing_explicit_path_fails(self, tmp_path):
        with pytest.raises(SystemExit):
            main.load_config(str(tmp_path / "nope.json"))

    def test_default_when_no_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(main, "PROJECT_DIR", tmp_path)
        assert main.load_config(None) == DEFAULT_CONFIG

    def test_user_overrides_merged(self, tmp_path):
        p = tmp_path / "cfg.json"
        p.write_text(json.dumps({
            "interval_seconds": 5,
            "rules": {"sustained_upload": {"mbps": 2.5}},
            "whitelist": [{"name": "x.exe", "weight": 0}],
        }), encoding="utf-8")
        cfg = main.load_config(str(p))
        assert cfg["interval_seconds"] == 5
        assert cfg["rules"]["sustained_upload"]["mbps"] == 2.5
        assert cfg["rules"]["sustained_upload"]["minutes"] == 10   # 未覆盖项保留
        assert cfg["whitelist"] == [{"name": "x.exe", "weight": 0}]
        assert DEFAULT_CONFIG["whitelist"]  # 原默认不被修改

    def test_broken_json_fails(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not json", encoding="utf-8")
        with pytest.raises(SystemExit):
            main.load_config(str(p))


class TestArgs:
    def test_flags(self):
        args = main.parse_args(["--once", "--no-ui", "--interval", "1",
                                "--duration", "10", "--output", "o"])
        assert args.once and args.no_ui
        assert args.interval == 1.0 and args.duration == 10.0
        assert args.output == "o"

    def test_defaults(self):
        args = main.parse_args([])
        assert not args.once and not args.no_ui
        assert args.interval is None and args.duration is None
