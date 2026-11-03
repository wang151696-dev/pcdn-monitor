"""process_inspector 单元测试：异常目录判定、进程退出容错、自启动索引、缓存。"""
import psutil

from models import ProcessSnapshot
from process_inspector import (AutostartIndex, ProcessInspector,
                               is_suspicious_path)


class TestSuspiciousPath:
    def test_temp_paths(self):
        for exe in ("C:\\Users\\x\\AppData\\Local\\Temp\\svc.exe",
                    "C:\\Windows\\Temp\\a.exe",
                    "c:\\users\\x\\appdata\\local\\temp\\sub\\b.exe",
                    "D:\\soft\\Cache\\tool.exe"):
            assert is_suspicious_path(exe) is True, exe

    def test_normal_paths(self):
        for exe in ("C:\\Program Files\\App\\app.exe",
                    "C:\\Program Files (x86)\\App\\app.exe",
                    "C:\\Windows\\System32\\svchost.exe"):
            assert is_suspicious_path(exe) is False, exe

    def test_case_and_slash_insensitive(self):
        assert is_suspicious_path("c:/Users/x/Temp/app.EXE") is True
        assert is_suspicious_path("C:/Users/x/AppData/Local/Temp/a.exe") is True

    def test_none(self):
        assert is_suspicious_path(None) is False
        assert is_suspicious_path("") is False

    def test_custom_patterns(self):
        assert is_suspicious_path("C:\\Games\\portable\\x.exe",
                                  patterns=["\\games\\portable\\"]) is True


class TestProcessInspector:
    def test_factory_snapshot_and_flags(self):
        auto = AutostartIndex(source=lambda: ({"foo.exe"}, "c:\\x\\foo.exe"))
        insp = ProcessInspector(
            config={"suspicious_path_patterns": ["\\temp\\"]},
            autostart=auto,
            factory=lambda pid: ProcessSnapshot(
                pid=pid, name="foo.exe", exe="C:\\Program Files\\foo\\foo.exe"),
        )
        snap = insp.inspect(123)
        assert snap.name == "foo.exe"
        assert snap.autostart is True       # foo.exe 命中自启动索引
        assert snap.path_suspicious is False

    def test_suspicious_path_flag(self):
        insp = ProcessInspector(
            factory=lambda pid: ProcessSnapshot(
                pid=pid, name="svc.exe",
                exe="C:\\Users\\u\\AppData\\Local\\Temp\\svc.exe"))
        assert insp.inspect(1).path_suspicious is True

    def test_process_exit_returns_placeholder(self):
        def factory(pid):
            raise psutil.NoSuchProcess(pid)

        insp = ProcessInspector(factory=factory)
        snap = insp.inspect(999)
        assert snap.inspect_error == "no_such_process"
        assert snap.name == "(已退出)"

    def test_access_denited_partial(self):
        def factory(pid):
            raise psutil.AccessDenied()

        insp = ProcessInspector(factory=factory)
        snap = insp.inspect(7)
        assert snap.pid == 7 and snap.exe is None

    def test_cache_hit(self):
        calls = []

        def factory(pid):
            calls.append(pid)
            return ProcessSnapshot(pid=pid, name="a.exe")

        insp = ProcessInspector(factory=factory, cache_seconds=60)
        insp.inspect(5)
        insp.inspect(5)
        assert calls == [5]


class TestAutostartIndex:
    def test_injected_source(self):
        idx = AutostartIndex(source=lambda: ({"steam"}, "steam.lnk c:\\games\\updater.exe"))
        assert idx.is_autostart("C:\\Games\\Steam\\Steam.exe") is True   # stem 命中
        assert idx.is_autostart("C:\\Tools\\Updater.exe") is True        # blob 命中
        assert idx.is_autostart("C:\\Tools\\random.exe") is False
        assert idx.is_autostart(None) is False

    def test_default_source_on_non_windows_or_windows(self):
        idx = AutostartIndex()
        idx.refresh_if_due(now=1.0)
        idx.refresh_if_due(now=2.0)  # 未到刷新间隔，不重复读取
        assert isinstance(idx.is_autostart("C:\\nothing\\x.exe"), bool)
