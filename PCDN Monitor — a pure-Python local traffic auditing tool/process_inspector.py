"""进程画像：可执行路径、命令行、用户名、可疑目录、开机自启动。

- 读取 psutil.Process 信息时全部容错：进程退出 / 权限不足只降级字段，不抛异常。
- 自启动检查（仅 Windows）：注册表 Run 键（HKCU/HKM/WOW6432Node）+ 启动文件夹。
  通过 AutostartIndex(source=...) 可注入数据源，便于测试与非 Windows 平台降级。
"""
from __future__ import annotations

import logging
import os
import time
from typing import Callable, Iterable, Optional, Set, Tuple

import psutil

from models import ProcessSnapshot

log = logging.getLogger("pcdn.process")

DEFAULT_SUSPICIOUS_PATTERNS = [
    "\\temp\\", "\\tmp\\", "\\windows\\temp\\", "\\appdata\\local\\temp\\", "\\cache\\",
]


def normalize_path(path: str) -> str:
    return path.replace("/", "\\").lower()


def is_suspicious_path(exe: Optional[str],
                       patterns: Iterable[str] = DEFAULT_SUSPICIOUS_PATTERNS) -> bool:
    """可执行文件是否位于临时/缓存等异常目录（模式匹配为路径子串，忽略大小写）。"""
    if not exe:
        return False
    norm = normalize_path(exe)
    return any(str(p).lower() in norm for p in patterns)


# ---------------------------------------------------------------- 自启动

def _startup_folders() -> list:
    folders = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        folders.append(os.path.join(appdata, "Microsoft", "Windows",
                                    "Start Menu", "Programs", "Startup"))
    programdata = os.environ.get("PROGRAMDATA")
    if programdata:
        folders.append(os.path.join(programdata, "Microsoft", "Windows",
                                    "Start Menu", "Programs", "StartUp"))
    return folders


def _default_autostart_source() -> Tuple[Set[str], str]:
    """收集自启动项：返回 (可执行名集合, 供子串匹配的小写文本)。非 Windows 返回空。"""
    if os.name != "nt":
        return set(), ""
    names: Set[str] = set()
    blobs = []

    import winreg

    run_keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ]
    for root, subkey in run_keys:
        try:
            key = winreg.OpenKey(root, subkey)
        except OSError:
            continue
        try:
            i = 0
            while True:
                try:
                    _name, data, _typ = winreg.EnumValue(key, i)
                except OSError:
                    break
                i += 1
                if isinstance(data, str) and data.strip():
                    blobs.append(data)
                    low = data.lower()
                    idx = low.find(".exe")
                    if idx != -1:
                        token = low[: idx + 4].replace('"', "").split("\\")[-1].strip()
                        if token:
                            names.add(token)
        finally:
            winreg.CloseKey(key)

    for folder in _startup_folders():
        try:
            entries = os.listdir(folder)
        except OSError:
            continue
        for fn in entries:
            low = fn.lower()
            blobs.append(low)
            names.add(low)
            names.add(low.rsplit(".", 1)[0])

    return names, " \n ".join(blobs).lower()


class AutostartIndex:
    """自启动索引，带定时刷新；source 可注入以便测试。"""

    def __init__(self, refresh_seconds: float = 300.0,
                 source: Optional[Callable[[], Tuple[Set[str], str]]] = None):
        self._source = source or _default_autostart_source
        self._refresh_seconds = float(refresh_seconds)
        self._names: Set[str] = set()
        self._blob: str = ""
        self._next_refresh = 0.0

    def refresh_if_due(self, now: Optional[float] = None) -> None:
        now = time.time() if now is None else now
        if now < self._next_refresh:
            return
        try:
            self._names, self._blob = self._source()
        except Exception:
            log.exception("读取自启动项失败")
        self._next_refresh = now + self._refresh_seconds

    def is_autostart(self, exe: Optional[str]) -> bool:
        if not exe:
            return False
        self.refresh_if_due()
        base = normalize_path(exe).split("\\")[-1]
        stem = base[:-4] if base.endswith(".exe") else base
        if base in self._names or stem in self._names:
            return True
        return base in self._blob


# ---------------------------------------------------------------- 进程画像

def _safe(fn: Callable, default=None):
    try:
        return fn()
    except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
        return default
    except Exception:
        return default


def _psutil_snapshot(pid: int) -> ProcessSnapshot:
    proc = psutil.Process(pid)
    snap = ProcessSnapshot(pid=pid)
    name = _safe(lambda: proc.name())
    snap.name = name or str(pid)
    snap.exe = _safe(lambda: proc.exe())
    snap.cmdline = _safe(lambda: proc.cmdline())
    snap.create_time = _safe(lambda: proc.create_time())
    snap.username = _safe(lambda: proc.username())
    return snap


class ProcessInspector:
    """带缓存的进程画像；factory 可注入以便测试。"""

    def __init__(self, config: Optional[dict] = None,
                 autostart: Optional[AutostartIndex] = None,
                 factory: Optional[Callable[[int], ProcessSnapshot]] = None,
                 cache_seconds: float = 30.0):
        cfg_patterns = (config or {}).get("suspicious_path_patterns")
        self.patterns = [str(p) for p in cfg_patterns] if cfg_patterns else DEFAULT_SUSPICIOUS_PATTERNS
        self.autostart = autostart if autostart is not None else AutostartIndex()
        self._factory = factory or _psutil_snapshot
        self._cache_seconds = float(cache_seconds)
        self._cache: dict = {}   # pid -> (采集时间, ProcessSnapshot)

    def inspect(self, pid: int) -> ProcessSnapshot:
        now = time.time()
        hit = self._cache.get(pid)
        if hit is not None and now - hit[0] < self._cache_seconds:
            return hit[1]
        try:
            snap = self._factory(pid)
        except psutil.NoSuchProcess:
            # 采集期间进程退出：返回占位画像，不中断采集
            snap = ProcessSnapshot(pid=pid, name="(已退出)", inspect_error="no_such_process")
        except Exception as exc:
            snap = ProcessSnapshot(pid=pid, name=f"(PID {pid})", inspect_error=str(exc))
        snap.path_suspicious = is_suspicious_path(snap.exe, self.patterns)
        self.autostart.refresh_if_due(now)
        snap.autostart = self.autostart.is_autostart(snap.exe)
        self._cache[pid] = (now, snap)
        return snap
