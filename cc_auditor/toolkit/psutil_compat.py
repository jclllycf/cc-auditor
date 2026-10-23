"""Runtime compatibility layer for psutil, headless Qt (PySide6), and FUSE fsync.

Ensures CC Auditor v1.4 and v2.0 Toolkit run cleanly in both:
1. Full Windows Python environments (with native psutil and PySide6 installed);
2. Minimal Python / Agent / Cloud sandbox environments (where psutil or PySide6 may be absent,
   or where virtual/FUSE filesystems reject os.fsync with EOPNOTSUPP/EINVAL).
"""
from __future__ import annotations

import ctypes
import os
import sys
import types
from pathlib import Path
from types import SimpleNamespace


def _linux_total_ram() -> int:
    try:
        with open("/proc/meminfo", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        return int(parts[1]) * 1024
    except OSError:
        pass
    return 16_000_000_000


def _windows_total_ram() -> int:
    if sys.platform != "win32":
        return _linux_total_ram()
    try:
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]
        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
            return int(stat.ullTotalPhys)
    except Exception:
        pass
    return 0


def build_psutil_fallback() -> types.ModuleType:
    """Create a safe, read-only fallback module conforming to the narrow psutil interface."""
    mod = types.ModuleType("psutil")
    mod.__version__ = "7.2.2-compat"
    mod.CONN_ESTABLISHED = "ESTABLISHED"

    class Error(Exception):
        pass

    class NoSuchProcess(Error):
        def __init__(self, pid=None, name=None, msg=None):
            super().__init__(msg or f"process {pid} not found")
            self.pid = pid

    class AccessDenied(Error):
        def __init__(self, pid=None, name=None, msg=None):
            super().__init__(msg or f"access denied for pid {pid}")
            self.pid = pid

    mod.Error = Error
    mod.NoSuchProcess = NoSuchProcess
    mod.AccessDenied = AccessDenied
    mod.cpu_count = lambda logical=True: os.cpu_count() or 1
    mod.virtual_memory = lambda: SimpleNamespace(total=_windows_total_ram())

    class Process:
        def __init__(self, pid: int):
            self.pid = int(pid)
            self.info = {"name": "", "ppid": 0}
            if sys.platform.startswith("linux"):
                proc_dir = Path(f"/proc/{self.pid}")
                if not proc_dir.exists():
                    raise NoSuchProcess(self.pid)
                try:
                    comm = (proc_dir / "comm").read_text(encoding="utf-8", errors="ignore").strip()
                    self.info["name"] = comm
                except OSError as exc:
                    raise AccessDenied(self.pid) from exc

        def name(self) -> str:
            return self.info.get("name") or ""

        def ppid(self) -> int:
            return int(self.info.get("ppid") or 0)

        def exe(self) -> str:
            if sys.platform.startswith("linux"):
                try:
                    return os.readlink(f"/proc/{self.pid}/exe")
                except OSError as exc:
                    raise AccessDenied(self.pid) from exc
            raise AccessDenied(self.pid)

        def create_time(self) -> float:
            return 0.0

        def is_running(self) -> bool:
            if sys.platform.startswith("linux"):
                return Path(f"/proc/{self.pid}").exists()
            return False

        def oneshot(self):
            import contextlib
            return contextlib.nullcontext()

        def cpu_times(self):
            return SimpleNamespace(user=0.0, system=0.0)

        def memory_info(self):
            return SimpleNamespace(rss=0)

    mod.Process = Process
    mod.process_iter = lambda attrs=None, ad_value=None: iter([])
    mod.net_connections = lambda kind="tcp": []
    return mod


def ensure_runtime_compat() -> dict[str, bool]:
    """Ensure psutil, headless PySide6 stubs (if missing), and safe fsync are active."""
    status = {"native_psutil": False, "native_pyside6": False, "fsync_wrapped": False}
    try:
        import psutil  # noqa: F401
        status["native_psutil"] = getattr(psutil, "__version__", "") != "7.2.2-compat"
    except ImportError:
        sys.modules["psutil"] = build_psutil_fallback()

    try:
        import PySide6  # noqa: F401
        status["native_pyside6"] = True
    except ImportError:
        for mod_name in ("PySide6", "PySide6.QtCore", "PySide6.QtGui", "PySide6.QtWidgets"):
            if mod_name not in sys.modules:
                stub = types.ModuleType(mod_name)
                for attr in (
                    "QThread", "Signal", "QUrl", "QTimer", "Qt", "QSize",
                    "QApplication", "QMainWindow", "QWidget", "QVBoxLayout",
                    "QHBoxLayout", "QGridLayout", "QLabel", "QPushButton",
                    "QComboBox", "QCheckBox", "QLineEdit", "QTableWidget",
                    "QTableWidgetItem", "QHeaderView", "QDialog", "QFileDialog",
                    "QScrollArea", "QFrame", "QStackedWidget", "QProgressBar",
                    "QMessageBox", "QPlainTextEdit", "QSplitter", "QGroupBox",
                    "QRadioButton", "QButtonGroup", "QSpinBox", "QDoubleSpinBox",
                    "QTabWidget", "QToolButton", "QSizePolicy",
                    "QFont", "QColor", "QPalette", "QIcon", "QDesktopServices",
                    "QPainter", "QPixmap", "QAction",
                ):
                    setattr(stub, attr, type(attr, (), {"__init__": lambda self, *a, **kw: None}))
                sys.modules[mod_name] = stub

    if not getattr(os.fsync, "_cc_safe_wrapped", False):
        orig_fsync = os.fsync

        def _safe_fsync(fd: int) -> None:
            try:
                orig_fsync(fd)
            except OSError as exc:
                # Ignore EOPNOTSUPP (95) / EINVAL (22) / EBADF on virtual/FUSE sandboxes
                if exc.errno not in (95, 22, 45):
                    raise

        _safe_fsync._cc_safe_wrapped = True  # type: ignore[attr-defined]
        os.fsync = _safe_fsync
        status["fsync_wrapped"] = True

    return status
