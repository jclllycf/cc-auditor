"""Host Identity & Vantage Point Verifier (Layer S07 / C12).

Prevents a cloud agent sandbox, WSL container, or remote SSH host from being
mistakenly reported as the user's physical local Windows computer.
"""
from __future__ import annotations

import hashlib
import os
import platform
from pathlib import Path
import socket
import struct
import sys
import uuid
from typing import Any

from .zero_contact_guard import utc_now

_SESSION_SALT = uuid.uuid4().hex


def inspect_host_identity(
    *,
    requested_target_host: str = "user_local_windows",
    mock_windows_host: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Identify the actual execution host and determine whether it matches the user's local Windows PC.

    Never exports raw machine serial numbers, MAC addresses, or personal usernames.
    """
    if mock_windows_host is not None:
        return {
            "captured_at_utc": utc_now(),
            "requested_target_host": requested_target_host,
            "vantage_point": "synthetic_windows_fixture",
            "is_user_local_windows": False,
            "synthetic": True,
            "os_platform": "win32",
            "os_family": "Windows",
            "windows_major": mock_windows_host.get("major", 10),
            "windows_build": mock_windows_host.get("build", 26200),
            "windows_edition_label": "Windows 11" if mock_windows_host.get("build", 26200) >= 22000 else "Windows 10",
            "architecture": mock_windows_host.get("arch", "x64"),
            "python_version": ".".join(map(str, sys.version_info[:3])),
            "ephemeral_host_id": "fixture_" + hashlib.sha256(b"synthetic_windows_fixture").hexdigest()[:12],
            "container_or_remote_indicators": ["synthetic_fixture_injected"],
            "vantage_warning": "当前使用合成测试夹具（Synthetic Fixture）模拟 Windows 环境，仅用于验证代码逻辑，不代表真实物理机实测结果。",
        }

    sys_plat = sys.platform
    machine = (os.environ.get("PROCESSOR_ARCHITEW6432") or platform.machine() or "").lower()
    arch = {
        "amd64": "x64",
        "x86_64": "x64",
        "arm64": "arm64",
        "aarch64": "arm64",
        "x86": "x86",
        "i386": "x86",
        "i686": "x86",
    }.get(machine, f"{struct.calcsize('P') * 8}bit")

    indicators: list[str] = []
    if Path("/.dockerenv").exists() or Path("/run/.containerenv").exists():
        indicators.append("container_marker_file")
    if Path("/working_dir").exists():
        indicators.append("cloud_sandbox_working_dir")
    if any(k in os.environ for k in ("WSL_DISTRO_NAME", "WSL_INTEROP")):
        indicators.append("wsl_environment_vars")
    if any(k in os.environ for k in ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY")):
        indicators.append("ssh_remote_session_vars")
    if any(k in os.environ for k in ("KUBERNETES_SERVICE_HOST", "CLOUD_RUN_JOB", "CODESPACES", "GITPOD_WORKSPACE_ID")):
        indicators.append("cloud_hosted_runtime_vars")

    win_major = 0
    win_build = 0
    win_label = "Non-Windows"
    if sys_plat == "win32":
        try:
            ver = sys.getwindowsversion()  # type: ignore[attr-defined]
            win_major = int(ver.major)
            win_build = int(ver.build)
            win_label = "Windows 11" if (win_major == 10 and win_build >= 22000) else ("Windows 10" if win_major == 10 else f"Windows NT {win_major}")
        except Exception:
            win_label = "Windows (version unknown)"

    if sys_plat == "win32" and "ssh_remote_session_vars" not in indicators and "cloud_hosted_runtime_vars" not in indicators:
        vantage_point = "local_windows_physical_or_vm"
        is_local_win = True
        warning = None
    elif "wsl_environment_vars" in indicators:
        vantage_point = "wsl_environment"
        is_local_win = False
        warning = "当前运行在 WSL (Windows Subsystem for Linux) 子系统中；网络栈、进程树与浏览器注册表与宿主 Windows 存在差异，建议在宿主 Windows 原生 Python 中运行完整本地预检。"
    elif "ssh_remote_session_vars" in indicators:
        vantage_point = "ssh_remote_session"
        is_local_win = False
        warning = "当前运行在 SSH 远端会话中；检测结果仅反映该 SSH 远端主机，不代表您本地桌面端或浏览器的网络出口。"
    else:
        vantage_point = "cloud_or_container_sandbox"
        is_local_win = False
        warning = (
            "当前运行在云端/Linux 容器沙箱环境中，并非您的本地 Windows 电脑！"
            "云端的 IP、时区、路由与浏览器绝不能代表您的真实本地环境。"
            "请将本工具包下载到您的本地 Windows 电脑并由本地非 Claude Agent 或本地脚本执行实机验收。"
        )

    try:
        raw_node = socket.gethostname()
    except Exception:
        raw_node = "unknown"
    ephemeral_id = "host_" + hashlib.sha256((_SESSION_SALT + ":" + raw_node).encode("utf-8")).hexdigest()[:12]

    return {
        "captured_at_utc": utc_now(),
        "requested_target_host": requested_target_host,
        "vantage_point": vantage_point,
        "is_user_local_windows": is_local_win,
        "synthetic": False,
        "os_platform": sys_plat,
        "os_family": "Windows" if sys_plat == "win32" else platform.system(),
        "windows_major": win_major,
        "windows_build": win_build,
        "windows_edition_label": win_label,
        "architecture": arch,
        "python_version": ".".join(map(str, sys.version_info[:3])),
        "ephemeral_host_id": ephemeral_id,
        "container_or_remote_indicators": indicators,
        "vantage_warning": warning,
    }
