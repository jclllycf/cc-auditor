"""Narrow local collectors. Never read cmdline, environ(), profiles or transcripts."""
from __future__ import annotations
import ctypes
import importlib.metadata
import ipaddress
import os
import queue
import shutil
import socket
import ssl
import struct
import sys
import threading
import time
from collections import Counter
from pathlib import Path
import psutil
from .model import evidence
from .tls_safety import verified_context

def host():
    return evidence("host", "审计器运行环境", "observed", {
        "os": sys.platform, "python": ".".join(map(str, sys.version_info[:3])),
        "architecture_bits": struct.calcsize("P") * 8, "logical_cpus": psutil.cpu_count(),
        "psutil": psutil.__version__, "ssl": ssl.OPENSSL_VERSION},
        "这些版本属于审计器；不代表 Claude 内置引擎或远程任务。")

def address_class(address):
    try:
        addr = ipaddress.ip_address(address.split("%")[0])
        if addr in ipaddress.ip_network("198.18.0.0/15") or addr in ipaddress.ip_network("2001:2::/48"):
            return "benchmark_or_proxy_mapping"
        if addr.is_loopback: return "loopback"
        if addr.is_link_local: return "link_local"
        if addr.is_private: return "private_or_reserved"
        if addr.is_global: return "public_unlocated"
        return "other_reserved"
    except ValueError:
        return "unclassified"

def classify(path, has_desktop_ancestor=False):
    p = path.lower().replace("/", "\\")
    if "\\claude-code\\" in p or "\\claude-code-runtime\\" in p:
        return "embedded_engine_candidate" if has_desktop_ancestor else "unattributed_engine"
    if "\\windowsapps\\" in p and ("claude" in p or "anthropic" in p):
        return "desktop_shell_candidate"
    if has_desktop_ancestor:
        return "desktop_child_candidate"
    if "\\.local\\bin\\" in p or "\\npm\\" in p or "\\.claude\\local\\" in p:
        return "standalone_cli_candidate"
    return "unattributed_claude"

def child_category(name):
    n = name.lower()
    if n in ("powershell.exe", "pwsh.exe", "cmd.exe", "bash.exe", "sh.exe", "conhost.exe"): return "shell"
    if n in ("node.exe", "node"): return "node_runtime"
    if n in ("python.exe", "python3.exe", "pythonw.exe"): return "python_runtime"
    if n in ("git.exe", "git"): return "git"
    return "other"

def process_snapshot(config, previous=None, elapsed_seconds=0):
    groups, children, connections = Counter(), Counter(), Counter()
    errors, transient, candidates, paths = [], {}, [], {}
    # Process names and parent IDs only. Do not use Process.attrs or as_dict() without an explicit allowlist.
    try:
        rows = list(psutil.process_iter(["name", "ppid"], ad_value=None))
    except (psutil.Error, OSError):
        return {"status": "error", "error": "process_query_failed"}, {}
    names = {p.pid: (p.info.get("name") or "").lower() for p in rows}
    parents = {p.pid: p.info.get("ppid") for p in rows}
    for p in rows:
        if names[p.pid] not in ("claude.exe", "claude"):
            continue
        candidates.append(p)
        try: paths[p.pid] = p.exe()
        except (psutil.Error, OSError): paths[p.pid] = ""; errors.append("candidate_path_unavailable")
    desktop = {pid for pid, path in paths.items() if classify(path) == "desktop_shell_candidate"}
    def ancestor_in(pid, ids):
        seen = set()
        for _ in range(12):
            parent = parents.get(pid)
            if parent in ids: return True
            if parent is None or parent in seen: return False
            seen.add(parent); pid = parent
        return False
    target = []
    for p in candidates:
        category = classify(paths[p.pid], ancestor_in(p.pid, desktop))
        groups[category] += 1
        if config.surface == "desktop" and category in ("desktop_shell_candidate", "embedded_engine_candidate", "desktop_child_candidate"):
            target.append(p)
        if config.surface == "cli" and category == "standalone_cli_candidate":
            target.append(p)
    target_ids = {p.pid for p in target}
    rss, valid_resources, conn_total, conn_success = 0, 0, 0, 0
    for p in rows:
        if p.pid not in target_ids and ancestor_in(p.pid, target_ids):
            children[child_category(names[p.pid])] += 1
    for p in target:
        try:
            with p.oneshot():
                created = p.create_time(); times = p.cpu_times(); memory = p.memory_info()
            transient[(p.pid, created)] = times.user + times.system
            rss += memory.rss; valid_resources += 1
        except (psutil.Error, OSError):
            errors.append("resource_unavailable")
    if "connections" in config.capabilities and target:
        try:
            # Windows exposes a system TCP table; query once and immediately filter by target PID.
            # Unrelated rows and raw addresses remain transient and are never serialized.
            for conn in psutil.net_connections(kind="tcp"):
                if conn.pid in target_ids and conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    connections[address_class(conn.raddr.ip)] += 1; conn_total += 1
            conn_success = 1
        except (psutil.Error, OSError): errors.append("connections_unavailable")
    cpu = None
    matched = 0
    if previous is not None and elapsed_seconds > 0:
        matched = len(transient.keys() & previous.keys())
        delta = sum(max(0, value - previous[k]) for k, value in transient.items() if k in previous)
        # No matching persistent process is not an observed zero CPU value.
        if matched or (not target and not previous):
            cpu = round(delta / elapsed_seconds / (psutil.cpu_count() or 1) * 100, 3)
    payload = {"status": "partial" if errors else "observed", "candidate_count": len(candidates),
               "target_count": len(target), "groups": dict(groups), "children": dict(children),
               "rss_mb": round(rss / 1048576, 2) if valid_resources or not target else None,
               "cpu_capacity_percent": cpu, "cpu_matched_processes": matched,
               "resource_processes": valid_resources,
               "established_count": conn_total if "connections" in config.capabilities and (conn_success or not target) else None,
               "connection_classes": dict(connections), "errors": sorted(set(errors)),
               "unattributed_count": sum(v for k, v in groups.items() if k.startswith("unattributed"))}
    return payload, transient

def file_version(path):
    if sys.platform != "win32": return None
    try:
        api = ctypes.WinDLL("version", use_last_error=True)
        api.GetFileVersionInfoSizeW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p]
        api.GetFileVersionInfoSizeW.restype = ctypes.c_uint32
        length = api.GetFileVersionInfoSizeW(str(path), None)
        if not 0 < length < 4 * 1024 * 1024: return None
        buf = ctypes.create_string_buffer(length)
        api.GetFileVersionInfoW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        if not api.GetFileVersionInfoW(str(path), 0, length, buf): return None
        pointer = ctypes.c_void_p(); size = ctypes.c_uint()
        api.VerQueryValueW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint)]
        if not api.VerQueryValueW(buf, "\\", ctypes.byref(pointer), ctypes.byref(size)) or size.value < 52: return None
        info = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32 * 13)).contents
        if info[0] != 0xFEEF04BD: return None
        return ".".join(str(x) for x in (info[2] >> 16, info[2] & 65535, info[3] >> 16, info[3] & 65535))
    except (OSError, ValueError): return None

def installation():
    found = shutil.which("claude.exe") or shutil.which("claude.cmd") or shutil.which("claude")
    if not found:
        candidate = Path.home() / ".local/bin/claude.exe"
        if candidate.is_file(): found = str(candidate)
    value = {"cli_located": bool(found), "binary_file_version": file_version(found) if found else None,
             "shells": {x: bool(shutil.which(x)) for x in ("powershell.exe", "pwsh.exe", "bash.exe", "git.exe")},
             "executed_cli": False}
    return evidence("installation", "CLI 安装与终端", "observed", value,
                    "检查 PATH 与已知本地安装位置，没有执行 claude --version。文件版本可能不同于产品语义版本。", "data",
                    limitations=["未发现不等于未安装：自定义、WSL、远端或 Node 包装入口可能不在此范围。", "不会读取 Claude 配置、MCP 定义、Hooks 或会话文件。"])

def api_environment():
    try: sdk = importlib.metadata.version("anthropic")
    except importlib.metadata.PackageNotFoundError: sdk = None
    # Presence tests only. Never copy or serialize a variable's value.
    presence = {key: key in os.environ for key in ("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "CLAUDE_CODE_ENABLE_TELEMETRY", "OTEL_EXPORTER_OTLP_ENDPOINT")}
    return evidence("api_environment", "调用环境指示", "observed", {"sdk_in_auditor_runtime": sdk, "variable_presence": presence, "sdk_initialized": False},
                    "只检查审计器继承环境中的变量名是否存在；不读取值、不导入 SDK 客户端。", "api",
                    limitations=["此进程的环境不能代表既有 CLI 进程或用户应用的环境。", "便携版的 Python 运行时与其他 API 应用分离。", "Hook/MCP 配置及真实认证状态未检查。"])

def tls_connectivity(cancel):
    """Public preflight: legacy active probe disabled."""
    raise PermissionError("legacy_active_probe_disabled_in_public_preflight")
