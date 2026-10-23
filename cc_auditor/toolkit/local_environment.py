"""Local OS Environment & Network Topology Collectors (Layers N04, N05, S07).

Reuses and extends CC Auditor v1.4 local read-only probes (`preflight.py`, `environment_probes.py`, `diagnostics.py`)
without requiring Qt (`PySide6`) or making any outbound network connections.
"""
from __future__ import annotations

from cc_auditor.toolkit.psutil_compat import ensure_runtime_compat
ensure_runtime_compat()

import ipaddress
import os
import sys
from typing import Any

from .psutil_compat import ensure_runtime_compat
from .host_identity import inspect_host_identity
from .zero_contact_guard import utc_now

ensure_runtime_compat()
from .. import preflight, environment_probes as probes, diagnostics  # noqa: E402


def inspect_local_environment(
    *,
    mock_facts: dict[str, Any] | None = None,
    mock_preferences: dict[str, Any] | None = None,
    mock_inventory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Collect read-only local OS, hardware, clock, certificate, environment variable, and language/timezone facts.

    Language, locale, IME, and timezone values are explicitly marked `reference_only=True` and never penalize scores.
    """
    synthetic = any(x is not None for x in (mock_facts, mock_preferences, mock_inventory))
    host_id = inspect_host_identity(
        mock_windows_host=mock_facts.get("os") if isinstance(mock_facts, dict) and "os" in mock_facts else None
    )

    if mock_facts is not None:
        base_facts = dict(mock_facts)
    else:
        base_facts = preflight.collect()

    if mock_preferences is not None:
        prefs = dict(mock_preferences)
    else:
        prefs = probes.local_preferences()

    if mock_inventory is not None:
        inv = dict(mock_inventory)
    else:
        inv = diagnostics.inventory()

    os_info = base_facts.get("os", {})
    mem_info = base_facts.get("memory", {})
    disk_info = base_facts.get("disk", {})
    hosts_info = base_facts.get("hosts", {})
    tools_info = base_facts.get("tools", {})
    env_flags = base_facts.get("environment", {})
    insecure_tls = bool(base_facts.get("insecure_tls"))

    custom_ca_vars = [
        k for k in ("SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS")
        if env_flags.get(k)
    ]

    # Evaluate Windows compatibility without penalizing non-Windows cloud hosts when not using a fixture
    win_known = os_info.get("status") == "observed"
    win_major = int(os_info.get("major", 0))
    win_build = int(os_info.get("build", 0))
    win_arch = str(os_info.get("arch", "other"))

    desktop_os_ok = win_known and win_major >= 10
    cli_os_ok = win_known and win_major >= 10 and win_build >= 17763 and win_arch in ("x64", "arm64")
    ram_ok = mem_info.get("status") == "observed" and float(mem_info.get("ram_gb", 0)) >= 4.0
    disk_ok = disk_info.get("status") == "observed" and float(disk_info.get("system_free_gb", 0)) >= 1.0
    shell_ok = any(bool(tools_info.get(k)) for k in ("powershell", "pwsh", "cmd"))

    return {
        "captured_at_utc": utc_now(),
        "synthetic": synthetic,
        "vantage": host_id,
        "os_compatibility": {
            "status": os_info.get("status", "unknown"),
            "windows_major": win_major,
            "windows_build": win_build,
            "architecture": win_arch,
            "desktop_compatible": desktop_os_ok if win_known else None,
            "cli_compatible": cli_os_ok if win_known else None,
        },
        "resources": {
            "memory_status": mem_info.get("status", "unknown"),
            "ram_gb": mem_info.get("ram_gb", 0),
            "cli_ram_sufficient": ram_ok if mem_info.get("status") == "observed" else None,
            "disk_status": disk_info.get("status", "unknown"),
            "system_free_gb": disk_info.get("system_free_gb", 0),
            "disk_sufficient": disk_ok if disk_info.get("status") == "observed" else None,
        },
        "security_and_certificates": {
            "running_as_admin": bool(prefs.get("admin", False)),
            "root_cert_count": prefs.get("root_cert_count"),
            "insecure_tls_env_enabled": insecure_tls,
            "custom_ca_env_vars_present": custom_ca_vars,
            "api_endpoint_override_present": bool(prefs.get("api_endpoint_override") or env_flags.get("ANTHROPIC_BASE_URL")),
            "hosts_file": {
                "status": hosts_info.get("status", "unknown"),
                "service_entries": int(hosts_info.get("service_entries", 0)),
                "blocking_entries": int(hosts_info.get("blocking_entries", 0)),
            },
        },
        "cli_and_processes": {
            "shells": tools_info,
            "shell_ready": shell_ok,
            "claude_on_path": bool(tools_info.get("claude_on_path")),
            "cli_binary_version": inv.get("cli_version"),
            "running_claude_instances_count": len(inv.get("instances", [])),
            "running_claude_instances": inv.get("instances", []),
            "inventory_status": inv.get("status", "unknown"),
            "note": "未安装 Claude 在使用前预检中属于完全正常状态；若已存在后台同名进程，仅作只读计数，本工具不会启动或关闭它们。",
        },
        "locale_and_time_reference": {
            "reference_only": True,
            "scoring_impact": 0,
            "language_status": prefs.get("language_status", "error"),
            "ui_languages": prefs.get("ui_languages", []),
            "format_language": prefs.get("format_language", ""),
            "input_languages_ime": prefs.get("input_languages", []),
            "timezone_status": prefs.get("timezone_status", "error"),
            "timezone": prefs.get("timezone", ""),
            "utc_offset": prefs.get("utc_offset", ""),
            "clock_local": prefs.get("clock_local", ""),
            "explanation": "语言（如 zh-CN）、输入法与时区（如 UTC+8）属于用户正常系统偏好，绝不作为地区违规或封号风险扣分依据。",
        },
    }


FAKE_IPV4_NETWORKS = (
    ipaddress.ip_network("198.18.0.0/15"),
)
FAKE_IPV6_NETWORKS = (
    ipaddress.ip_network("2001:2::/48"),
    ipaddress.ip_network("fdfe:dcba:9876::/48"),
    ipaddress.ip_network("fc00::/18"),
)
WINDOWS_SITE_LOCAL_PLACEHOLDER = ipaddress.ip_network("fec0:0:0:ffff::/64")


def classify_dns_servers_v21(dns_servers: list[str]) -> dict[str, Any]:
    """Classify adapter DNS servers accurately without mislabeling Windows fec0:: placeholders or Mihomo ULA Fake-IP."""
    fake_ip_dns: list[str] = []
    public_dns: list[str] = []
    private_or_ula_dns: list[str] = []
    windows_placeholder_dns: list[str] = []

    for srv in dns_servers:
        try:
            clean_srv = str(srv).split("%")[0].strip()
            addr = ipaddress.ip_address(clean_srv)
        except ValueError:
            continue

        if isinstance(addr, ipaddress.IPv4Address):
            if any(addr in net for net in FAKE_IPV4_NETWORKS):
                fake_ip_dns.append(srv)
            elif addr.is_global:
                public_dns.append(srv)
            else:
                private_or_ula_dns.append(srv)
        else:
            if any(addr in net for net in FAKE_IPV6_NETWORKS):
                fake_ip_dns.append(srv)
            elif addr in WINDOWS_SITE_LOCAL_PLACEHOLDER or addr.is_site_local:
                windows_placeholder_dns.append(srv)
            elif addr.is_global:
                public_dns.append(srv)
            else:
                private_or_ula_dns.append(srv)

    smhnr_parallel_leak_risk = bool(fake_ip_dns and public_dns)

    return {
        "fake_ip_dns_servers": fake_ip_dns,
        "public_dns_servers": public_dns,
        "private_or_local_dns_servers": private_or_ula_dns,
        "windows_site_local_placeholder_dns": windows_placeholder_dns,
        "fake_ip_v4_count": sum(1 for s in fake_ip_dns if "." in s),
        "fake_ip_v6_count": sum(1 for s in fake_ip_dns if ":" in s),
        "windows_placeholder_v6_count": len(windows_placeholder_dns),
        "public_ip_count": len(public_dns),
        "smhnr_parallel_dns_leak_risk": smhnr_parallel_leak_risk,
        "smhnr_warning_zh": (
            f"检测到网卡同时配置了 TUN Fake-IP DNS ({', '.join(fake_ip_dns)}) 与公网 DNS ({', '.join(public_dns)})。"
            "在 Windows 多宿主解析 (SMHNR) 机制下，若核心未配置 `dns-hijack: [any:53]` 且未阻断非隧道 53 端口，"
            "系统进程发送的 UDP 查询可能并行泄漏至公网 DNS，需要通过权威 DNS 接收端实证核验。"
            if smhnr_parallel_leak_risk else None
        ),
    }


def inspect_network_topology(
    *,
    mock_preferences: dict[str, Any] | None = None,
    mock_local_network: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Inspect local proxy settings (WinINET, PAC, WPAD, Env), active VPN/TUN interfaces, default routes, and local DNS."""
    synthetic = mock_preferences is not None or mock_local_network is not None
    host_id = inspect_host_identity(
        mock_windows_host={"major": 10, "build": 26200, "arch": "x64"} if synthetic else None
    )

    prefs = dict(mock_preferences) if mock_preferences is not None else probes.local_preferences()
    if mock_local_network is not None:
        net = dict(mock_local_network)
    elif sys.platform == "win32":
        try:
            net = probes.windows_network()
        except Exception:
            net = {"adapters": [], "routes": [], "dns": []}
    else:
        net = {"adapters": [], "routes": [], "dns": []}

    tunnels = net.get("tunnels", [])
    active_tunnels = [t for t in tunnels if t.get("active")]
    v4_tun_owners = [t["family"] for t in active_tunnels if t.get("default_v4")]
    v6_tun_owners = [t["family"] for t in active_tunnels if t.get("default_v6")]

    dns_servers = net.get("dns_servers", [])
    dns_classified = classify_dns_servers_v21(dns_servers)

    # Detect potential split-routing or orphan TUN anomalies
    anomalies: list[dict[str, str]] = []
    if dns_classified["smhnr_parallel_dns_leak_risk"]:
        anomalies.append({
            "id": "windows_smhnr_parallel_dns_leak_risk",
            "severity": "medium",
            "description": dns_classified["smhnr_warning_zh"] or "网卡同时配置了 TUN Fake-IP DNS 与公网 DNS，存在 SMHNR 并行查询泄露风险。",
        })
    if active_tunnels and not (v4_tun_owners or v6_tun_owners):
        anomalies.append({
            "id": "tun_active_without_default_route",
            "severity": "medium",
            "description": f"检测到活动虚拟隧道网卡（{', '.join(t['family'] for t in active_tunnels)}），但未持有默认路由（0.0.0.0/0 或 /1），可能导致部分进程直连绕过隧道。",
        })
    if v4_tun_owners and net.get("ipv6_default") and not v6_tun_owners:
        anomalies.append({
            "id": "tun_ipv4_only_with_ipv6_default",
            "severity": "medium",
            "description": "TUN 隧道仅接管了 IPv4 默认路由，但系统存在非隧道的 IPv6 默认路由（::/0），支持 IPv6 的浏览器或客户端可能发生 IPv6 旁路直连泄漏。",
        })
    if prefs.get("system_proxy_enabled") and not prefs.get("system_proxy"):
        anomalies.append({
            "id": "system_proxy_enabled_empty_server",
            "severity": "medium",
            "description": "Windows 系统代理开关处于开启状态，但代理服务器地址为空或格式无效。",
        })
    for k, val in (prefs.get("environment_proxies") or {}).items():
        if "不支持" in str(val):
            anomalies.append({
                "id": f"invalid_env_proxy_{k.lower()}",
                "severity": "medium",
                "description": f"环境变量 {k} 已设置但地址格式不受支持。",
            })

    return {
        "captured_at_utc": utc_now(),
        "synthetic": synthetic,
        "vantage": host_id,
        "status": net.get("status", "error"),
        "query_flags": {
            "adapters_ok": bool(net.get("adapters_ok")),
            "routes_ok": bool(net.get("routes_ok")),
            "dns_ok": bool(net.get("dns_ok")),
            "vpn_ok": bool(net.get("vpn_ok")),
            "proxy_registry_ok": prefs.get("proxy_status") == "ok",
        },
        "proxy_configuration": {
            "system_proxy_enabled": bool(prefs.get("system_proxy_enabled")),
            "system_proxy_sanitized": prefs.get("system_proxy", ""),
            "pac_configured": bool(prefs.get("pac_configured")),
            "wpad_auto_detect": prefs.get("auto_detect"),
            "environment_proxies_sanitized": prefs.get("environment_proxies", {}),
            "note": "代理地址已剥离任何用户名、密码与查询参数；系统静态代理关闭不代表 TUN 虚拟网卡未工作。",
        },
        "vpn_and_tun_topology": {
            "windows_vpn_connected_count": int(net.get("vpn_connected", 0)),
            "active_adapter_count": int(net.get("active_adapter_count", 0)),
            "detected_tunnels": tunnels,
            "active_tunnel_families": sorted({t["family"] for t in active_tunnels}),
            "tun_owns_ipv4_default_route": bool(v4_tun_owners),
            "tun_owns_ipv6_default_route": bool(v6_tun_owners),
            "system_has_ipv4_default_route": bool(net.get("ipv4_default")),
            "system_has_ipv6_default_route": bool(net.get("ipv6_default")),
        },
        "dns_configuration": {
            "active_adapter_dns_servers": dns_servers,
            "fake_ip_dns_servers": dns_classified["fake_ip_dns_servers"],
            "public_dns_servers": dns_classified["public_dns_servers"],
            "private_or_local_dns_servers": dns_classified["private_or_local_dns_servers"],
            "windows_site_local_placeholder_dns": dns_classified["windows_site_local_placeholder_dns"],
            "smhnr_parallel_dns_leak_risk": dns_classified["smhnr_parallel_dns_leak_risk"],
            "recursive_egress_leak_tested": False,
            "dns_leak_boundary_note": "本机 DNS 列表仅反映网卡配置；未部署受控权威 DNS 接收端前，不能仅凭本机配置宣称‘无 DNS 泄漏’。",
        },
        "topology_anomalies": anomalies,
    }
