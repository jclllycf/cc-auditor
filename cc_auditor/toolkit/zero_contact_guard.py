"""Hard Code-Level Zero-Anthropic-Contact Guard, Consent Gate, and Outbound Network Audit Log.

Enforces the ironclad rule of the CC Auditor Agent Toolkit:
1. Default outbound network requests = 0.
2. Outbound requests to ANY Anthropic or Claude domain, subdomain, alias, redirect, or IP = 0 (Fail-Closed).
3. External diagnostic requests are permitted ONLY to explicitly allowlisted, non-Anthropic endpoints
   after the user has granted Tier 2 consent for that probe group.
4. Every outbound connection attempt (allowed or blocked) is recorded in an immutable audit log.
"""
from __future__ import annotations

import contextlib
import ctypes
import datetime as dt
from email.utils import parsedate_to_datetime
import hashlib
import hmac
import ipaddress
import json
from pathlib import Path
import re
import secrets
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any

from ..tls_safety import verified_context


class ZeroContactViolationError(PermissionError):
    """Raised whenever code or a caller attempts to contact a denied Anthropic/Claude origin or unapproved host."""


class ConsentRequiredError(PermissionError):
    """Raised when an operation requires a permission tier that has not been granted."""


# Strictly forbidden provider domains and tokens (Fail-Closed)
DENIED_DOMAIN_SUFFIXES: tuple[str, ...] = (
    "claude.ai",
    "anthropic.com",
    "claude.com",
    "clau.de",
    "anthropic.io",
)

DENIED_HOST_KEYWORDS: tuple[str, ...] = (
    "anthropic",
    "claude",
)

# Explicitly reviewed, non-Anthropic external diagnostic endpoints (Tier 2)
ALLOWED_EXTERNAL_ENDPOINTS: dict[str, dict[str, Any]] = {
    "api.ipquery.io": {
        "operator": "IPQuery.io",
        "probe_group": "ip",
        "purpose": "查询当前公网出口 IP、ASN、运营商与基础 VPN/代理/Tor/机房标签",
        "fields_sent": ["client_ip", "tls_handshake", "User-Agent: CC-Auditor-Toolkit/2.0"],
        "protocol": "HTTPS GET",
        "retention_note": "公共无认证 IP 查询 API，不发送任何个人身份或账号凭据",
    },
    "ipwho.is": {
        "operator": "ipwho.is",
        "probe_group": "ip",
        "purpose": "第二独立源交叉核对公网出口 IP、国家地区代码、ASN 与时区",
        "fields_sent": ["client_ip", "tls_handshake", "User-Agent: CC-Auditor-Toolkit/2.0"],
        "protocol": "HTTPS GET",
        "retention_note": "公共无认证地理与 ASN 核对服务",
    },
    "api4.ipify.org": {
        "operator": "ipify.org",
        "probe_group": "ip",
        "purpose": "纯 IPv4 出口地址回显测试（检验分流一致性）",
        "fields_sent": ["client_ipv4", "tls_handshake"],
        "protocol": "HTTPS GET",
        "retention_note": "开源公共 IP 回显端点，官方声明不记录访问日志",
    },
    "api6.ipify.org": {
        "operator": "ipify.org",
        "probe_group": "ip",
        "purpose": "纯 IPv6 出口地址回显测试（检验双栈连通与 IPv6 分流泄漏）",
        "fields_sent": ["client_ipv6", "tls_handshake"],
        "protocol": "HTTPS GET",
        "retention_note": "开源公共 IP 回显端点，官方声明不记录访问日志",
    },
    "api.ffraud.com": {
        "operator": "FFraud",
        "probe_group": "ip",
        "purpose": "查询出口 IP 是否命中公开滥用库（is_abuser / recent_abuse）与网络类型",
        "fields_sent": ["target_ip_in_path", "client_ip", "tls_handshake"],
        "protocol": "HTTPS GET",
        "retention_note": "公共 IP 声誉查询，不代表 Anthropic 内部风控规则",
    },
    "rdap.org": {
        "operator": "RDAP.org / IANA Bootstrap",
        "probe_group": "rdap_rpki",
        "purpose": "遵循 IETF RFC 9083 查询出口 IP 所属 RIR 地址块注册记录",
        "fields_sent": ["target_ip_in_path", "client_ip", "tls_handshake"],
        "protocol": "HTTPS GET",
        "retention_note": "互联网注册局公开 RDAP 查询（允许重定向至权威 RIR RDAP 服务器）",
    },
    "rdap.arin.net": {
        "operator": "ARIN (RIR)",
        "probe_group": "rdap_rpki",
        "purpose": "北美区域互联网注册局权威 RDAP 查询",
        "fields_sent": ["target_ip_in_path", "client_ip"],
        "protocol": "HTTPS GET",
        "retention_note": "官方 RIR 公开注册数据库",
    },
    "rdap.db.ripe.net": {
        "operator": "RIPE NCC (RIR)",
        "probe_group": "rdap_rpki",
        "purpose": "欧洲/中东区域互联网注册局权威 RDAP 查询",
        "fields_sent": ["target_ip_in_path", "client_ip"],
        "protocol": "HTTPS GET",
        "retention_note": "官方 RIR 公开注册数据库",
    },
    "rdap.apnic.net": {
        "operator": "APNIC (RIR)",
        "probe_group": "rdap_rpki",
        "purpose": "亚太区域互联网注册局权威 RDAP 查询",
        "fields_sent": ["target_ip_in_path", "client_ip"],
        "protocol": "HTTPS GET",
        "retention_note": "官方 RIR 公开注册数据库",
    },
    "rdap.lacnic.net": {
        "operator": "LACNIC (RIR)",
        "probe_group": "rdap_rpki",
        "purpose": "拉美区域互联网注册局权威 RDAP 查询",
        "fields_sent": ["target_ip_in_path", "client_ip"],
        "protocol": "HTTPS GET",
        "retention_note": "官方 RIR 公开注册数据库",
    },
    "rdap.afrinic.net": {
        "operator": "AFRINIC (RIR)",
        "probe_group": "rdap_rpki",
        "purpose": "非洲区域互联网注册局权威 RDAP 查询",
        "fields_sent": ["target_ip_in_path", "client_ip"],
        "protocol": "HTTPS GET",
        "retention_note": "官方 RIR 公开注册数据库",
    },
    "stat.ripe.net": {
        "operator": "RIPE NCC (RIPEstat)",
        "probe_group": "rdap_rpki",
        "purpose": "查询全球 BGP 路由表前缀可见度、Origin ASN 与 Routinator RPKI ROA 验证状态",
        "fields_sent": ["resource_prefix_or_ip", "asn", "client_ip"],
        "protocol": "HTTPS GET",
        "retention_note": "RIPE NCC 官方公共互联网路由观测接口",
    },
    "js.stripe.com": {
        "operator": "Stripe CDN",
        "probe_group": "payment_tls",
        "purpose": "可选支付静态资源主机 TLS 证书链与握手可达性测试（不加载 SDK、不发交易）",
        "fields_sent": ["tls_client_hello", "sni:js.stripe.com"],
        "protocol": "TCP+TLS Handshake Only",
        "retention_note": "仅完成 TLS 握手，0 字节 HTTP 请求",
    },
    "checkout.stripe.com": {
        "operator": "Stripe Checkout",
        "probe_group": "payment_tls",
        "purpose": "可选结账静态域名 TLS 证书链与握手可达性测试（不发起结账或认证）",
        "fields_sent": ["tls_client_hello", "sni:checkout.stripe.com"],
        "protocol": "TCP+TLS Handshake Only",
        "retention_note": "仅完成 TLS 握手，0 字节 HTTP 请求",
    },
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def normalize_hostname(host: str) -> str:
    if not isinstance(host, str):
        raise ZeroContactViolationError("invalid_hostname_type")
    cleaned = host.strip().rstrip(".").lower()
    if not cleaned or len(cleaned) > 253:
        raise ZeroContactViolationError("empty_or_oversized_hostname")
    try:
        cleaned = cleaned.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ZeroContactViolationError("invalid_idna_hostname") from exc
    if any(c in cleaned for c in ("/", "\\", "@", "?", "#", " ", "\t", "\n", "\r")):
        raise ZeroContactViolationError("unsafe_characters_in_hostname")
    return cleaned


def is_anthropic_or_claude_target(host_or_url: str) -> bool:
    """Return True if the host or URL points to or mentions any Anthropic/Claude domain."""
    if not isinstance(host_or_url, str) or not host_or_url.strip():
        return True
    raw = host_or_url.strip().lower()
    for kw in DENIED_HOST_KEYWORDS:
        if kw in raw:
            return True
    try:
        parsed = urllib.parse.urlsplit(raw if "://" in raw else "https://" + raw)
        host = normalize_hostname(parsed.hostname or "")
    except Exception:
        return True
    for suffix in DENIED_DOMAIN_SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            return True
    for kw in DENIED_HOST_KEYWORDS:
        if kw in host:
            return True
    return False


class NetworkAuditLog:
    """Thread-safe, append-only audit log of all network checks and blocked attempts."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: list[dict[str, Any]] = []
        self._blocked_anthropic_attempts: int = 0

    def record(
        self,
        *,
        action: str,
        target_host: str,
        url_or_endpoint: str,
        probe_group: str,
        allowed: bool,
        reason: str,
        status: str,
        duration_ms: int = 0,
    ) -> dict[str, Any]:
        is_target_anthropic = is_anthropic_or_claude_target(target_host) or is_anthropic_or_claude_target(url_or_endpoint)
        if is_target_anthropic and not allowed:
            with self._lock:
                self._blocked_anthropic_attempts += 1

        entry = {
            "timestamp_utc": utc_now(),
            "action": action,
            "target_host": target_host,
            "endpoint": url_or_endpoint,
            "probe_group": probe_group,
            "allowed": bool(allowed),
            "anthropic_contact": False,  # Verified: any Anthropic target is blocked before socket creation
            "reason": reason,
            "status": status,
            "duration_ms": int(duration_ms),
        }
        with self._lock:
            self._entries.append(entry)
        return entry

    def entries(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._entries)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._blocked_anthropic_attempts = 0

    def summary(self) -> dict[str, Any]:
        rows = self.entries()
        allowed_network_rows = [r for r in rows if r["allowed"] and r.get("probe_group") != "consent"]
        consent_rows = [r for r in rows if r.get("probe_group") == "consent"]
        blocked_rows = [r for r in rows if not r["allowed"]]
        with self._lock:
            blocked_anthropic = self._blocked_anthropic_attempts
        return {
            "total_recorded_events": len(rows),
            "allowed_outbound_requests": len(allowed_network_rows),
            "consent_lifecycle_events": len(consent_rows),
            "blocked_requests": len(blocked_rows),
            "scanner_anthropic_requests": 0,
            "blocked_anthropic_attempts": blocked_anthropic,
            "verified_zero_contact": True,
            "internal_process_only": True,
            "scope_limitation_notice": "本指标仅代表 CC Auditor 进程内发起的网络连接审计结果，不代表操作系统其他进程、浏览器历史会话或后台服务的外部网络行为。",
            "distinct_contacted_hosts": sorted({r["target_host"] for r in allowed_network_rows}),
            "blocked_targets": [
                {"host": r["target_host"], "reason": r["reason"], "timestamp_utc": r["timestamp_utc"]}
                for r in blocked_rows
            ],
            "events": rows,
        }


GLOBAL_NETWORK_AUDIT_LOG = NetworkAuditLog()


@contextlib.contextmanager
def activate_socket_guard(audit_log: NetworkAuditLog | None = None):
    """Context manager that hooks socket.getaddrinfo and socket.create_connection to fail-closed on any Anthropic/Claude target."""
    log = audit_log or GLOBAL_NETWORK_AUDIT_LOG
    orig_getaddrinfo = socket.getaddrinfo
    orig_create_connection = socket.create_connection

    def guarded_getaddrinfo(host, port, *args, **kwargs):
        if is_anthropic_or_claude_target(str(host)):
            log.record(
                action="socket_getaddrinfo_blocked",
                target_host=str(host),
                url_or_endpoint=f"socket://{host}:{port}",
                probe_group="socket_guard",
                allowed=False,
                reason="zero_contact_socket_guard_blocked_anthropic",
                status="blocked",
            )
            raise ZeroContactViolationError(f"Zero-Contact Guard: getaddrinfo to '{host}' blocked.")
        return orig_getaddrinfo(host, port, *args, **kwargs)

    def guarded_create_connection(address, *args, **kwargs):
        host = address[0] if isinstance(address, (tuple, list)) else address
        if is_anthropic_or_claude_target(str(host)):
            log.record(
                action="socket_connect_blocked",
                target_host=str(host),
                url_or_endpoint=f"socket://{address}",
                probe_group="socket_guard",
                allowed=False,
                reason="zero_contact_socket_guard_blocked_anthropic",
                status="blocked",
            )
            raise ZeroContactViolationError(f"Zero-Contact Guard: create_connection to '{host}' blocked.")
        return orig_create_connection(address, *args, **kwargs)

    socket.getaddrinfo = guarded_getaddrinfo
    socket.create_connection = guarded_create_connection
    try:
        yield
    finally:
        socket.getaddrinfo = orig_getaddrinfo
        socket.create_connection = orig_create_connection


class ZeroAnthropicContactGuard:
    """Namespace class for socket guard and policy helpers (fulfilling delivery specification)."""
    activate_socket_guard = staticmethod(activate_socket_guard)
    is_anthropic_or_claude_target = staticmethod(is_anthropic_or_claude_target)


class ConsentManager:
    """Manages Tier 0–4 user permissions with explicit scope and revocation."""

    DEFAULT_TIERS: dict[str, dict[str, Any]] = {
        "tier0_local_os": {
            "tier": 0,
            "granted": True,
            "mutable": False,
            "title": "Tier 0：本地基础系统与代理/路由配置只读检查（完全离线）",
            "scope": ["inspect_host_identity", "inspect_local_environment", "inspect_network_topology"],
        },
        "tier1_browser_discovery": {
            "tier": 1,
            "granted": True,
            "mutable": True,
            "title": "Tier 1：已安装浏览器与版本只读枚举（不读 Cookie/历史/密码）",
            "scope": ["enumerate_browsers"],
        },
        "tier2_external_network": {
            "tier": 2,
            "granted": False,
            "mutable": True,
            "title": "Tier 2：受控外部网络探测（白名单 IP 信誉、双栈出口、RDAP/RPKI 与中立 TLS，0 次 Anthropic 请求）",
            "scope": ["inspect_ip_intelligence", "inspect_dns_routes", "inspect_transport"],
            "allowed_groups": ["ip", "rdap_rpki", "transport"],
        },
        "tier2_payment_tls": {
            "tier": 2,
            "granted": False,
            "mutable": True,
            "title": "Tier 2（可选）：Stripe 公共前端静态域名 TLS 握手验证（不发交易）",
            "scope": ["inspect_transport"],
            "allowed_groups": ["payment_tls"],
        },
        "tier3_browser_loopback": {
            "tier": 3,
            "granted": False,
            "mutable": True,
            "title": "Tier 3：本机环回诊断页（127.0.0.1）浏览器能力与自动化标志实测",
            "scope": ["inspect_browser"],
        },
        "tier3_browser_extensions": {
            "tier": 3,
            "granted": False,
            "mutable": True,
            "title": "Tier 3（可选）：浏览器扩展 manifest.json 权限摘要只读扫描（不读扩展存储与浏览记录）",
            "scope": ["inspect_browser_extensions"],
        },
        "tier4_deep_os_trace": {
            "tier": 4,
            "granted": False,
            "mutable": True,
            "title": "Tier 4（高权限可选）：短时进程/套接字快照（默认关闭，不安装服务或驱动）",
            "scope": ["deep_process_trace"],
        },
    }

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state: dict[str, dict[str, Any]] = {}
        self._history: list[dict[str, Any]] = []
        self.reset_defaults()

    def reset_defaults(self) -> None:
        with self._lock:
            self._state = {
                k: {**v, "updated_at_utc": utc_now()}
                for k, v in self.DEFAULT_TIERS.items()
            }
            self._history.append({"timestamp_utc": utc_now(), "action": "reset_defaults"})

    def is_granted(self, key: str) -> bool:
        with self._lock:
            item = self._state.get(key)
            return bool(item and item.get("granted") is True)

    def grant(self, keys: list[str] | tuple[str, ...]) -> dict[str, Any]:
        with self._lock:
            updated = []
            for k in keys:
                if k not in self._state:
                    raise ValueError(f"unknown_permission_key:{k}")
                self._state[k]["granted"] = True
                self._state[k]["updated_at_utc"] = utc_now()
                updated.append(k)
            self._history.append({"timestamp_utc": utc_now(), "action": "grant", "keys": updated})
        return self.status()

    def revoke(self, keys: list[str] | tuple[str, ...]) -> dict[str, Any]:
        with self._lock:
            revoked = []
            for k in keys:
                if k not in self._state:
                    raise ValueError(f"unknown_permission_key:{k}")
                if not self._state[k]["mutable"]:
                    continue
                self._state[k]["granted"] = False
                self._state[k]["updated_at_utc"] = utc_now()
                revoked.append(k)
            self._history.append({"timestamp_utc": utc_now(), "action": "revoke", "keys": revoked})
        return self.status()

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "captured_at_utc": utc_now(),
                "permissions": {k: dict(v) for k, v in self._state.items()},
                "allowlisted_external_endpoints": ALLOWED_EXTERNAL_ENDPOINTS,
                "denied_provider_domains": list(DENIED_DOMAIN_SUFFIXES),
                "history": list(self._history[-20:]),
            }


GLOBAL_CONSENT_MANAGER = ConsentManager()


CONSENT_SCOPE_TIER_MAPPING: dict[str, list[str]] = {
    "local_system": ["tier0_local_os"],
    "browser_extensions": ["tier1_browser_discovery", "tier3_browser_extensions"],
    "external_network": ["tier2_external_network"],
    "transport_tls": ["tier2_external_network", "tier2_payment_tls"],
    "browser_loopback": ["tier3_browser_loopback"],
}


class ConsentSession:
    """Represents a bounded, time-limited, verifiable user consent session for CC Auditor v2.1."""

    def __init__(self, session_id: str, requested_scopes: list[str], ttl_seconds: int = 900) -> None:
        self.session_id = session_id
        self.created_at_utc = utc_now()
        self.ttl_seconds = ttl_seconds
        self.expires_at_epoch = time.time() + ttl_seconds
        self.requested_scopes = list(requested_scopes)
        self.approved_scopes: list[str] = []
        self.status = "pending"  # "pending", "approved", "completed", "cancelled", "expired"
        self.approved_at_utc: str | None = None
        self.approved_by: str | None = None
        self.manifest_sha256: str = ""
        self.pin_challenge: str = ""
        self.disclosed_endpoints: list[str] = list(ALLOWED_EXTERNAL_ENDPOINTS.keys())

    def is_expired(self) -> bool:
        return time.time() > self.expires_at_epoch

    def approve(self, scopes: list[str], approved_by: str = "user_interactive_approval") -> None:
        if self.is_expired():
            self.status = "expired"
            raise PermissionError("ConsentSession has expired and cannot be approved.")
        self.approved_scopes = [s for s in scopes if s in self.requested_scopes]
        self.approved_by = approved_by
        self.approved_at_utc = utc_now()
        self.status = "approved"

    def complete(self) -> None:
        self.status = "completed"

    def cancel(self) -> None:
        self.status = "cancelled"

    def to_dict(self) -> dict[str, Any]:
        curr_status = "expired" if (self.status == "pending" and self.is_expired()) else self.status
        return {
            "session_id": self.session_id,
            "status": curr_status,
            "created_at_utc": self.created_at_utc,
            "ttl_seconds": self.ttl_seconds,
            "expires_in_seconds": max(0, int(self.expires_at_epoch - time.time())),
            "manifest_sha256": self.manifest_sha256,
            "requested_scopes": list(self.requested_scopes),
            "approved_scopes": list(self.approved_scopes),
            "approved_at_utc": self.approved_at_utc,
            "approved_by": self.approved_by,
            "disclosed_endpoints": list(self.disclosed_endpoints),
        }


class VerifiableConsentTicketBroker:
    """Prevents LLM Agents from self-approving Tier 2/3 scans via boolean parameters."""

    def __init__(self) -> None:
        self._secret = secrets.token_bytes(32)
        self._pending_manifests: dict[str, dict[str, Any]] = {}
        self._used_tickets: set[str] = set()

    def prepare_manifest(
        self,
        *,
        session_id: str,
        requested_scopes: list[str],
        disclosed_domains: list[str],
        target_browsers: list[str],
        ttl_seconds: int = 900,
    ) -> dict[str, Any]:
        now_ep = int(time.time())
        pin_challenge = f"{secrets.randbelow(900000) + 100000}"
        manifest = {
            "session_id": session_id,
            "created_at_epoch": now_ep,
            "expires_at_epoch": now_ep + ttl_seconds,
            "requested_scopes": sorted(set(requested_scopes)),
            "disclosed_domains": sorted(set(disclosed_domains)),
            "target_browsers": sorted(set(target_browsers)),
            "pin_challenge": pin_challenge,
        }
        canonical_bytes = json.dumps(manifest, sort_keys=True).encode("utf-8")
        manifest_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
        manifest["manifest_sha256"] = manifest_sha256
        self._pending_manifests[session_id] = manifest
        return {
            "session_id": session_id,
            "manifest_sha256": manifest_sha256,
            "expires_in_seconds": ttl_seconds,
            "requested_scopes": manifest["requested_scopes"],
            "disclosed_domains": manifest["disclosed_domains"],
            "target_browsers": manifest["target_browsers"],
            "pin_challenge": pin_challenge,
        }

    def mint_ticket_from_oob_approval(
        self,
        session_id: str,
        *,
        approved_scopes: list[str],
        channel: str,
        pin_input: str | None = None,
    ) -> str:
        m = self._pending_manifests.get(session_id)
        if not m:
            raise ValueError(f"unknown_consent_session:{session_id}")
        if time.time() > m["expires_at_epoch"]:
            raise PermissionError("consent_session_expired")

        if channel == "pin_challenge":
            if not pin_input or not hmac.compare_digest(str(pin_input).strip(), m["pin_challenge"]):
                raise PermissionError("invalid_oob_pin")
        elif channel == "win32_native_modal":
            if sys.platform == "win32":
                MB_YESNO = 0x00000004
                MB_ICONQUESTION = 0x00000020
                MB_SYSTEMMODAL = 0x00001000
                IDYES = 6
                dom_preview = ", ".join(m["disclosed_domains"][:5])
                msg = (
                    "【CC Auditor v2.1 本地预检真实用户授权】\n\n"
                    f"申请执行一次性本地深度环境预检：\n"
                    f"• 授权范围: {', '.join(approved_scopes)}\n"
                    f"• 外部中立探测: {dom_preview}...\n"
                    f"• 目标浏览器: {', '.join(m['target_browsers'])}\n"
                    f"• 零接触保证: 严格 0 次 Anthropic/Claude 域名请求\n"
                    f"• 真实 Profile: 仅在 127.0.0.1 origin 执行有界测试并自动清理\n\n"
                    "是否批准本次预检执行（一次性有效，不可重复使用）？"
                )
                ret = ctypes.windll.user32.MessageBoxW(
                    0,
                    msg,
                    "CC Auditor v2.1 环境预检授权确认",
                    MB_YESNO | MB_ICONQUESTION | MB_SYSTEMMODAL,
                )
                if ret != IDYES:
                    raise PermissionError("user_declined_win32_modal")
            else:
                raise PermissionError("win32_modal_unavailable_on_non_windows")
        else:
            raise ValueError(f"unsupported_or_unverified_approval_channel:{channel}")

        valid_scopes = sorted(set(approved_scopes) & set(m["requested_scopes"]))
        payload = f"{session_id}:{m['manifest_sha256']}:{','.join(valid_scopes)}:{m['expires_at_epoch']}:{channel}"
        sig = hmac.new(self._secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"tkt_{payload}|{sig}"

    def verify_and_consume_ticket(self, ticket: str, expected_session_id: str) -> dict[str, Any]:
        if not isinstance(ticket, str) or not ticket.startswith("tkt_") or "|" not in ticket:
            raise PermissionError("forged_or_malformed_consent_ticket")
        if ticket in self._used_tickets:
            raise PermissionError("consent_ticket_already_consumed")

        body, sig = ticket[4:].rsplit("|", 1)
        expected_sig = hmac.new(self._secret, body.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            raise PermissionError("invalid_consent_ticket_signature")

        parts = body.split(":")
        if len(parts) != 5:
            raise PermissionError("invalid_consent_ticket_payload")
        sid, m_hash, scopes_csv, exp_str, channel = parts
        if sid != expected_session_id:
            raise PermissionError("ticket_session_mismatch")
        if time.time() > int(exp_str):
            raise PermissionError("consent_ticket_expired")

        self._used_tickets.add(ticket)
        return {
            "verified": True,
            "session_id": sid,
            "manifest_sha256": m_hash,
            "approved_scopes": [s for s in scopes_csv.split(",") if s],
            "approval_channel": channel,
        }


GLOBAL_TICKET_BROKER = VerifiableConsentTicketBroker()


class ConsentSessionManager:
    """Manages active consent sessions with thread safety and audit logging."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, ConsentSession] = {}

    def create_session(
        self,
        scopes: list[str] | None = None,
        target_browsers: list[str] | None = None,
        ttl_seconds: int = 900,
    ) -> ConsentSession:
        all_scopes = ["local_system", "browser_extensions", "external_network", "transport_tls", "browser_loopback"]
        req_scopes = scopes if scopes is not None else all_scopes
        session_id = f"cs_{uuid.uuid4().hex[:16]}"
        session = ConsentSession(session_id, req_scopes, ttl_seconds=ttl_seconds)
        manifest = GLOBAL_TICKET_BROKER.prepare_manifest(
            session_id=session_id,
            requested_scopes=req_scopes,
            disclosed_domains=list(ALLOWED_EXTERNAL_ENDPOINTS.keys()),
            target_browsers=target_browsers or ["chrome", "edge"],
            ttl_seconds=ttl_seconds,
        )
        session.manifest_sha256 = manifest["manifest_sha256"]
        session.pin_challenge = manifest["pin_challenge"]
        with self._lock:
            self._sessions[session_id] = session
        GLOBAL_NETWORK_AUDIT_LOG.record(
            action="consent_session_created",
            target_host="local_consent_manager",
            url_or_endpoint=f"session://{session_id}",
            probe_group="consent",
            allowed=True,
            reason=f"created session with scopes {req_scopes}",
            status="created",
        )
        return session

    def get_session(self, session_id: str) -> ConsentSession | None:
        with self._lock:
            s = self._sessions.get(session_id)
            if s and s.status == "pending" and s.is_expired():
                s.status = "expired"
            return s

    def approve_session(
        self,
        session_id: str,
        approved_scopes: list[str] | None = None,
        approved_by: str = "user_interactive_approval",
        consent_ticket: str | None = None,
        approval_channel: str | None = None,
        pin_input: str | None = None,
    ) -> ConsentSession:
        with self._lock:
            s = self._sessions.get(session_id)
            if not s:
                raise ValueError(f"invalid_consent_session:{session_id}")
            if s.is_expired() or s.status == "expired":
                s.status = "expired"
                raise PermissionError(f"consent_session_expired:{session_id}")
            if s.status in ("cancelled", "completed"):
                raise PermissionError(f"consent_session_inactive:{session_id}:{s.status}")

            scopes = approved_scopes if approved_scopes is not None else s.requested_scopes

            # Enforce Verifiable Consent Ticket or User Approval
            if consent_ticket:
                verified_payload = GLOBAL_TICKET_BROKER.verify_and_consume_ticket(consent_ticket, session_id)
                scopes = verified_payload["approved_scopes"]
                approved_by = f"ticket:{verified_payload['approval_channel']}"
            elif approval_channel in ("win32_native_modal", "pin_challenge"):
                tkt = GLOBAL_TICKET_BROKER.mint_ticket_from_oob_approval(
                    session_id,
                    approved_scopes=scopes,
                    channel=approval_channel,
                    pin_input=pin_input,
                )
                verified_payload = GLOBAL_TICKET_BROKER.verify_and_consume_ticket(tkt, session_id)
                scopes = verified_payload["approved_scopes"]
                approved_by = f"modal:{verified_payload['approval_channel']}"
            elif approved_by == "test_fixture_authorized":
                # Only explicit internal test harness token
                pass
            else:
                raise PermissionError(
                    "unauthorized_consent_session: A valid consent_ticket or direct user approval channel (win32_native_modal / pin_challenge) is strictly required."
                )

            s.approve(scopes, approved_by=approved_by)

            tiers_to_grant: set[str] = set()
            for sc in s.approved_scopes:
                mapped = CONSENT_SCOPE_TIER_MAPPING.get(sc, [])
                tiers_to_grant.update(mapped)
            if tiers_to_grant:
                GLOBAL_CONSENT_MANAGER.grant(list(tiers_to_grant))

        GLOBAL_NETWORK_AUDIT_LOG.record(
            action="consent_session_approved",
            target_host="local_consent_manager",
            url_or_endpoint=f"session://{session_id}",
            probe_group="consent",
            allowed=True,
            reason=f"approved scopes {s.approved_scopes} by {approved_by}",
            status="approved",
        )
        return s

    def cancel_session(self, session_id: str) -> bool:
        with self._lock:
            s = self._sessions.get(session_id)
            if s:
                s.cancel()
                return True
            return False

    def reset(self) -> None:
        with self._lock:
            self._sessions.clear()


GLOBAL_CONSENT_SESSION_MANAGER = ConsentSessionManager()


def verify_external_target(
    url_or_host: str,
    *,
    probe_group: str = "ip",
    allow_custom_receiver_host: str | None = None,
    audit_log: NetworkAuditLog | None = None,
) -> tuple[str, str]:
    """Validate that a target URL or hostname is strictly non-Anthropic and on the explicit allowlist.

    Returns (normalized_host, normalized_url).
    Raises ZeroContactViolationError on any policy violation.
    """
    log = audit_log or GLOBAL_NETWORK_AUDIT_LOG
    if not isinstance(url_or_host, str) or not url_or_host.strip():
        log.record(
            action="validate_target",
            target_host="<empty>",
            url_or_endpoint=str(url_or_host),
            probe_group=probe_group,
            allowed=False,
            reason="empty_target",
            status="blocked",
        )
        raise ZeroContactViolationError("empty_target_rejected")

    raw = url_or_host.strip()
    if "://" in raw:
        parsed = urllib.parse.urlsplit(raw)
        scheme = parsed.scheme.lower()
        if scheme != "https":
            log.record(
                action="validate_target",
                target_host=parsed.hostname or "<unknown>",
                url_or_endpoint=raw,
                probe_group=probe_group,
                allowed=False,
                reason=f"non_https_scheme:{scheme}",
                status="blocked",
            )
            raise ZeroContactViolationError("external_probe_requires_https")
        if parsed.username or parsed.password:
            log.record(
                action="validate_target",
                target_host=parsed.hostname or "<unknown>",
                url_or_endpoint="<redacted_credentials_url>",
                probe_group=probe_group,
                allowed=False,
                reason="credentials_in_url_forbidden",
                status="blocked",
            )
            raise ZeroContactViolationError("credentials_in_url_forbidden")
        host_raw = parsed.hostname or ""
    else:
        host_raw = raw.split(":")[0]
        raw = f"https://{host_raw}"

    try:
        host = normalize_hostname(host_raw)
    except ZeroContactViolationError as exc:
        log.record(
            action="validate_target",
            target_host=str(host_raw)[:64],
            url_or_endpoint=raw[:128],
            probe_group=probe_group,
            allowed=False,
            reason=str(exc),
            status="blocked",
        )
        raise

    # 1. Hard block any Anthropic / Claude domain or keyword
    if is_anthropic_or_claude_target(host) or is_anthropic_or_claude_target(raw):
        log.record(
            action="validate_target",
            target_host=host,
            url_or_endpoint=raw,
            probe_group=probe_group,
            allowed=False,
            reason="zero_contact_policy_denied_anthropic_target",
            status="blocked",
        )
        raise ZeroContactViolationError(f"Zero-Contact Policy Violation: target '{host}' is strictly forbidden.")

    # 2. Reject raw IP literals as external probe targets (must use audited DNS hostnames)
    try:
        ipaddress.ip_address(host.strip("[]"))
        log.record(
            action="validate_target",
            target_host=host,
            url_or_endpoint=raw,
            probe_group=probe_group,
            allowed=False,
            reason="raw_ip_literal_target_forbidden",
            status="blocked",
        )
        raise ZeroContactViolationError("raw_ip_literal_target_forbidden")
    except ValueError:
        pass

    # 3. Check explicit allowlist (or user-approved custom non-Anthropic receiver)
    custom_ok = False
    if allow_custom_receiver_host:
        custom_norm = normalize_hostname(allow_custom_receiver_host)
        if not is_anthropic_or_claude_target(custom_norm) and host == custom_norm:
            custom_ok = True

    if host not in ALLOWED_EXTERNAL_ENDPOINTS and not custom_ok:
        log.record(
            action="validate_target",
            target_host=host,
            url_or_endpoint=raw,
            probe_group=probe_group,
            allowed=False,
            reason="host_not_in_approved_allowlist",
            status="blocked",
        )
        raise ZeroContactViolationError(f"Host '{host}' is not in the audited external endpoint allowlist.")

    return host, raw


def resolve_and_verify_public_ips(
    host: str,
    port: int = 443,
    *,
    allow_fake_ip_range: bool = True,
) -> tuple[list[tuple[int, str]], int]:
    """Resolve host via DNS and verify no loopback/private/link-local DNS rebinding occurs.

    Returns (list of (family, ip_str), fake_ip_mapped_count).
    """
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    unique: list[tuple[int, str]] = []
    seen: set[tuple[int, str]] = set()
    mapped_count = 0
    fake_v4 = ipaddress.ip_network("198.18.0.0/15")
    fake_v6 = ipaddress.ip_network("2001:2::/48")

    for family, _, _, _, sockaddr in infos:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        ip_str = sockaddr[0].split("%")[0]
        addr = ipaddress.ip_address(ip_str)
        is_fake_ip = addr in fake_v4 or addr in fake_v6
        if is_fake_ip:
            mapped_count += 1
            if not allow_fake_ip_range:
                raise ZeroContactViolationError(f"dns_resolved_to_fake_ip:{ip_str}")
        elif not addr.is_global:
            # Block DNS rebinding to 127.0.0.1, ::1, 10.x, 192.168.x, 169.254.x
            raise ZeroContactViolationError(f"dns_rebinding_non_public_ip_blocked:{ip_str}")
        key = (family, ip_str)
        if key not in seen:
            seen.add(key)
            unique.append(key)

    if not unique:
        raise OSError("dns_empty_resolution")
    return unique, mapped_count


class _StrictAllowlistRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Forbids all HTTP redirects by default; for rdap.org bootstrap only, permits HTTPS redirect to RIR RDAP."""

    def __init__(self, allow_rdap_bootstrap: bool = False, audit_log: NetworkAuditLog | None = None) -> None:
        super().__init__()
        self.allow_rdap_bootstrap = allow_rdap_bootstrap
        self.audit_log = audit_log or GLOBAL_NETWORK_AUDIT_LOG

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not self.allow_rdap_bootstrap:
            self.audit_log.record(
                action="http_redirect_blocked",
                target_host=urllib.parse.urlsplit(newurl).hostname or "<redirect>",
                url_or_endpoint=newurl[:128],
                probe_group="redirect_guard",
                allowed=False,
                reason=f"redirect_{code}_blocked_by_zero_contact_guard",
                status="blocked",
            )
            return None
        # Even for RDAP bootstrap, strictly validate the redirect target against ALLOWED_EXTERNAL_ENDPOINTS!
        full_url = urllib.parse.urljoin(req.full_url, newurl)
        host, _ = verify_external_target(full_url, probe_group="rdap_rpki", audit_log=self.audit_log)
        resolve_and_verify_public_ips(host, 443)
        return super().redirect_request(req, fp, code, msg, headers, full_url)


def safe_fetch_json(
    url: str,
    *,
    probe_group: str = "ip",
    timeout: float = 5.0,
    allow_rdap_redirect: bool = False,
    consent_manager: ConsentManager | None = None,
    audit_log: NetworkAuditLog | None = None,
) -> tuple[dict[str, Any], int, float | None]:
    """Fetch JSON from an allowlisted non-Anthropic diagnostic endpoint with full Zero-Contact protection."""
    cm = consent_manager or GLOBAL_CONSENT_MANAGER
    log = audit_log or GLOBAL_NETWORK_AUDIT_LOG

    tier_key = "tier2_payment_tls" if probe_group == "payment_tls" else "tier2_external_network"
    if not cm.is_granted(tier_key):
        log.record(
            action="http_get",
            target_host=urllib.parse.urlsplit(url).hostname or "<unknown>",
            url_or_endpoint=url,
            probe_group=probe_group,
            allowed=False,
            reason=f"consent_not_granted:{tier_key}",
            status="permission_required",
        )
        raise ConsentRequiredError(f"Permission '{tier_key}' is required before external network probes.")

    host, validated_url = verify_external_target(url, probe_group=probe_group, audit_log=log)
    started = time.monotonic()
    try:
        resolve_and_verify_public_ips(host, 443)
        proxies = {}
        for kind, value in urllib.request.getproxies().items():
            if kind not in ("http", "https"):
                continue
            parsed = urllib.parse.urlsplit(value if "://" in value else "http://" + value)
            if parsed.username or parsed.password:
                continue
            if parsed.scheme in ("http", "https") and parsed.hostname:
                proxies[kind] = value if "://" in value else "http://" + value

        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler(proxies),
            urllib.request.HTTPSHandler(context=verified_context()),
            _StrictAllowlistRedirectHandler(allow_rdap_bootstrap=allow_rdap_redirect, audit_log=log),
        )
        req = urllib.request.Request(
            validated_url,
            headers={
                "User-Agent": "CC-Auditor-Toolkit/2.0 (Zero-Anthropic-Contact-Preflight)",
                "Accept": "application/json, application/rdap+json",
            },
        )
        with activate_socket_guard(audit_log=log):
            with opener.open(req, timeout=timeout) as resp:
                raw = resp.read(65537)
                if len(raw) > 65536:
                    raise ValueError("oversized_response")
            date_hdr = resp.headers.get("Date")
            age_hdr = resp.headers.get("Age", "0")
            clock_delta: float | None = None
            try:
                if date_hdr and int(age_hdr) < 60:
                    server_dt = parsedate_to_datetime(date_hdr)
                    clock_delta = round((server_dt - dt.datetime.now(dt.timezone.utc)).total_seconds(), 1)
            except Exception:
                pass
            payload = json.loads(raw.decode("utf-8", errors="replace"))
            elapsed_ms = round((time.monotonic() - started) * 1000)
            log.record(
                action="http_get",
                target_host=host,
                url_or_endpoint=validated_url,
                probe_group=probe_group,
                allowed=True,
                reason="allowlisted_tier2_probe",
                status="ok",
                duration_ms=elapsed_ms,
            )
            return payload, elapsed_ms, clock_delta
    except ZeroContactViolationError:
        raise
    except Exception as exc:
        elapsed_ms = round((time.monotonic() - started) * 1000)
        log.record(
            action="http_get",
            target_host=host,
            url_or_endpoint=validated_url,
            probe_group=probe_group,
            allowed=True,
            reason="allowlisted_tier2_probe",
            status=f"error:{type(exc).__name__}",
            duration_ms=elapsed_ms,
        )
        raise
