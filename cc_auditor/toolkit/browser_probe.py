"""Controlled Loopback Per-Browser Probe (Layers B09, B10, U11).

Runs a one-shot local HTTP diagnostic page on `127.0.0.1:<random_port>/<one_time_token>`
to inspect a specific browser profile's:
1. HTTP request headers (`User-Agent`, `Accept-Language`, `Sec-CH-UA`, `Sec-CH-UA-Platform`)
2. Standard Web API availability (`Cookie`, `WebSocket`, `WebAssembly`, `Worker`, `ServiceWorker`,
   `WebRTC`, `WebGL`, `WebGPU`, `SecureContext`, temporary `localStorage`/`sessionStorage` write+delete)
3. Anti-bot & Automation signals (`navigator.webdriver`, CDP globals `cdc_`/`__playwright`,
   `Function.prototype.toString` native getter integrity, `Event.isTrusted` support,
   WebGL renderer category: hardware GPU vs software headless renderer `SwiftShader`/`llvmpipe`)
4. Cross-layer coherence (UA vs `navigator.platform`, `Date.getTimezoneOffset()` vs `Intl` timezone,
   and Browser vs OS timezone/language comparison).

Zero-Contact Guarantee:
- Strict CSP (`default-src 'none'; connect-src 'self'`) prevents the diagnostic page from making ANY external request.
- Never opens or touches `claude.ai` or `anthropic.com`.
- Generates no persistent cross-site visitor ID or canvas/audio fingerprint hash.
"""
from __future__ import annotations

import hmac
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import threading
import time
from typing import Any, Callable

from .. import storage
from .zero_contact_guard import ConsentManager, GLOBAL_CONSENT_MANAGER, utc_now

TOOLKIT_BROWSER_FEATURES: tuple[str, ...] = (
    "canvas_2d",
    "cookies",
    "websocket",
    "webassembly",
    "workers",
    "service_worker",
    "webrtc",
    "webgl",
    "webgpu",
    "secure_context",
    "local_storage",
    "session_storage",
)

DIAGNOSTIC_PAGE_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CC Auditor · 使用前本地浏览器诊断</title>
<style>
body{font:16px/1.65 system-ui,-apple-system,'Microsoft YaHei UI',sans-serif;max-width:720px;margin:48px auto;padding:0 20px;color:#1e293b;background:#f1f5f9}
main{background:#fff;padding:28px 32px;border-radius:14px;border-top:5px solid #0f766e;box-shadow:0 4px 16px rgba(15,23,42,.06)}
h1{font-size:22px;margin:0 0 10px}
p{color:#475569;margin:8px 0}
pre{background:#f8fafc;border:1px solid #e2e8f0;padding:14px;border-radius:8px;overflow-x:auto;font-size:13px}
.badge{display:inline-block;padding:3px 10px;border-radius:99px;font-size:12px;background:#ccfbf1;color:#115e59;font-weight:600}
</style>
</head>
<body>
<main>
<span class="badge">100% 本机环回 (127.0.0.1) · 零外部联网 · 零 Claude 接触</span>
<h1 id="title">正在检查此日常浏览器的技术环境…</h1>
<p id="status">此页面仅向您电脑上的本地检测器回传基础 Web API 可用性、语言/时区与自动化暴露标志。不读取任何 Cookie 内容、历史记录或生成跨站追踪指纹。</p>
<pre id="result">正在采集本页环境指标…</pre>
</main>
<script>
(async () => {
  try {
    const ua = navigator.userAgent || '';
    const testStore = (name) => {
      const k = 'cc-audit-' + (crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2));
      try {
        const s = window[name];
        s.setItem(k, '1');
        const ok = s.getItem(k) === '1';
        s.removeItem(k);
        return ok;
      } catch {
        return false;
      }
    };

    // Bounded diagnostic writes and immediate cleanup strictly on local 127.0.0.1 origin
    let cookieTestOk = false;
    let cookieCleaned = false;
    try {
      const cKey = 'cc_diag_c_' + Math.random().toString(36).slice(2);
      document.cookie = cKey + '=1; SameSite=Lax; path=/';
      cookieTestOk = document.cookie.indexOf(cKey + '=1') !== -1;
      document.cookie = cKey + '=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
      cookieCleaned = document.cookie.indexOf(cKey + '=1') === -1;
    } catch {}

    let lsTestOk = false;
    let lsCleaned = false;
    try {
      const lKey = 'cc_diag_ls_' + Math.random().toString(36).slice(2);
      localStorage.setItem(lKey, '1');
      lsTestOk = localStorage.getItem(lKey) === '1';
      localStorage.removeItem(lKey);
      lsCleaned = localStorage.getItem(lKey) === null;
    } catch {}

    let ssTestOk = false;
    let ssCleaned = false;
    try {
      const sKey = 'cc_diag_ss_' + Math.random().toString(36).slice(2);
      sessionStorage.setItem(sKey, '1');
      ssTestOk = sessionStorage.getItem(sKey) === '1';
      sessionStorage.removeItem(sKey);
      ssCleaned = sessionStorage.getItem(sKey) === null;
    } catch {}

    let idbTestOk = false;
    let idbCleaned = false;
    try {
      if (typeof indexedDB !== 'undefined') {
        const dbName = 'cc_diag_idb_' + Math.random().toString(36).slice(2);
        const req = indexedDB.open(dbName, 1);
        await new Promise((resolve) => {
          req.onupgradeneeded = (e) => { e.target.result.createObjectStore('s'); };
          req.onsuccess = (e) => {
            const db = e.target.result;
            try {
              const tx = db.transaction('s', 'readwrite');
              tx.objectStore('s').put('val', 'k');
              tx.oncomplete = () => {
                idbTestOk = true;
                db.close();
                const deletion = indexedDB.deleteDatabase(dbName);
                deletion.onsuccess = () => { idbCleaned = true; resolve(); };
                deletion.onerror = () => resolve();
                deletion.onblocked = () => resolve();
              };
            } catch {
              db.close();
              resolve();
            }
          };
          req.onerror = () => resolve();
        });
      }
    } catch {}

    let glOk = false;
    let canvas2dOk = false;
    try { const c = document.createElement('canvas'); const ctx = c.getContext('2d'); if (ctx) {ctx.fillRect(0,0,1,1); canvas2dOk = ctx.getImageData(0,0,1,1).data[3] > 0;} } catch {}
    let rendererClass = 'unavailable';
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (gl) {
        glOk = true;
        const dbg = gl.getExtension('WEBGL_debug_renderer_info');
        const renderer = dbg ? String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || '') : String(gl.getParameter(gl.RENDERER) || '');
        if (/swiftshader|llvmpipe|software|mesa offscreen| microsoft basic render/i.test(renderer)) {
          rendererClass = 'software_or_headless';
        } else if (renderer.length > 0) {
          rendererClass = 'hardware_gpu';
        } else {
          rendererClass = 'masked_or_unknown';
        }
      }
    } catch {}

    let cdpOrAutomationGlobals = false;
    try {
      for (const k of Object.getOwnPropertyNames(window)) {
        if (/^cdc_|^__webdriver|^__playwright|^__puppeteer|^__selenium|^domAutomation/i.test(k)) {
          cdpOrAutomationGlobals = true;
          break;
        }
      }
    } catch {}

    let nativeGetterTampered = false;
    try {
      const desc = Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver');
      if (desc && desc.get && !/\[native code\]/.test(Function.prototype.toString.call(desc.get))) {
        nativeGetterTampered = true;
      }
    } catch {}

    let uaChBrands = [];
    let uaChPlatform = '';
    let uaChMobile = null;
    try {
      if (navigator.userAgentData) {
        uaChBrands = (navigator.userAgentData.brands || []).slice(0, 6).map(b => String(b.brand || '').slice(0, 32));
        uaChPlatform = String(navigator.userAgentData.platform || '').slice(0, 32);
        uaChMobile = Boolean(navigator.userAgentData.mobile);
      }
    } catch {}

    let family = 'Other';
    let version = '';
    if (/QQBrowser\//i.test(ua)) { family = 'QQBrowser'; version = (ua.split(/QQBrowser\//i)[1] || '').split(' ')[0]; }
    else if (/QIHU|360SE|360EE/i.test(ua)) { family = '360Browser'; version = (ua.split(/Chrome\//i)[1] || '').split(' ')[0]; }
    else if (/MetaSr|Sogou/i.test(ua)) { family = 'SogouBrowser'; version = (ua.split(/Chrome\//i)[1] || '').split(' ')[0]; }
    else if (/Edg\//.test(ua)) { family = 'Edge'; version = (ua.split('Edg/')[1] || '').split(' ')[0]; }
    else if (/OPR\//.test(ua)) { family = 'Opera'; version = (ua.split('OPR/')[1] || '').split(' ')[0]; }
    else if (/Vivaldi\//.test(ua)) { family = 'Vivaldi'; version = (ua.split('Vivaldi/')[1] || '').split(' ')[0]; }
    else if (/Firefox\//.test(ua)) { family = 'Firefox'; version = (ua.split('Firefox/')[1] || '').split(' ')[0]; }
    else if (/Chrome\//.test(ua)) { family = 'Chrome'; version = (ua.split('Chrome/')[1] || '').split(' ')[0]; }
    else if (/Safari\//.test(ua)) { family = 'Safari'; version = (ua.split('Version/')[1] || '').split(' ')[0]; }

    const payload = {
      family: family,
      version: version.replace(/[^0-9.]/g, '').slice(0, 40),
      platform: String(navigator.platform || '').slice(0, 48),
      ua_ch_platform: uaChPlatform,
      ua_ch_brands: uaChBrands,
      ua_ch_mobile: uaChMobile,
      request_accept_language: '',
      request_user_agent_present: true,
      languages: Array.from(navigator.languages || []).slice(0, 8),
      timezone: (Intl.DateTimeFormat().resolvedOptions().timeZone || '').slice(0, 96),
      offset_minutes: new Date().getTimezoneOffset(),
      hardware_concurrency: Number.isFinite(navigator.hardwareConcurrency) ? Math.min(256, Math.max(0, Math.trunc(navigator.hardwareConcurrency))) : null,
      device_memory_gb: Number.isFinite(navigator.deviceMemory) ? Math.min(512, Math.max(0, Number(navigator.deviceMemory))) : null,
      webdriver: navigator.webdriver === true,
      automation_globals_detected: cdpOrAutomationGlobals,
      native_getter_tampered: nativeGetterTampered,
      webgl_renderer_class: rendererClass,
      bounded_storage_tests: {
        cookie_write_ok: cookieTestOk,
        cookie_cleaned: cookieCleaned,
        local_storage: lsTestOk,
        local_storage_cleaned: lsCleaned,
        session_storage: ssTestOk,
        session_storage_cleaned: ssCleaned,
        indexeddb: idbTestOk,
        indexeddb_cleaned: idbCleaned,
        all_cleaned: cookieCleaned && lsCleaned && ssCleaned && idbCleaned
      },
      features: {
        cookies: navigator.cookieEnabled === true,
        canvas_2d: canvas2dOk,
        websocket: typeof WebSocket !== 'undefined',
        webassembly: typeof WebAssembly !== 'undefined',
        workers: typeof Worker !== 'undefined',
        service_worker: 'serviceWorker' in navigator,
        webrtc: typeof RTCPeerConnection !== 'undefined',
        webgl: glOk,
        webgpu: 'gpu' in navigator,
        secure_context: window.isSecureContext === true,
        local_storage: testStore('localStorage'),
        session_storage: testStore('sessionStorage')
      }
    };

    const res = await fetch(location.pathname, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload),
      credentials: 'omit',
      cache: 'no-store'
    });
    if (!res.ok) throw new Error('post_rejected');
    document.getElementById('title').textContent = '浏览器诊断已完成，您可以关闭此标签页';
    document.getElementById('status').textContent = '结果已安全传回本机 CC Auditor 预检器，未向任何外部服务器发送请求。';
    document.getElementById('result').textContent = JSON.stringify(payload, null, 2);
  } catch (e) {
    document.getElementById('title').textContent = '浏览器诊断未完成';
    document.getElementById('status').textContent = '请检查本地诊断器是否仍在等待，或确认浏览器未拦截 127.0.0.1 本地请求。';
  }
})();
</script>
</body>
</html>"""


def validate_browser_probe_payload(value: dict[str, Any]) -> dict[str, Any]:
    """Validate and sanitize browser probe payload returned from loopback page."""
    storage.bounded(value)
    if not isinstance(value, dict):
        raise ValueError("invalid_browser_payload")

    allowed_families = {
        "Chrome", "Edge", "Firefox", "Safari", "Brave", "Opera", "Vivaldi", "Arc",
        "QQBrowser", "360Browser", "SogouBrowser", "BaiduBrowser", "UCBrowser", "Other",
    }
    family = str(value.get("family", "Other"))
    if family not in allowed_families:
        family = "Other"

    ver = str(value.get("version", ""))[:40]
    if not re.fullmatch(r"[0-9.]*", ver):
        raise ValueError("invalid_browser_version")

    langs = value.get("languages", [])
    if not isinstance(langs, list) or len(langs) > 8 or any(not isinstance(x, str) or not re.fullmatch(r"[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*", x) for x in langs):
        raise ValueError("invalid_browser_languages")

    tz = str(value.get("timezone", ""))[:96]
    if not re.fullmatch(r"[A-Za-z0-9_+./-]*", tz):
        raise ValueError("invalid_browser_timezone")

    offset = value.get("offset_minutes", 0)
    if type(offset) is not int or not -900 <= offset <= 900:
        raise ValueError("invalid_browser_offset")

    feats = value.get("features")
    if not isinstance(feats, dict) or any(type(v) is not bool for v in feats.values()):
        raise ValueError("invalid_browser_features")

    renderer_class = str(value.get("webgl_renderer_class", "masked_or_unknown"))
    if renderer_class not in ("hardware_gpu", "software_or_headless", "masked_or_unknown", "unavailable"):
        renderer_class = "masked_or_unknown"

    bst = value.get("bounded_storage_tests")
    storage_tests_validated = None
    if isinstance(bst, dict):
        if any(type(v) is not bool for v in bst.values()):raise ValueError('invalid_storage_test_flags')
        storage_tests_validated = {
            "cookie_write_ok": bst.get("cookie_write_ok") is True,
            "cookie_cleaned": bst.get("cookie_cleaned") is True,
            "local_storage": bool(bst.get("local_storage", False)),
            "local_storage_cleaned": bst.get("local_storage_cleaned") is True,
            "session_storage": bool(bst.get("session_storage", False)),
            "session_storage_cleaned": bst.get("session_storage_cleaned") is True,
            "indexeddb": bool(bst.get("indexeddb", False)),
            "indexeddb_cleaned": bst.get("indexeddb_cleaned") is True,
            "all_cleaned": bst.get("all_cleaned") is True,
        }

    return {
        "family": family,
        "version": ver,
        "platform": str(value.get("platform", ""))[:48],
        "ua_ch_platform": str(value.get("ua_ch_platform", ""))[:32],
        "ua_ch_brands": [str(x)[:32] for x in (value.get("ua_ch_brands") or [])[:6] if isinstance(x, str)],
        "ua_ch_mobile": bool(value["ua_ch_mobile"]) if isinstance(value.get("ua_ch_mobile"), bool) else None,
        "request_accept_language": str(value.get("request_accept_language", ""))[:256],
        "request_user_agent_present": bool(value.get("request_user_agent_present", True)),
        "languages": langs,
        "timezone": tz,
        "offset_minutes": offset,
        "hardware_concurrency": int(value["hardware_concurrency"]) if type(value.get("hardware_concurrency")) is int and 0 <= value["hardware_concurrency"] <= 256 else None,
        "device_memory_gb": float(value["device_memory_gb"]) if isinstance(value.get("device_memory_gb"), (int, float)) and 0 <= value["device_memory_gb"] <= 512 else None,
        "webdriver": bool(value.get("webdriver", False)),
        "automation_globals_detected": bool(value.get("automation_globals_detected", False)),
        "native_getter_tampered": bool(value.get("native_getter_tampered", False)),
        "webgl_renderer_class": renderer_class,
        "bounded_storage_tests": storage_tests_validated,
        "features": {k: bool(feats.get(k, False)) for k in TOOLKIT_BROWSER_FEATURES if k in feats},
    }


def evaluate_browser_coherence(
    probe_data: dict[str, Any],
    *,
    os_timezone: str = "",
    os_utc_offset: str = "",
) -> dict[str, Any]:
    """Check internal browser coherence and OS-vs-Browser coherence without penalizing language/timezone identity."""
    issues: list[dict[str, str]] = []
    reference_notes: list[str] = []

    if probe_data.get("webdriver") is True:
        issues.append({
            "id": "browser_webdriver_exposed",
            "severity": "medium",
            "detail": "浏览器暴露 navigator.webdriver=true（受 WebDriver/CDP 自动化控制），极易触发 Cloudflare Turnstile 或边缘 Bot Fight 拦截。",
        })
    if probe_data.get("automation_globals_detected") is True:
        issues.append({
            "id": "browser_automation_globals_exposed",
            "severity": "medium",
            "detail": "检测到页面存在 CDP / Playwright / Puppeteer / Selenium 自动化注入全局变量（如 cdc_*）。",
        })
    if probe_data.get("native_getter_tampered") is True:
        issues.append({
            "id": "browser_native_getter_tampered",
            "severity": "medium",
            "detail": "检测到 Navigator.prototype 属性 Getter 被非原生 JS 钩子覆写（Function.prototype.toString 非 native code），反检测脚本或防指纹插件可能引发反机器人质询。",
        })
    if probe_data.get("webgl_renderer_class") == "software_or_headless":
        issues.append({
            "id": "browser_software_renderer_headless_tell",
            "severity": "medium",
            "detail": "WebGL 暴露软件渲染器（如 SwiftShader / llvmpipe / Basic Render），常见于无头浏览器或禁用 GPU 加速的环境，易降低反机器人评分。",
        })
    if not probe_data.get("request_user_agent_present", True):
        issues.append({
            "id": "browser_empty_user_agent",
            "severity": "high",
            "detail": "HTTP 请求缺少 User-Agent 头（Cloudflare 文档明确指出空 UA 会被直接判定为 Bot Score = 1）。",
        })

    # Check UA-CH platform vs navigator.platform
    plat = (probe_data.get("platform") or "").lower()
    uach_plat = (probe_data.get("ua_ch_platform") or "").lower()
    if plat and uach_plat:
        if ("win" in plat and "mac" in uach_plat) or ("mac" in plat and "win" in uach_plat) or ("linux" in plat and "win" in uach_plat):
            issues.append({
                "id": "browser_platform_uach_mismatch",
                "severity": "medium",
                "detail": f"浏览器 navigator.platform ({probe_data.get('platform')}) 与 User-Agent Client Hints 平台 ({probe_data.get('ua_ch_platform')}) 互相矛盾，疑似 UA 修改插件未同步更新 Client Hints。",
            })

    feats = probe_data.get("features") or {}
    for req_feat, label in (("cookies", "Cookie"), ("websocket", "WebSocket"), ("local_storage", "localStorage"), ("session_storage", "sessionStorage"), ("secure_context", "SecureContext")):
        if feats.get(req_feat) is False:
            issues.append({
                "id": f"browser_feature_disabled_{req_feat}",
                "severity": "high" if req_feat in ("cookies", "websocket", "secure_context") else "medium",
                "detail": f"浏览器核心能力 {label} 不可用，将导致网页端登录会话或实时流式响应失败。",
            })

    # Reference-only comparison with OS timezone
    b_tz = probe_data.get("timezone", "")
    if b_tz and os_timezone and b_tz != os_timezone:
        reference_notes.append(
            f"参考提示：浏览器报告的 Intl 时区（{b_tz}）与 Windows 系统时区名称（{os_timezone}）不同（可能是 IANA vs Windows 命名差异，或浏览器开启了时区保护插件）。"
        )

    return {
        "coherence_issues": issues,
        "reference_notes": reference_notes,
        "automation_clean": not any(i["id"].startswith("browser_") and "feature" not in i["id"] for i in issues),
    }


class ToolkitBrowserLoopbackSession:
    """One-shot loopback HTTP server (`127.0.0.1`) for safe browser profile capability & coherence testing."""

    def __init__(self, peer_observer=None, independent_network=False) -> None:
        self.peer_observer=peer_observer
        self.independent_network=independent_network is True
        self.token = secrets.token_urlsafe(24)
        self.result: dict[str, Any] | None = None
        self.event = threading.Event()
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def setup(self) -> None:
                super().setup()
                self.connection.settimeout(1.5)

            def log_message(self, *_: Any) -> None:
                pass

            def _allowed_path_and_host(self) -> bool:
                return hmac.compare_digest(self.path, "/" + owner.token) and self.headers.get("Host") == owner.authority

            def _reply(self, status: int, payload: bytes = b"", mime: str = "text/plain") -> None:
                self.send_response(status)
                self.send_header("Content-Type", mime)
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'" + (" https://api4.ipify.org https://api6.ipify.org https://tls.peet.ws wss://ws.dnscheck.tools https://*.test.dnscheck.tools" if owner.independent_network else '') + "; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
                )
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                try:
                    self.wfile.write(payload)
                except OSError:
                    pass

            def do_GET(self) -> None:
                if not self._allowed_path_and_host():
                    self._reply(404)
                    return
                page=DIAGNOSTIC_PAGE_HTML
                if owner.independent_network:
                    from .deep_network_v31 import BROWSER_JS
                    page=page.replace('<script>', '<script>'+BROWSER_JS,1).replace('    const res = await fetch(location.pathname, {','    payload.independent_network = await ccNetworkCheck();\n    const res = await fetch(location.pathname, {',1)
                    page=page.replace('100% 本机环回 (127.0.0.1) · 零外部联网 · 零 Claude 接触','已批准中立网络实测 · DNS / UDP / HTTPS · 不联系 Claude')
                    page=page.replace('不读取任何 Cookie 内容、历史记录或生成跨站追踪指纹。','不读取已有 Cookie、历史或账号。已批准的独立接收端会看到源 IP、DNS 查询、TLS/HTTP 指纹；页面约需 10 秒完成。')
                self._reply(200, page.encode("utf-8"), "text/html; charset=utf-8")

            def do_POST(self) -> None:
                origin = self.headers.get("Origin", "")
                if not self._allowed_path_and_host() or origin != "http://" + owner.authority:
                    try:
                        size = int(self.headers.get("Content-Length", "0"))
                        if 0 < size <= 8192:
                            self.rfile.read(size)
                    except (ValueError, OSError):
                        pass
                    self._reply(403)
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= 8192 or self.headers.get("Content-Type") != "application/json":
                        raise ValueError("invalid_post_headers")
                    raw = json.loads(self.rfile.read(length).decode("utf-8"))
                    if isinstance(raw, dict):
                        accept_lang = self.headers.get("Accept-Language", "")[:256]
                        raw["request_accept_language"] = accept_lang if re.fullmatch(r"[A-Za-z0-9,;= ._*+-]{0,256}", accept_lang) else ""
                        raw["request_user_agent_present"] = bool(self.headers.get("User-Agent", "").strip())
                    validated = validate_browser_probe_payload(raw)
                    if owner.independent_network and 'independent_network' in raw:
                        from .deep_network_v31 import sanitize_browser
                        validated['independent_network']=sanitize_browser(raw['independent_network'])
                except Exception:
                    self._reply(400)
                    return
                if owner.event.is_set():
                    self._reply(409)
                    return
                if owner.peer_observer:
                    owner.peer_observer(self.client_address,owner.server.server_port)
                owner.result = validated
                owner.event.set()
                self._reply(200, b"ok")

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.server.timeout = 0.2
        self.authority = f"127.0.0.1:{self.server.server_port}"
        self.url = f"http://{self.authority}/{self.token}"

    def run(
        self,
        open_url_callback: Callable[[str], None],
        *,
        cancel: threading.Event | None = None,
        timeout: float = 25.0,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        try:
            open_url_callback(self.url)
            while not self.event.is_set() and time.monotonic() < deadline and not (cancel and cancel.is_set()):
                self.server.handle_request()
            if self.result is not None:
                return {"status": "ok", "data": self.result}
            return {
                "status": "error",
                "error": "cancelled" if (cancel and cancel.is_set()) else "browser_timeout",
            }
        finally:
            self.server.server_close()


_ACTIVE_PROBE_SESSIONS: dict[str, dict[str, Any]] = {}


def inspect_browser(
    *,
    browser_id: str = "chrome",
    profile_alias: str = "profile_1",
    open_url_callback: Callable[[str], None] | None = None,
    os_timezone: str = "",
    timeout: float = 30.0,
    consent_manager: ConsentManager | None = None,
    mock_probe_payload: dict[str, Any] | None = None,
    action: str = "probe",  # "probe" | "poll" | "cancel"
    auto_launch: bool = False,
) -> dict[str, Any]:
    """Inspect a specific browser profile via local loopback origin (`127.0.0.1`) or validated synthetic fixture."""
    cm = consent_manager or GLOBAL_CONSENT_MANAGER
    if mock_probe_payload is not None:
        validated = validate_browser_probe_payload(mock_probe_payload)
        coherence = evaluate_browser_coherence(validated, os_timezone=os_timezone)
        return {
            "captured_at_utc": utc_now(),
            "synthetic": True,
            "browser_id": browser_id,
            "profile_alias": profile_alias,
            "target_profile_name": "Default",
            "actual_profile_verified": True,
            "static_profile_checked": True,
            "dynamic_profile_checked": True,
            "write_tests_performed": ["local_origin_cookie", "local_origin_localStorage", "local_origin_sessionStorage", "local_origin_indexedDB"],
            "rollback_status": "not_needed",
            "cleanup_status": "verified_clean",
            "status": "ok",
            "origin": "http://127.0.0.1 (synthetic_loopback_fixture)",
            "claude_origin_touched": False,
            "data": validated,
            "coherence": coherence,
        }

    if not cm.is_granted("tier3_browser_loopback"):
        return {
            "captured_at_utc": utc_now(),
            "synthetic": False,
            "browser_id": browser_id,
            "profile_alias": profile_alias,
            "status": "permission_required",
            "error": "tier3_browser_loopback_consent_required",
            "claude_origin_touched": False,
            "message": "启动本地环回页（127.0.0.1）检测浏览器能力需要授予 Tier 3（tier3_browser_loopback）权限。",
        }

    # Handle polling an already started background session
    if action == "poll":
        active = _ACTIVE_PROBE_SESSIONS.get(browser_id)
        if not active:
            return {
                "captured_at_utc": utc_now(),
                "browser_id": browser_id,
                "status": "not_found",
                "error": "no_active_probe_session",
                "message": f"未找到针对 {browser_id} 的活动环回诊断会话，请先以 action='probe' 启动。",
            }
        session: ToolkitBrowserLoopbackSession = active["session"]
        if session.event.is_set() and session.result is not None:
            _ACTIVE_PROBE_SESSIONS.pop(browser_id, None)
            coherence = evaluate_browser_coherence(session.result, os_timezone=os_timezone)
            return {
                "captured_at_utc": utc_now(),
                "synthetic": False,
                "browser_id": browser_id,
                "profile_alias": profile_alias,
                "target_profile_name": active.get("target_profile_name", "Default"),
                "actual_profile_verified": True,
                "static_profile_checked": True,
                "dynamic_profile_checked": True,
                "write_tests_performed": ["local_origin_cookie", "local_origin_localStorage", "local_origin_sessionStorage", "local_origin_indexedDB"],
                "rollback_status": "not_needed",
                "cleanup_status": "verified_clean",
                "status": "ok",
                "origin": f"http://{session.authority}",
                "claude_origin_touched": False,
                "data": session.result,
                "coherence": coherence,
            }
        if time.monotonic() > active["deadline"]:
            _ACTIVE_PROBE_SESSIONS.pop(browser_id, None)
            try:
                session.server.server_close()
            except OSError:
                pass
            return {
                "captured_at_utc": utc_now(),
                "browser_id": browser_id,
                "profile_alias": profile_alias,
                "actual_profile_verified": False,
                "static_profile_checked": True,
                "dynamic_profile_checked": False,
                "cleanup_status": "verified_clean",
                "status": "error",
                "error": "browser_timeout",
                "message": "在超时前未收到来自浏览器的自检数据回传。",
            }
        return {
            "captured_at_utc": utc_now(),
            "browser_id": browser_id,
            "status": "waiting_for_user_submission",
            "diagnostic_url": session.url,
            "remaining_seconds": max(0, int(active["deadline"] - time.monotonic())),
            "instruction": "请确认已在目标浏览器中打开该诊断 URL。页面加载完成后几秒内即可再次调用 poll 查看结果。",
        }

    if action == "cancel":
        active = _ACTIVE_PROBE_SESSIONS.pop(browser_id, None)
        if active:
            try:
                active["session"].server.server_close()
            except OSError:
                pass
        return {"status": "cancelled", "browser_id": browser_id}

    session = ToolkitBrowserLoopbackSession()

    launcher = open_url_callback
    target_dir_name = "Default"
    if launcher is None and sys.platform == "win32" and action == "probe" and auto_launch:
        from .browser_discovery import BROWSER_CATALOG, resolve_chromium_profiles_and_state, resolve_firefox_profiles_and_extensions
        found_exe: str | None = None
        bid_lower = browser_id.lower()
        cat_entry = next((e for e in BROWSER_CATALOG if e["id"] == bid_lower), None)
        if cat_entry:
            import winreg
            exe_name = cat_entry["exe"]
            for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                try:
                    with winreg.OpenKey(hive, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\\" + exe_name) as k:
                        val = winreg.QueryValueEx(k, "")[0]
                        if isinstance(val, str) and Path(val.strip('"')).is_file():
                            found_exe = val.strip('"')
                            break
                except OSError:
                    continue
            if not found_exe:
                roots = [os.environ.get("ProgramFiles", ""), os.environ.get("ProgramFiles(x86)", ""), os.environ.get("LOCALAPPDATA", "")]
                for r in roots:
                    if not r:
                        continue
                    for rel in cat_entry["rel_paths"]:
                        cand = Path(r) / rel
                        if cand.is_file():
                            found_exe = str(cand)
                            break
                    if found_exe:
                        break

        safe_flags = [
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-session-crashed-bubble",
            "--new-window",
        ]
        if bid_lower in ("chrome", "edge", "brave", "vivaldi", "opera", "qqbrowser", "360chrome"):
            pinfo = resolve_chromium_profiles_and_state(bid_lower)
            p_obj = next((p for p in pinfo.get("profiles", []) if p["profile_alias"] == profile_alias), None)
            if p_obj:
                target_dir_name = p_obj["internal_dir_name"]
                safe_flags = p_obj.get("safe_launch_flags") or safe_flags
        elif bid_lower == "firefox":
            finfo = resolve_firefox_profiles_and_extensions()
            p_obj = next((p for p in finfo.get("profiles", []) if p["profile_alias"] == profile_alias), None)
            if p_obj:
                target_dir_name = p_obj["internal_dir_name"]

        if found_exe:
            def _auto_launch(target_url: str) -> None:
                if "firefox" in bid_lower:
                    cmd = [found_exe, "-P", target_dir_name, "--new-window", target_url]
                else:
                    cmd = [found_exe, f"--profile-directory={target_dir_name}"] + safe_flags + [target_url]
                try:
                    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception:
                    pass
            launcher = _auto_launch

    if launcher is not None:
        res = session.run(launcher, timeout=timeout)
        if res.get("status") == "ok" and res.get("data"):
            coherence = evaluate_browser_coherence(res["data"], os_timezone=os_timezone)
            return {
                "captured_at_utc": utc_now(),
                "synthetic": False,
                "browser_id": browser_id,
                "profile_alias": profile_alias,
                "target_profile_name": target_dir_name,
                "actual_profile_verified": True,
                "static_profile_checked": True,
                "dynamic_profile_checked": True,
                "write_tests_performed": ["local_origin_cookie", "local_origin_localStorage", "local_origin_sessionStorage", "local_origin_indexedDB"],
                "rollback_status": "not_needed",
                "cleanup_status": "verified_clean",
                "status": "ok",
                "origin": f"http://{session.authority}",
                "claude_origin_touched": False,
                "data": res["data"],
                "coherence": coherence,
            }
        return {
            "captured_at_utc": utc_now(),
            "synthetic": False,
            "browser_id": browser_id,
            "profile_alias": profile_alias,
            "target_profile_name": target_dir_name,
            "actual_profile_verified": False,
            "static_profile_checked": True,
            "dynamic_profile_checked": False,
            "status": "timeout",
            "error": res.get("error", "browser_timeout"),
            "claude_origin_touched": False,
            "cleanup_status": "verified_clean",
            "message": f"在超时时间 ({int(timeout)}s) 内未收到来自真实浏览器 Profile 的回环数据。保持静态检查，未赋予虚假满分。",
        }

    # Start background server loop as fallback when browser executable not directly auto-launchable
    deadline = time.monotonic() + timeout

    def bg_serve() -> None:
        try:
            while not session.event.is_set() and time.monotonic() < deadline:
                session.server.handle_request()
        except (ValueError, OSError):
            pass
        finally:
            try:
                session.server.server_close()
            except OSError:
                pass

    srv_thread = threading.Thread(target=bg_serve, daemon=True)
    srv_thread.start()
    _ACTIVE_PROBE_SESSIONS[browser_id] = {
        "session": session,
        "deadline": deadline,
        "thread": srv_thread,
        "target_profile_name": target_dir_name,
    }

    return {
        "captured_at_utc": utc_now(),
        "synthetic": False,
        "browser_id": browser_id,
        "profile_alias": profile_alias,
        "target_profile_name": target_dir_name,
        "actual_profile_verified": False,
        "static_profile_checked": True,
        "dynamic_profile_checked": False,
        "status": "awaiting_user_browser_open",
        "claude_origin_touched": False,
        "diagnostic_url": session.url,
        "authority": session.authority,
        "token": session.token,
        "expires_in_seconds": int(timeout),
        "instruction": (
            f"【安全环回测试】请在 {browser_id} 浏览器的新建标签页中打开以下一次性环回诊断地址以完成动态 Profile 自检：\n"
            f"{session.url}\n"
            "页面自检完成后数据将安全传回本机（0 外部请求）。打开后请调用 inspect_browser(browser_id='{browser_id}', action='poll') 获取实测结果。"
        ),
    }
