"""Multi-Browser Discovery & Read-Only Extension Permission Auditor (Layers B08, B10).

Discovers installed and user-specified portable browsers on Windows without full-disk scanning:
- International Mainstream: Chrome, Edge, Firefox, Brave, Vivaldi, Opera, Arc
- Domestic Chinese Browsers: QQBrowser, 360SE, 360Chrome, SogouExplorer, BaiduBrowser, 2345Explorer, UCBrowser, Maxthon
- Fingerprint / Anti-Detect Browsers: AdsPower, BitBrowser, DolphinAnty, MoreLogin, Hubstudio, IxBrowser

Never reads Cookies, browsing history, saved passwords, or extension local storage.
"""
from __future__ import annotations

from cc_auditor.toolkit.psutil_compat import ensure_runtime_compat
ensure_runtime_compat()

import configparser
import json
import os
from pathlib import Path
import re
import shutil
import sys
from typing import Any

from ..collectors import file_version
from .host_identity import inspect_host_identity
from .zero_contact_guard import ConsentManager, GLOBAL_CONSENT_MANAGER, utc_now

BROWSER_CATALOG: list[dict[str, Any]] = [
    {"id": "chrome", "name": "Google Chrome", "exe": "chrome.exe", "engine": "Chromium", "category": "mainstream",
     "rel_paths": [r"Google\Chrome\Application\chrome.exe"]},
    {"id": "edge", "name": "Microsoft Edge", "exe": "msedge.exe", "engine": "Chromium", "category": "mainstream",
     "rel_paths": [r"Microsoft\Edge\Application\msedge.exe"]},
    {"id": "firefox", "name": "Mozilla Firefox", "exe": "firefox.exe", "engine": "Gecko", "category": "mainstream",
     "rel_paths": [r"Mozilla Firefox\firefox.exe"]},
    {"id": "brave", "name": "Brave Browser", "exe": "brave.exe", "engine": "Chromium", "category": "mainstream",
     "rel_paths": [r"BraveSoftware\Brave-Browser\Application\brave.exe"]},
    {"id": "vivaldi", "name": "Vivaldi", "exe": "vivaldi.exe", "engine": "Chromium", "category": "mainstream",
     "rel_paths": [r"Vivaldi\Application\vivaldi.exe"]},
    {"id": "opera", "name": "Opera", "exe": "opera.exe", "engine": "Chromium", "category": "mainstream",
     "rel_paths": [r"Programs\Opera\opera.exe", r"Opera\opera.exe"]},
    {"id": "arc", "name": "Arc Browser", "exe": "Arc.exe", "engine": "Chromium", "category": "mainstream",
     "rel_paths": [r"Microsoft\WindowsApps\Arc.exe"]},
    {"id": "qqbrowser", "name": "QQ 浏览器 (QQBrowser)", "exe": "QQBrowser.exe", "engine": "Chromium-DualCore", "category": "domestic_cn",
     "rel_paths": [r"Tencent\QQBrowser\QQBrowser.exe"]},
    {"id": "360se", "name": "360 安全浏览器 (360SE)", "exe": "360se.exe", "engine": "Chromium-DualCore", "category": "domestic_cn",
     "rel_paths": [r"360\360se6\Application\360se.exe", r"360se6\Application\360se.exe"]},
    {"id": "360chrome", "name": "360 极速浏览器 (360Chrome)", "exe": "360chrome.exe", "engine": "Chromium-DualCore", "category": "domestic_cn",
     "rel_paths": [r"360Chrome\Chrome\Application\360chrome.exe", r"360ChromeX\Chrome\Application\360chromex.exe"]},
    {"id": "sogou", "name": "搜狗高速浏览器 (SogouExplorer)", "exe": "SogouExplorer.exe", "engine": "Chromium-DualCore", "category": "domestic_cn",
     "rel_paths": [r"SogouExplorer\SogouExplorer.exe"]},
    {"id": "baidu", "name": "百度浏览器 (BaiduBrowser)", "exe": "baidubrowser.exe", "engine": "Chromium-DualCore", "category": "domestic_cn",
     "rel_paths": [r"baidu\baidubrowser\baidubrowser.exe"]},
    {"id": "ucbrowser", "name": "UC 浏览器 (UCBrowser)", "exe": "UCBrowser.exe", "engine": "Chromium-DualCore", "category": "domestic_cn",
     "rel_paths": [r"UCBrowser\Application\UCBrowser.exe"]},
    {"id": "2345explorer", "name": "2345 加速浏览器", "exe": "2345Explorer.exe", "engine": "Chromium-DualCore", "category": "domestic_cn",
     "rel_paths": [r"2345Soft\2345Explorer\2345Explorer.exe"]},
    {"id": "maxthon", "name": "傲游浏览器 (Maxthon)", "exe": "Maxthon.exe", "engine": "Chromium", "category": "domestic_cn",
     "rel_paths": [r"Maxthon\Application\Maxthon.exe"]},
    {"id": "adspower", "name": "AdsPower 指纹浏览器", "exe": "AdsPower Global.exe", "engine": "Chromium-Antidetect", "category": "fingerprint_antidetect",
     "rel_paths": [r"AdsPower Global\AdsPower Global.exe"]},
    {"id": "bitbrowser", "name": "比特指纹浏览器 (BitBrowser)", "exe": "BitBrowser.exe", "engine": "Chromium-Antidetect", "category": "fingerprint_antidetect",
     "rel_paths": [r"BitBrowser\BitBrowser.exe"]},
    {"id": "dolphin_anty", "name": "Dolphin{anty} 指纹浏览器", "exe": "Dolphin Anty.exe", "engine": "Chromium-Antidetect", "category": "fingerprint_antidetect",
     "rel_paths": [r"Programs\Dolphin Anty\Dolphin Anty.exe"]},
    {"id": "morelogin", "name": "MoreLogin 指纹浏览器", "exe": "MoreLogin.exe", "engine": "Chromium-Antidetect", "category": "fingerprint_antidetect",
     "rel_paths": [r"MoreLogin\MoreLogin.exe"]},
]

HIGH_RISK_PERMISSIONS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*", "debugger", "proxy", "webRequestBlocking", "cookies"}


def _detect_windows_default_browser_prog_id() -> str:
    if sys.platform != "win32":
        return ""
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice",
        ) as key:
            val = winreg.QueryValueEx(key, "ProgId")[0]
            return str(val or "")
    except Exception:
        return ""


CHROMIUM_USER_DATA_PATHS: dict[str, str] = {
    "chrome": r"Google\Chrome\User Data",
    "edge": r"Microsoft\Edge\User Data",
    "brave": r"BraveSoftware\Brave-Browser\User Data",
    "vivaldi": r"Vivaldi\User Data",
    "opera": r"Opera Software\Opera Stable",
    "qqbrowser": r"Tencent\QQBrowser\User Data",
    "360chrome": r"360Chrome\Chrome\User Data",
    "360se": r"360se6\User Data",
}


def resolve_chromium_profiles_and_state(
    browser_id: str,
    user_data_dir: Path | None = None,
) -> dict[str, Any]:
    """Parse Chromium `Local State` and per-profile `Preferences` in read-only mode."""
    local_app = os.environ.get("LOCALAPPDATA", "")
    if user_data_dir is None:
        rel = CHROMIUM_USER_DATA_PATHS.get(browser_id.lower())
        if not rel or not local_app:
            return {"status": "unavailable", "profiles": []}
        user_data_dir = Path(local_app) / rel

    if not user_data_dir.is_dir():
        return {"status": "not_found", "profiles": []}

    info_cache: dict[str, Any] = {}
    local_state_path = user_data_dir / "Local State"
    if local_state_path.is_file() and local_state_path.stat().st_size <= 8 * 1024 * 1024:
        try:
            ls_data = json.loads(local_state_path.read_text(encoding="utf-8", errors="ignore"))
            info_cache = (ls_data.get("profile") or {}).get("info_cache") or {}
        except Exception:
            info_cache = {}

    candidate_dirs: list[str] = []
    if info_cache:
        candidate_dirs = [k for k in info_cache.keys() if (user_data_dir / k).is_dir()]
    else:
        if (user_data_dir / "Default").is_dir():
            candidate_dirs.append("Default")
        try:
            for child in sorted(user_data_dir.iterdir()):
                if child.is_dir() and re.fullmatch(r"Profile \d+", child.name):
                    candidate_dirs.append(child.name)
        except OSError:
            pass

    profiles_out: list[dict[str, Any]] = []
    for idx, folder_name in enumerate(candidate_dirs[:16], 1):
        prof_dir = user_data_dir / folder_name
        prefs_file = prof_dir / "Preferences"
        restore_on_startup: int | None = None
        exit_type: str = "Normal"
        ext_dir = prof_dir / "Extensions"
        has_extensions_dir = ext_dir.is_dir()

        if prefs_file.is_file() and prefs_file.stat().st_size <= 16 * 1024 * 1024:
            try:
                prefs = json.loads(prefs_file.read_text(encoding="utf-8", errors="ignore"))
                restore_on_startup = (prefs.get("session") or {}).get("restore_on_startup")
                exit_type = str((prefs.get("profile") or {}).get("exit_type", "Normal"))
            except Exception:
                pass

        session_restore_risk = (restore_on_startup == 1) or (exit_type.lower() == "crashed")

        profiles_out.append({
            "profile_alias": f"profile_{idx}",
            "internal_dir_name": folder_name,
            "extensions_dir_exists": has_extensions_dir,
            "extensions_dir_path": str(ext_dir) if has_extensions_dir else None,
            "restore_on_startup_mode": restore_on_startup,
            "last_exit_type": exit_type,
            "auto_session_restore_risk": session_restore_risk,
            "safe_launch_flags": [
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-session-crashed-bubble",
                "--new-window",
            ],
        })

    return {
        "status": "observed",
        "browser_id": browser_id,
        "profiles_count": len(profiles_out),
        "profiles": profiles_out,
    }


def resolve_firefox_profiles_and_extensions(firefox_roaming_dir: Path | None = None) -> dict[str, Any]:
    """Parse Firefox `profiles.ini` and per-profile `extensions.json` in read-only mode."""
    roaming = os.environ.get("APPDATA", "")
    if firefox_roaming_dir is None:
        if not roaming:
            return {"status": "unavailable", "profiles": []}
        firefox_roaming_dir = Path(roaming) / r"Mozilla\Firefox"

    ini_path = firefox_roaming_dir / "profiles.ini"
    if not ini_path.is_file():
        return {"status": "not_found", "profiles": []}

    cp = configparser.ConfigParser()
    try:
        cp.read(ini_path, encoding="utf-8")
    except Exception:
        return {"status": "error", "profiles": []}

    profiles_out: list[dict[str, Any]] = []
    idx = 0
    for sec in cp.sections():
        if not sec.startswith("Profile"):
            continue
        idx += 1
        is_rel = cp.get(sec, "IsRelative", fallback="1") == "1"
        raw_path = cp.get(sec, "Path", fallback="")
        if not raw_path:
            continue
        pdir = (firefox_roaming_dir / raw_path) if is_rel else Path(raw_path)
        ext_json = pdir / "extensions.json"
        addon_count = 0
        if ext_json.is_file() and ext_json.stat().st_size <= 8 * 1024 * 1024:
            try:
                edata = json.loads(ext_json.read_text(encoding="utf-8", errors="ignore"))
                addon_count = len(edata.get("addons") or [])
            except Exception:
                pass
        profiles_out.append({
            "profile_alias": f"profile_{idx}",
            "internal_dir_name": pdir.name,
            "profile_dir_path": str(pdir),
            "extensions_json_exists": ext_json.is_file(),
            "addons_count": addon_count,
            "auto_session_restore_risk": False,
            "safe_launch_flags": [
                "--new-window",
            ],
        })
    return {"status": "observed", "browser_id": "firefox", "profiles_count": len(profiles_out), "profiles": profiles_out}


def _count_safe_profile_aliases(browser_id: str) -> list[str]:
    """Count local profiles and return privacy-safe aliases (e.g., ['profile_1', 'profile_2'])."""
    bid = browser_id.lower()
    if bid in CHROMIUM_USER_DATA_PATHS or bid in ("chrome", "edge", "brave", "vivaldi", "opera", "qqbrowser", "360chrome"):
        cres = resolve_chromium_profiles_and_state(bid)
        if cres.get("profiles"):
            return [p["profile_alias"] for p in cres["profiles"]]
    elif bid == "firefox":
        fres = resolve_firefox_profiles_and_extensions()
        if fres.get("profiles"):
            return [p["profile_alias"] for p in fres["profiles"]]
    return ["profile_1"]


def enumerate_browsers(
    *,
    portable_paths: list[str] | None = None,
    skipped_browser_ids: list[str] | None = None,
    consent_manager: ConsentManager | None = None,
    mock_browsers: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Enumerate installed and portable browsers with engine, version, category, and profile aliases (Layer B08)."""
    cm = consent_manager or GLOBAL_CONSENT_MANAGER
    if not cm.is_granted("tier1_browser_discovery"):
        return {
            "captured_at_utc": utc_now(),
            "status": "permission_required",
            "error": "tier1_browser_discovery_consent_required",
            "browsers": [],
        }

    skipped_set = {str(x).lower().strip() for x in (skipped_browser_ids or [])}

    if mock_browsers is not None:
        items = []
        for b in mock_browsers:
            bid = str(b.get("id", "unknown")).lower()
            is_skipped = bid in skipped_set or bool(b.get("user_skipped"))
            items.append({
                "id": bid,
                "name": b.get("name", bid),
                "engine": b.get("engine", "Chromium"),
                "category": b.get("category", "mainstream"),
                "version": b.get("version", ""),
                "is_default_https": bool(b.get("is_default_https")),
                "portable": bool(b.get("portable")),
                "profile_aliases": b.get("profile_aliases") or ["profile_1"],
                "user_skipped": is_skipped,
                "assessment_state": "skipped_by_user" if is_skipped else "discovered_static_only",
            })
        return {
            "captured_at_utc": utc_now(),
            "synthetic": True,
            "vantage": inspect_host_identity(mock_windows_host={"major": 10, "build": 26200, "arch": "x64"}),
            "status": "observed",
            "total_discovered": len(items),
            "eligible_for_assessment": sum(1 for x in items if not x["user_skipped"]),
            "skipped_count": sum(1 for x in items if x["user_skipped"]),
            "browsers": items,
        }

    discovered: dict[str, dict[str, Any]] = {}
    default_prog_id = _detect_windows_default_browser_prog_id().lower()

    if sys.platform == "win32":
        import winreg
        roots = [
            os.environ.get("ProgramFiles", r"C:\Program Files"),
            os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
            os.environ.get("LOCALAPPDATA", ""),
            os.environ.get("APPDATA", ""),
        ]
        for entry in BROWSER_CATALOG:
            bid = entry["id"]
            exe = entry["exe"]
            found_path: str | None = None

            # 1. Check App Paths registry
            for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
                    try:
                        with winreg.OpenKey(
                            hive,
                            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\\" + exe,
                            0,
                            winreg.KEY_READ | view,
                        ) as k:
                            val = winreg.QueryValueEx(k, "")[0]
                            if isinstance(val, str) and Path(val.strip('"')).is_file():
                                found_path = val.strip('"')
                                break
                    except OSError:
                        continue
                if found_path:
                    break

            # 2. Check fixed relative paths under standard program directories
            if not found_path:
                for root in roots:
                    if not root:
                        continue
                    for rel in entry["rel_paths"]:
                        cand = Path(root) / rel
                        try:
                            if cand.is_file():
                                found_path = str(cand)
                                break
                        except OSError:
                            continue
                    if found_path:
                        break

            # 3. Check PATH
            if not found_path:
                w = shutil.which(exe)
                if w and Path(w).is_file():
                    found_path = w

            if found_path:
                ver = file_version(found_path) or ""
                is_def = (
                    (bid == "chrome" and "chrome" in default_prog_id)
                    or (bid == "edge" and "msedge" in default_prog_id)
                    or (bid == "firefox" and "firefox" in default_prog_id)
                    or (bid in default_prog_id)
                )
                is_skipped = bid in skipped_set
                prof_info: dict[str, Any] = {}
                if bid in CHROMIUM_USER_DATA_PATHS or bid in ("chrome", "edge", "brave", "vivaldi", "opera", "qqbrowser", "360chrome"):
                    prof_info = resolve_chromium_profiles_and_state(bid)
                elif bid == "firefox":
                    prof_info = resolve_firefox_profiles_and_extensions()

                profiles_list = prof_info.get("profiles", [])
                aliases = [p["profile_alias"] for p in profiles_list] if profiles_list else ["profile_1"]
                discovered[bid] = {
                    "id": bid,
                    "name": entry["name"],
                    "engine": entry["engine"],
                    "category": entry["category"],
                    "version": ver,
                    "exe_path": found_path,
                    "is_default_https": is_def,
                    "portable": False,
                    "profile_aliases": aliases,
                    "profiles": profiles_list,
                    "actual_profile_verified": bool(profiles_list),
                    "user_skipped": is_skipped,
                    "assessment_state": "skipped_by_user" if is_skipped else "discovered_static_only",
                }

    # Check user-supplied portable browser paths (cross-platform safe)
    for idx, raw_p in enumerate((portable_paths or [])[:8], 1):
        try:
            p = Path(raw_p).resolve()
            if p.is_file():
                bid = f"portable_{idx}_{p.stem.lower()}"
                is_skipped = bid in skipped_set or "portable" in skipped_set
                discovered[bid] = {
                    "id": bid,
                    "name": f"便携版浏览器 ({p.name})",
                    "engine": "Chromium" if "firefox" not in p.name.lower() else "Gecko",
                    "category": "portable",
                    "version": file_version(str(p)) or "",
                    "is_default_https": False,
                    "portable": True,
                    "profile_aliases": ["profile_portable_1"],
                    "user_skipped": is_skipped,
                    "assessment_state": "skipped_by_user" if is_skipped else "discovered_static_only",
                }
        except OSError:
            continue

    items = list(discovered.values())
    return {
        "captured_at_utc": utc_now(),
        "synthetic": False,
        "vantage": inspect_host_identity(),
        "status": "observed" if sys.platform == "win32" or items else "unsupported_on_non_windows",
        "total_discovered": len(items),
        "eligible_for_assessment": sum(1 for x in items if not x["user_skipped"]),
        "skipped_count": sum(1 for x in items if x["user_skipped"]),
        "browsers": items,
    }


def inspect_browser_extensions(
    *,
    browser_id: str = "chrome",
    profile_alias: str = "profile_1",
    extensions_dir: str | None = None,
    consent_manager: ConsentManager | None = None,
    mock_extensions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Read-only audit of browser extension manifest permissions (Layer B10, Tier 3).

    Inspects ONLY `manifest.json` permission arrays (`permissions`, `host_permissions`).
    Never reads extension local storage, cookies, or user browsing history.
    """
    cm = consent_manager or GLOBAL_CONSENT_MANAGER
    if mock_extensions is None and not cm.is_granted("tier3_browser_extensions"):
        return {
            "captured_at_utc": utc_now(),
            "browser_id": browser_id,
            "profile_alias": profile_alias,
            "status": "permission_required",
            "error": "tier3_browser_extensions_consent_required",
            "message": "扫描浏览器扩展权限摘要需要授予 Tier 3（tier3_browser_extensions）权限。",
        }

    dir_verified = False
    raw_list: list[dict[str, Any]] = []
    resolved_ext_dir = extensions_dir

    if mock_extensions is not None:
        raw_list = list(mock_extensions)
        dir_verified = True
    else:
        bid = browser_id.lower()
        if resolved_ext_dir is None:
            if bid in CHROMIUM_USER_DATA_PATHS or bid in ("chrome", "edge", "brave", "vivaldi", "opera", "qqbrowser", "360chrome"):
                pinfo = resolve_chromium_profiles_and_state(bid)
                target_prof = next((p for p in pinfo.get("profiles", []) if p["profile_alias"] == profile_alias), None)
                if not target_prof and pinfo.get("profiles"):
                    target_prof = pinfo["profiles"][0]
                if target_prof and target_prof.get("extensions_dir_path"):
                    resolved_ext_dir = target_prof["extensions_dir_path"]

        if resolved_ext_dir:
            ext_root = Path(resolved_ext_dir)
            if ext_root.is_dir():
                dir_verified = True
                for ext_id_dir in sorted(ext_root.iterdir())[:64]:
                    if not ext_id_dir.is_dir():
                        continue
                    for ver_dir in sorted(ext_id_dir.iterdir(), reverse=True)[:2]:
                        manifest_file = ver_dir / "manifest.json"
                        if manifest_file.is_file() and manifest_file.stat().st_size <= 262144:
                            try:
                                m = json.loads(manifest_file.read_text(encoding="utf-8", errors="ignore"))
                                perms = [str(x) for x in (m.get("permissions") or []) if isinstance(x, str)]
                                host_perms = [str(x) for x in (m.get("host_permissions") or []) if isinstance(x, str)]
                                raw_list.append({
                                    "extension_alias": f"ext_{len(raw_list) + 1}",
                                    "manifest_version": m.get("manifest_version", 2),
                                    "permissions": perms[:32],
                                    "host_permissions": host_perms[:32],
                                    "sideloaded_or_unpacked": "update_url" not in m,
                                })
                            except Exception:
                                pass
                            break
        elif bid == "firefox":
            fres = resolve_firefox_profiles_and_extensions()
            target_fprof = next((p for p in fres.get("profiles", []) if p["profile_alias"] == profile_alias), None)
            if not target_fprof and fres.get("profiles"):
                target_fprof = fres["profiles"][0]
            if target_fprof and target_fprof.get("extensions_json_exists"):
                dir_verified = True
                pdir = Path(target_fprof["profile_dir_path"])
                ext_json = pdir / "extensions.json"
                if ext_json.is_file() and ext_json.stat().st_size <= 8 * 1024 * 1024:
                    try:
                        edata = json.loads(ext_json.read_text(encoding="utf-8", errors="ignore"))
                        for addon in (edata.get("addons") or [])[:64]:
                            if addon.get("type") in ("extension", None):
                                perms = [str(x) for x in (addon.get("userPermissions", {}).get("permissions") or []) if isinstance(x, str)]
                                host_perms = [str(x) for x in (addon.get("userPermissions", {}).get("origins") or []) if isinstance(x, str)]
                                raw_list.append({
                                    "extension_alias": f"ext_{len(raw_list) + 1}",
                                    "manifest_version": addon.get("manifestVersion", 2),
                                    "permissions": perms[:32],
                                    "host_permissions": host_perms[:32],
                                    "sideloaded_or_unpacked": not bool(addon.get("signedState", 1)),
                                })
                    except Exception:
                        pass

    high_risk_count = 0
    proxy_or_debugger_count = 0
    sideloaded_count = 0
    summarized: list[dict[str, Any]] = []

    for idx, item in enumerate(raw_list[:64], 1):
        perms = set(item.get("permissions") or []) | set(item.get("host_permissions") or [])
        broad_host = bool(perms & {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"})
        has_debugger_or_proxy = bool(perms & {"debugger", "proxy", "webRequestBlocking"})
        sideloaded = bool(item.get("sideloaded_or_unpacked"))
        if broad_host and has_debugger_or_proxy:
            high_risk_count += 1
        if has_debugger_or_proxy:
            proxy_or_debugger_count += 1
        if sideloaded:
            sideloaded_count += 1
        summarized.append({
            "extension_alias": item.get("extension_alias") or f"ext_{idx}",
            "manifest_version": item.get("manifest_version", 3),
            "has_broad_host_access": broad_host,
            "has_debugger_or_proxy_permission": has_debugger_or_proxy,
            "sideloaded_or_unpacked": sideloaded,
            "matched_sensitive_permissions": sorted(perms & HIGH_RISK_PERMISSIONS),
        })

    return {
        "captured_at_utc": utc_now(),
        "synthetic": mock_extensions is not None,
        "browser_id": browser_id,
        "profile_alias": profile_alias,
        "status": "observed",
        "extensions_dir_verified": dir_verified,
        "extensions_dir_path": str(resolved_ext_dir) if resolved_ext_dir else None,
        "total_extensions_scanned": len(summarized),
        "high_risk_permission_combo_count": high_risk_count,
        "proxy_or_debugger_extension_count": proxy_or_debugger_count,
        "sideloaded_or_unpacked_count": sideloaded_count,
        "extensions_summary": summarized,
        "privacy_note": "仅统计扩展声明的权限类别与安装来源，未读取扩展名称、个人浏览记录或扩展内部存储。",
    }
