"""Bounded report storage. Local integrity hashes are not provider attestation."""
from __future__ import annotations
import hashlib
import json
import math
import os
import re
import stat
from datetime import datetime
from pathlib import Path
from . import SCHEMA
from .catalog import SOURCES, STATUSES, checklist, source
from .model import Config, canonical, root_dir

MAX_REPORT = 2 * 1024 * 1024
REPORT_KEYS = {"schema", "version", "run_id", "started_at_utc", "finished_at_utc", "duration_ms", "state", "source_sha256", "config", "evidence", "samples", "coverage", "outcomes", "limitations", "checklist_states", "synthetic"}
EVIDENCE_KEYS = {"id", "title", "status", "kind", "value", "explanation", "confidence", "source", "captured_at_utc", "limitations"}
VALUE_KEYS = {
    "host": {"os", "python", "architecture_bits", "logical_cpus", "psutil", "ssl"},
    "installation": {"cli_located", "binary_file_version", "shells", "executed_cli"},
    "api_environment": {"sdk_in_auditor_runtime", "variable_presence", "sdk_initialized"},
    "process": {"samples", "valid_samples", "attribution"}, "connections": {"valid_samples"},
    "connectivity": {"error", "destination", "tls_version", "certificate_verified", "duration_ms", "dns_result_count", "http_request_sent", "authenticated"},
    "checklist": {"items", "states"}, "browser_import": {"schema", "captured_at_utc", "browser_family", "platform_family", "features", "preferences_included", "languages", "timezone", "claude_origin_observed", "synthetic"},
    "browser": set(), "history": set(), "tracing": set(), "integrations": set(), "authenticated": set(),
}
SAMPLE_KEYS = {"status", "error", "candidate_count", "target_count", "groups", "children", "rss_mb", "cpu_capacity_percent", "cpu_matched_processes", "resource_processes", "established_count", "connection_classes", "errors", "unattributed_count", "elapsed_ms", "captured_at_utc"}

def no_reparse(path):
    p = Path(path)
    if not p.exists() and not p.is_symlink(): return
    info = p.lstat()
    if p.is_symlink() or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024):
        raise ValueError("reparse_path_rejected")
    if p.is_file() and info.st_nlink != 1:
        raise ValueError("hardlink_rejected")

def safe_dir(path):
    path = Path(path).absolute()
    for part in [*reversed(path.parents), path]:
        no_reparse(part)
    path.mkdir(parents=True, exist_ok=True)
    no_reparse(path)
    return path

def bounded(value, depth=0):
    if depth > 12: raise ValueError("report_too_deep")
    if value is None or type(value) is bool: return
    if type(value) in (int, float):
        if not math.isfinite(value) or abs(value) > 10**14: raise ValueError("invalid_number")
    elif type(value) is str:
        if len(value) > 4096 or any(ord(x) < 32 and x not in "\n\t\r" for x in value): raise ValueError("invalid_text")
    elif type(value) is list:
        if len(value) > 2000: raise ValueError("report_too_large")
        for x in value: bounded(x, depth+1)
    elif type(value) is dict:
        if len(value) > 80 or any(type(k) is not str for k in value): raise ValueError("invalid_object")
        for k, v in value.items():
            if k.lower() in {"token", "password", "api_key", "cookie", "authorization", "prompt", "cmdline", "commandline", "transcript", "card_number", "raw_body", "raw_headers"}: raise ValueError("sensitive_field_rejected")
            bounded(k, depth+1); bounded(v, depth+1)
    else: raise ValueError("invalid_type")

def timestamp(value):
    if type(value) is not str or len(value) > 40: raise ValueError("invalid_timestamp")
    try: dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError: raise ValueError("invalid_timestamp") from None
    if dt.tzinfo is None: raise ValueError("missing_timezone")

def validate_report(r):
    bounded(r)
    if type(r) is not dict or set(r) != REPORT_KEYS or r["schema"] != SCHEMA: raise ValueError("unsupported_schema")
    if not re.fullmatch("[a-f0-9]{32}", r["run_id"]) or not re.fullmatch("[a-f0-9]{64}", r["source_sha256"]): raise ValueError("invalid_identity")
    if not re.fullmatch(r"\d+\.\d+\.\d+", r["version"]): raise ValueError("invalid_version")
    timestamp(r["started_at_utc"]); timestamp(r["finished_at_utc"])
    if r["state"] not in ("completed", "partial", "cancelled") or type(r["synthetic"]) is not bool: raise ValueError("invalid_run_state")
    if type(r["duration_ms"]) is not int or not 0 <= r["duration_ms"] <= 600000: raise ValueError("invalid_duration")
    expected_config = set(Config.__dataclass_fields__)
    if type(r["config"]) is not dict or set(r["config"]) != expected_config: raise ValueError("invalid_config")
    Config(**r["config"]).validate()
    if type(r["evidence"]) is not list or len(r["evidence"]) > 24: raise ValueError("invalid_evidence")
    if any(type(r[k]) is not list or any(type(v) is not str for v in r[k]) for k in ("limitations",)):
        raise ValueError("invalid_limitations")
    seen=set()
    for item in r["evidence"]:
        if type(item) is not dict or set(item) != EVIDENCE_KEYS or item["id"] not in VALUE_KEYS: raise ValueError("invalid_evidence")
        if item["status"] not in STATUSES or item["confidence"] not in ("high", "medium", "unknown"): raise ValueError("invalid_evidence_status")
        if item["kind"] not in ("local_observation", "documented", "unknown", "user_supplied"): raise ValueError("invalid_evidence_kind")
        if item["id"] in seen: raise ValueError("duplicate_evidence")
        seen.add(item["id"])
        if type(item["title"]) is not str or type(item["explanation"]) is not str or type(item["limitations"]) is not list or any(type(x) is not str for x in item["limitations"]): raise ValueError("invalid_evidence_text")
        src = item["source"]
        if type(src) is not dict or src.get("id") not in SOURCES or src != source(src["id"]): raise ValueError("untrusted_source")
        timestamp(item["captured_at_utc"])
        val = item["value"]
        if val is not None:
            if type(val) is not dict: raise ValueError("invalid_evidence_value")
            if val=={"error":"collector_failed"} and item["status"]=="error": continue
            if not set(val) <= VALUE_KEYS[item["id"]]: raise ValueError("invalid_evidence_value")
            if item["id"] == "browser_import": validate_browser(val)
            if item["id"] == "checklist" and val.get("items") != checklist(r["config"]["surface"], r["config"]["phase"]): raise ValueError("invalid_checklist")
            if item["id"] == "installation" and val.get("executed_cli") is not False: raise ValueError("invalid_execution_claim")
            if item["id"] == "api_environment" and val.get("sdk_initialized") is not False: raise ValueError("invalid_sdk_claim")
            if item["id"] == "api_environment":
                flags=val.get("variable_presence")
                allowed={"ANTHROPIC_API_KEY","ANTHROPIC_BASE_URL","HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","CLAUDE_CODE_ENABLE_TELEMETRY","OTEL_EXPORTER_OTLP_ENDPOINT"}
                if type(flags) is not dict or set(flags)!=allowed or any(type(x) is not bool for x in flags.values()): raise ValueError("invalid_presence_flags")
            if item["id"] == "connectivity":
                if "error" in val:
                    if set(val)!={"error"} or val["error"] not in {"dns_timeout","dns_failed","certificate_verification_failed","transport_failed"}: raise ValueError("invalid_transport_error")
                elif val.get("destination")!="api.anthropic.com:443" or val.get("http_request_sent") is not False or val.get("authenticated") is not False: raise ValueError("invalid_transport_claim")
    if type(r["samples"]) is not list or len(r["samples"]) > 125: raise ValueError("invalid_samples")
    for s in r["samples"]:
        if type(s) is not dict or not set(s) <= SAMPLE_KEYS or s.get("status") not in ("observed", "partial", "error"): raise ValueError("invalid_sample")
        for k in ("target_count", "candidate_count", "rss_mb", "cpu_capacity_percent", "established_count", "unattributed_count"):
            if s.get(k) is not None and (type(s[k]) not in (int,float) or s[k] < 0): raise ValueError("invalid_measurement")
        timestamp(s.get("captured_at_utc"))
        for key,allowed in (("groups",{"desktop_shell_candidate","embedded_engine_candidate","desktop_child_candidate","unattributed_engine","standalone_cli_candidate","unattributed_claude"}),("children",{"shell","node_runtime","python_runtime","git","other"}),("connection_classes",{"benchmark_or_proxy_mapping","loopback","link_local","private_or_reserved","public_unlocated","other_reserved","unclassified"})):
            if key in s and (type(s[key]) is not dict or not set(s[key])<=allowed or any(type(v) is not int or v<0 for v in s[key].values())): raise ValueError("invalid_sample_categories")
        codes={"process_query_failed","candidate_path_unavailable","resource_unavailable","connections_unavailable","snapshot_failed","snapshot_timeout","probe_unavailable","cancelled_during_snapshot"}
        if "error" in s and s["error"] not in codes: raise ValueError("invalid_sample_error")
        if "errors" in s and (type(s["errors"]) is not list or any(x not in codes for x in s["errors"])): raise ValueError("invalid_sample_errors")
    from .catalog import CAPABILITIES
    if type(r["coverage"]) is not list or len(r["coverage"])!=len(CAPABILITIES): raise ValueError("invalid_coverage")
    if {x.get("id") for x in r["coverage"] if type(x) is dict}!=set(CAPABILITIES): raise ValueError("invalid_coverage_ids")
    if any(type(x) is not dict or set(x)!={"id","status"} or x["status"] not in STATUSES for x in r["coverage"]): raise ValueError("invalid_coverage_status")
    if type(r["outcomes"]) is not dict: raise ValueError("invalid_outcomes")
    if r["outcomes"].get("policy_eligibility") != "not_assessed" or r["outcomes"].get("account_outcome") != "unknown" or r["outcomes"].get("server_decision") != "unknown":
        raise ValueError("unsupported_account_claim")
    if set(r["outcomes"]) != {"policy_eligibility", "account_outcome", "server_decision", "connectivity"} or r["outcomes"]["connectivity"] not in ("not_tested", "observer_tls_verified", "observer_probe_incomplete"): raise ValueError("invalid_outcomes")
    return r

def duplicates(pairs):
    d = {}
    for k,v in pairs:
        if k in d: raise ValueError("duplicate_key")
        d[k] = v
    return d

def read_json(path, limit=MAX_REPORT):
    p = Path(path).absolute()
    for parent in [*reversed(p.parents), p]: no_reparse(parent)
    with p.open("rb") as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit or info.st_nlink != 1: raise ValueError("file_rejected")
        raw = f.read(limit + 1)
    if len(raw) > limit: raise ValueError("file_too_large")
    try:
        return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=duplicates, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid_number")))
    except (UnicodeError, RecursionError, json.JSONDecodeError): raise ValueError("invalid_json") from None

def read_report(path):
    data = read_json(path)
    if type(data) is not dict or set(data) != {"report", "sha256"}: raise ValueError("invalid_envelope")
    r = validate_report(data["report"])
    if data["sha256"] != hashlib.sha256(canonical(r)).hexdigest(): raise ValueError("integrity_mismatch")
    return r

def report_dir(): return root_dir() / "data" / "reports"

def save_report(report, directory=None):
    validate_report(report)
    directory = safe_dir(directory or report_dir())
    from .render import render_report
    target = directory / f"{report['run_id']}.json"
    payload = {"report": report, "sha256": hashlib.sha256(canonical(report)).hexdigest()}
    raw = json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False)
    if len(raw.encode("utf-8")) > MAX_REPORT: raise ValueError("report_too_large")
    # Exclusive creation, never overwrite an original or a previous run.
    with target.open("x", encoding="utf-8") as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    html = directory / f"{report['run_id']}.html"
    with html.open("x", encoding="utf-8") as f: f.write(render_report(report))
    return target, html

def history(directory=None, limit=300):
    directory = Path(directory or report_dir())
    if not directory.exists(): return [], 0
    no_reparse(directory)
    rows, rejected = [], 0
    candidates = []
    # Bound enumerated entries too, not just parsed files.
    for idx, p in enumerate(directory.iterdir()):
        if idx >= 1500: rejected += 1; break
        if re.fullmatch(r"[a-f0-9]{32}\.json", p.name): candidates.append(p)
    total_bytes=0
    for p in sorted(candidates, key=lambda x: x.lstat().st_mtime, reverse=True)[:limit]:
        try:
            total_bytes+=p.lstat().st_size
            if total_bytes>16*1024*1024: rejected+=1; break
            rows.append(read_report(p))
        except (ValueError, OSError, TypeError, KeyError, OverflowError): rejected += 1
    return rows, rejected

BROWSER_KEYS = {"schema", "captured_at_utc", "browser_family", "platform_family", "features", "preferences_included", "languages", "timezone", "claude_origin_observed", "synthetic"}
def validate_browser(data):
    bounded(data)
    if type(data) is not dict or set(data) != BROWSER_KEYS or data["schema"] != "cc-auditor-browser/1": raise ValueError("invalid_browser_schema")
    timestamp(data["captured_at_utc"])
    if data["browser_family"] not in ("Edge", "Chrome", "Firefox", "Safari", "Other") or data["platform_family"] not in ("Windows", "macOS", "Linux", "Android", "iOS", "Other"): raise ValueError("invalid_browser_family")
    if type(data["features"]) is not dict or set(data["features"]) != {"websocket", "webassembly", "workers", "secure_context", "cookies_enabled"} or any(type(x) is not bool for x in data["features"].values()): raise ValueError("invalid_browser_features")
    if type(data["preferences_included"]) is not bool or type(data["synthetic"]) is not bool or data["claude_origin_observed"] is not False: raise ValueError("invalid_browser_claim")
    if type(data["languages"]) is not list or len(data["languages"]) > 5 or any(type(x) is not str or not re.fullmatch(r"[A-Za-z0-9-]{2,35}", x) for x in data["languages"]): raise ValueError("invalid_languages")
    if data["timezone"] is not None and (type(data["timezone"]) is not str or not re.fullmatch(r"[A-Za-z0-9_+/\-]{1,70}", data["timezone"])): raise ValueError("invalid_timezone")
    if not data["preferences_included"] and (data["languages"] or data["timezone"] is not None): raise ValueError("unconsented_preferences")
    return data
