from __future__ import annotations
import dataclasses
import hashlib
import json
import math
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from . import VERSION, SCHEMA
from .catalog import SURFACES, SUBTYPES, PHASES, CONTEXTS, ALLOWED, STATUSES, source

def utc():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")

def root_dir():
    return Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent.parent

def asset_dir():
    return Path(getattr(sys, "_MEIPASS", root_dir()))

def fingerprint():
    bundled = asset_dir() / "assets" / "source-sha256.txt"
    if getattr(sys, "frozen", False) and bundled.is_file():
        return bundled.read_text(encoding="ascii").strip()
    h = hashlib.sha256()
    for p in sorted(Path(__file__).parent.glob("*.py")):
        h.update(p.name.encode()); h.update(p.read_bytes())
    return h.hexdigest()

@dataclasses.dataclass(frozen=True)
class Config:
    surface: str = "desktop"
    subtype: str = "Code"
    phase: str = "idle"
    context: str = "unknown"
    capabilities: tuple[str, ...] = ("host", "process")
    duration: int = 10
    interval: float = 2.0
    external_consent: bool = False
    checklist_states: tuple[int, ...] = ()

    def validate(self):
        if type(self.external_consent) is not bool or type(self.capabilities) not in (tuple,list):
            raise ValueError("invalid_consent")
        if self.surface not in SURFACES or self.phase not in PHASES or self.context not in CONTEXTS:
            raise ValueError("invalid_selection")
        if self.subtype not in SUBTYPES[self.surface]:
            raise ValueError("invalid_subtype")
        if type(self.duration) is not int or not 2 <= self.duration <= 120:
            raise ValueError("invalid_duration")
        if type(self.interval) not in (int, float) or not math.isfinite(self.interval) or not 1 <= self.interval <= 10:
            raise ValueError("invalid_interval")
        if len(set(self.capabilities)) != len(self.capabilities) or not set(self.capabilities) <= ALLOWED[self.surface]:
            raise ValueError("invalid_capabilities")
        if "connections" in self.capabilities and "process" not in self.capabilities:
            raise ValueError("connections_require_process")
        if "connectivity" in self.capabilities and (not self.external_consent or self.subtype != "Direct API"):
            raise ValueError("external_probe_not_authorized")
        if any(type(x) is not int or x not in (0, 1, 2) for x in self.checklist_states) or len(self.checklist_states) > 4:
            raise ValueError("invalid_checklist")
        if self.phase in ("registration", "billing", "history") and set(self.capabilities) - {"host"}:
            raise ValueError("manual_phase_no_collectors")
        return self

def evidence(id, title, status, value=None, explanation="", source_id="data", kind="local_observation", confidence="high", limitations=()):
    if status not in STATUSES:
        raise ValueError("invalid_status")
    return {"id": id, "title": title, "status": status, "kind": kind, "value": value,
            "explanation": explanation, "confidence": confidence, "source": source(source_id),
            "captured_at_utc": utc(), "limitations": list(limitations)}

def new_report(config):
    config.validate()
    selection = dataclasses.asdict(config)
    selection["capabilities"] = list(config.capabilities)
    selection["checklist_states"] = list(config.checklist_states)
    return {"schema": SCHEMA, "version": VERSION, "run_id": uuid.uuid4().hex, "started_at_utc": utc(),
            "finished_at_utc": None, "duration_ms": 0, "state": "running", "source_sha256": fingerprint(),
            "config": selection, "evidence": [], "samples": [], "coverage": [],
            "outcomes": {"policy_eligibility": "not_assessed", "account_outcome": "unknown", "server_decision": "unknown", "connectivity": "not_tested"},
            "limitations": ["阶段和执行位置由用户声明；本工具不会启动 Claude 任务。", "本机证据不覆盖云端、SSH 或虚拟机内部行为。", "政策、文档收集类别、实际测量和账户结果分别解释。", "连接数量不能证明上传字节或通信正文。"],
            "checklist_states": list(config.checklist_states), "synthetic": False}

def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
