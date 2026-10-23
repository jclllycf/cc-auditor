"""CC Auditor Agent Toolkit (v2.0) — Zero-Anthropic-Contact Preflight Core & MCP Server.

This subpackage extends CC Environment Auditor v1.4 into an Agent-Native preflight toolkit
while preserving all original v1.4 files and their SHA-256 fingerprints byte-for-byte.
"""
from __future__ import annotations

from cc_auditor.toolkit.psutil_compat import ensure_runtime_compat
ensure_runtime_compat()

TOOLKIT_VERSION = "2.1.0"
TOOLKIT_SCHEMA = "cc-auditor-agent-toolkit/2.1"
SCORING_MODEL_VERSION = "2026-10-18.v2.1"
POLICY_SNAPSHOT_DATE = "2026-05-12"
RULESET_REVIEWED_DATE = "2026-10-18"
