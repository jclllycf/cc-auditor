"""Audit an explicit development file set without regenerating release manifests.

The old public manifest remains the v3.6 release receipt, not the v3.7 receipt.
Untracked field-study documents, AGENTS and private artifacts are not selected.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

from .release_guard import safe_name, reviewed_findings, exceptions, sha

BASELINE = '6c4d7a2f153323248f7751853607e818695523be'
ADDITIONS = (
    'cc_auditor/toolkit/address_semantics.py',
    'cc_auditor/toolkit/effective_policy_v37.py',
    'cc_auditor/toolkit/evidence_v37.py',
    'cc_auditor/toolkit/review_v37.py',
    'tests_toolkit/test_v37_evidence.py',
    'public_build/demo_v37.py',
    'public_build/verify_candidate_v37.py',
    'docs/upgrade-v37/IMPLEMENTATION_ZH.md',
    'docs/upgrade-v37/USAGE_ZH.md',
    'docs/upgrade-v37/VALIDATION_ZH.md',
    'preview-v37.cmd',
)


def verify(root):
    from cc_auditor.storage import no_reparse
    root = Path(root).resolve()
    old = subprocess.run(['git', 'show', BASELINE + ':public-manifest.json'], cwd=root,
                         check=True, capture_output=True).stdout
    if old != (root/'public-manifest.json').read_bytes():
        raise ValueError('preserve_v36_public_manifest')
    baseline = json.loads(old)
    names = sorted({r['path'] for r in baseline['files']} | set(ADDITIONS))
    allowed = set(names)
    for path in (root/'cc_auditor/toolkit').glob('*.py'):
        if path.relative_to(root).as_posix() not in allowed:
            raise ValueError('unlisted_candidate_module')
    policy = exceptions(root)
    entries = []
    for name in names:
        safe_name(name)
        path = root/name
        no_reparse(path)
        if not path.is_file() or path.stat().st_nlink != 1:
            raise ValueError('unsafe_or_missing_candidate_file:' + name)
        raw = path.read_bytes()
        findings = reviewed_findings(name, raw, policy)
        if findings:
            raise ValueError(json.dumps(findings, ensure_ascii=True))
        entries.append({'path': name, 'sha256': sha(raw)})
    return {'status': 'passed', 'scope': 'explicit_development_sources_privacy_and_content_boundary',
            'version': '3.7.0-dev1', 'baseline': BASELINE, 'file_count': len(entries),
            'candidate_files_sha256': sha(json.dumps(entries, sort_keys=True).encode('utf-8')),
            'v36_manifest_unchanged': True, 'release_manifest_verified_for_v37': False,
            'excluded': ['AGENTS.md', 'docs/field-study-20261031', 'scratch', 'data', 'private_local_evidence'],
            'note': 'Development source boundary only. This is not EXE, release, CI or real-host acceptance.'}


def main():
    if hasattr(sys.stdout, 'reconfigure'):sys.stdout.reconfigure(encoding='utf-8')
    print(json.dumps(verify(Path(__file__).resolve().parents[1]), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
