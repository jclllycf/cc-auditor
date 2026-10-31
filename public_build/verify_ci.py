"""Select a declared source contract; development checks are not release checks."""
from __future__ import annotations

import json
from pathlib import Path


def verify(root, version):
    root = Path(root)
    manifest = json.loads((root/'public-manifest.json').read_text('utf-8'))
    if version == '3.7.0-dev1' and manifest.get('version') == '3.6.0-beta.1':
        from .verify_candidate_v37 import verify as candidate_verify
        return candidate_verify(root)
    if version == manifest.get('version') and version == '3.6.0-beta.1':
        from .release_guard import audit_tree
        result = audit_tree(root, manifest, git_checkout=True)
        result.pop('files', None)
        return {**result, 'scope': 'exact_release_source_manifest', 'version': version}
    raise ValueError('undeclared_source_contract')


def main():
    from cc_auditor.toolkit.preflight_v3 import VERSION
    print(json.dumps(verify(Path(__file__).resolve().parents[1],VERSION),indent=2))


if __name__ == '__main__':
    main()
