"""CI source-contract routing; no network and no runtime scan."""
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from .verify_ci import verify


class SourceContract(unittest.TestCase):
    def fixture(self, directory, version='3.6.0-beta.1'):
        root=Path(directory)
        (root/'public-manifest.json').write_text(json.dumps({'version':version,'files':[]}),encoding='utf-8')
        return root

    def test_development_is_not_labeled_as_exact_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root=self.fixture(directory)
            with patch('public_build.verify_candidate_v37.verify',return_value={'scope':'explicit_development_sources_privacy_and_content_boundary','release_manifest_verified_for_v37':False}) as gate:
                result=verify(root,'3.7.0-dev1')
            gate.assert_called_once_with(root)
            self.assertFalse(result['release_manifest_verified_for_v37'])

    def test_legacy_release_still_requires_exact_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root=self.fixture(directory)
            with patch('public_build.release_guard.audit_tree',return_value={'status':'passed','files':{}}) as gate:
                result=verify(root,'3.6.0-beta.1')
            gate.assert_called_once()
            self.assertEqual(gate.call_args.args[1]['version'],'3.6.0-beta.1')
            self.assertEqual(result['scope'],'exact_release_source_manifest')

    def test_unknown_versions_cannot_silently_skip_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root=self.fixture(directory)
            with self.assertRaises(ValueError):verify(root,'3.7.0-stable')
            with self.assertRaises(ValueError):verify(root,'4.0')

    def test_changed_development_manifest_cannot_select_candidate_exemption(self):
        with tempfile.TemporaryDirectory() as directory:
            root=self.fixture(directory,'3.7.0-dev1')
            with self.assertRaises(ValueError):verify(root,'3.7.0-dev1')
