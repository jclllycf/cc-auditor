"""公开清理器的离线负例测试；不导入或调用任何诊断模块。"""
import ast
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from public_build.sanitize_runtime import ERROR_CODE, TARGETS, sanitize_bytes, sanitize_public_runtime


def fixture(relative: str, newline: bytes = b"\n") -> bytes:
    text = '# coding: utf-8\n# untouched 中文\nSENTINEL = "unchanged"\n\n'
    for name in TARGETS[relative]:
        text += f'def {name}(*args, **kwargs):\n    """old active body"""\n    raise AssertionError("must never run")\n\n'
    text += '# untouched tail 注释\ndef kept():\n    return SENTINEL\n'
    return text.encode("utf-8").replace(b"\n", newline)


class RuntimeSanitizerTests(unittest.TestCase):
    def test_stubs_raise_before_any_call_and_keep_other_bytes(self):
        for relative in TARGETS:
            for ending in (b"\n", b"\r\n"):
                with self.subTest(relative=relative, ending=ending):
                    raw = fixture(relative, ending)
                    result, receipt = sanitize_bytes(raw, relative)
                    self.assertTrue(result.startswith(raw.split(b"def ", 1)[0]))
                    self.assertEqual(result.split(b"# untouched tail", 1)[1], raw.split(b"# untouched tail", 1)[1])
                    namespace = {}
                    with patch("socket.socket", side_effect=AssertionError("network forbidden")), patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")):
                        exec(compile(result, relative, "exec"), namespace)
                        for name in TARGETS[relative]:
                            with self.assertRaisesRegex(PermissionError, ERROR_CODE):
                                namespace[name](None, anything=True)
                    self.assertEqual(namespace["kept"](), "unchanged")
                    self.assertEqual(len(receipt["modified_functions"]), len(TARGETS[relative]))

    def test_strict_verification_and_idempotence(self):
        for relative in TARGETS:
            with self.assertRaisesRegex(ValueError, "not_disabled"):
                sanitize_bytes(fixture(relative), relative, verify_only=True)
            result, _ = sanitize_bytes(fixture(relative), relative)
            again, receipt = sanitize_bytes(result, relative, verify_only=True)
            self.assertEqual(again, result)
            self.assertFalse(receipt["changed"])
            self.assertEqual(receipt["input_sha256"], receipt["output_sha256"])

    def test_missing_duplicate_decorated_or_inline_definition_rejected(self):
        relative = "cc_auditor/collectors.py"
        bad = [b"def other():\n    pass\n", b"def tls_connectivity():\n    pass\ndef tls_connectivity():\n    pass\n", b"@deco\ndef tls_connectivity():\n    pass\n", b"def tls_connectivity(): pass\n"]
        for raw in bad:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                sanitize_bytes(raw, relative)

    def test_unlisted_path_rejected(self):
        with self.assertRaisesRegex(ValueError, "unlisted"):
            sanitize_bytes(b"", "cc_auditor/private.py")

    def test_prevalidation_does_not_partially_modify_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            originals = {}
            for relative in TARGETS:
                path = root / relative
                path.parent.mkdir(exist_ok=True, parents=True)
                originals[path] = fixture(relative)
                path.write_bytes(originals[path])
            last = root / list(TARGETS)[-1]
            last.write_text("# unexpected source version\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "missing"):
                sanitize_public_runtime(root)
            for path, raw in originals.items():
                if path != last:
                    self.assertEqual(path.read_bytes(), raw)

    def test_owned_staging_receipt_has_no_absolute_paths_and_verifies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for relative in TARGETS:
                path = root / relative
                path.parent.mkdir(exist_ok=True, parents=True)
                path.write_bytes(fixture(relative))
            receipt = sanitize_public_runtime(root)
            self.assertEqual(receipt["target_count"], 5)
            self.assertEqual(receipt["network_operations"], 0)
            self.assertTrue(all(not Path(item["path"]).is_absolute() for item in receipt["files"]))
            checked = sanitize_public_runtime(root, verify_only=True)
            self.assertEqual(checked["status"], "verified")
            self.assertTrue(all(not item["changed"] for item in checked["files"]))

    def test_source_workspace_and_git_initialized_tree_rejected(self):
        with self.assertRaisesRegex(ValueError, "never_sanitize_source"):
            sanitize_public_runtime(Path(__file__).resolve().parents[1])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / ".git").mkdir()
            with self.assertRaisesRegex(ValueError, "before_git"):
                sanitize_public_runtime(root)

    def test_real_legacy_targets_are_replaced_without_executing_them(self):
        source = Path(__file__).resolve().parents[1]
        for relative, names in TARGETS.items():
            raw = (source / relative).read_bytes()
            result, receipt = sanitize_bytes(raw, relative)
            original_tree = ast.parse(raw)
            result_tree = ast.parse(result)
            original_defs = {n.name: ast.dump(n, include_attributes=False) for n in original_tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
            result_defs = {n.name: ast.dump(n, include_attributes=False) for n in result_tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
            self.assertEqual(set(original_defs), set(result_defs))
            for name in original_defs.keys() - set(names):
                self.assertEqual(original_defs[name], result_defs[name])
            self.assertEqual(set(receipt["functions"]), set(names))


if __name__ == "__main__":
    unittest.main()

