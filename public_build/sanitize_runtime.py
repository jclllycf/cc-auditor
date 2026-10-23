"""仅在独立发布 staging 中禁用旧版主动联网入口。

使用 AST 定位顶层函数，按原始字节行范围替换函数体；不重写其余源码。
不导入诊断模块，不运行探针，不修改研发源码。只接受没有 Git 元数据的
独立 staging；所有目标必须存在且结构正确，否则拒绝生成半清理结果。
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any


ERROR_CODE = "legacy_active_probe_disabled_in_public_preflight"
TARGETS: dict[str, tuple[str, ...]] = {
    "cc_auditor/collectors.py": ("tls_connectivity",),
    "cc_auditor/diagnostics.py": ("route_probe", "routes"),
    # 此版本没有 environment_probes.online；真实入口是下列两函数。
    # 同时禁用父入口和可单独调用的子进程函数，避免保留直连任务分发。
    "cc_auditor/environment_probes.py": ("network_checks", "_network_child"),
}


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _regular_path(path: Path, root: Path) -> None:
    """不接受可将 staging 写入导向研发文件的重解析点或硬链接。"""
    current = root
    for part in ((), *[(p,) for p in path.relative_to(root).parts]):
        if part:
            current = current / part[0]
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024):
            raise ValueError("staging_reparse_path_rejected")
    if not path.is_file() or path.stat().st_nlink != 1:
        raise ValueError("staging_nonregular_or_hardlink_rejected")


def _functions(raw: bytes, relative_path: str) -> tuple[ast.Module, dict[str, ast.FunctionDef]]:
    # ast.parse(bytes) 正确处理 UTF-8 BOM 与编码声明，同时保持原始字节供编辑。
    tree = ast.parse(raw, filename=relative_path)
    found: dict[str, ast.FunctionDef] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in TARGETS[relative_path]:
            if not isinstance(node, ast.FunctionDef) or node.name in found or node.decorator_list:
                raise ValueError("legacy_probe_definition_ambiguous")
            found[node.name] = node
    if set(found) != set(TARGETS[relative_path]):
        raise ValueError("legacy_probe_definition_missing")
    return tree, found


def _is_stub(node: ast.FunctionDef) -> bool:
    statements = list(node.body)
    if statements and isinstance(statements[0], ast.Expr) and isinstance(statements[0].value, ast.Constant) and isinstance(statements[0].value.value, str):
        statements.pop(0)
    if len(statements) != 1 or not isinstance(statements[0], ast.Raise):
        return False
    call = statements[0].exc
    return (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "PermissionError"
        and len(call.args) == 1
        and isinstance(call.args[0], ast.Constant)
        and call.args[0].value == ERROR_CODE
        and not call.keywords
        and statements[0].cause is None
    )


def sanitize_bytes(raw: bytes, relative_path: str, *, verify_only: bool = False) -> tuple[bytes, dict[str, Any]]:
    """返回清理字节及相对路径/hash回执，不做文件写入或网络访问。

    若源码版本改变到目标缺失、函数重名或同一行函数体，显式失败让维护者审查。
    已清理输入幂等；verify_only 要求所有目标已经是严格 fail-closed stub。
    """
    if relative_path not in TARGETS:
        raise ValueError("unlisted_sanitize_target")
    _, found = _functions(raw, relative_path)
    lines = raw.splitlines(keepends=True)
    changes: list[tuple[int, int, bytes, str]] = []
    newline = b"\r\n" if b"\r\n" in raw else b"\n"
    for name, node in found.items():
        if _is_stub(node):
            continue
        if verify_only:
            raise ValueError("legacy_active_probe_not_disabled")
        first = node.body[0]
        if first.lineno <= node.lineno or not node.end_lineno:
            raise ValueError("legacy_probe_inline_body_not_supported")
        first_line = lines[first.lineno - 1]
        indent = first_line[: len(first_line) - len(first_line.lstrip(b" \t"))]
        if not indent or first.col_offset <= node.col_offset:
            raise ValueError("legacy_probe_indentation_invalid")
        replacement = (
            indent + b'"""Public preflight: legacy active probe disabled."""' + newline
            + indent + b'raise PermissionError("' + ERROR_CODE.encode("ascii") + b'")' + newline
        )
        # 不增删目标函数之外的字节；包括导入、注释、空行及其他定义。
        changes.append((first.lineno - 1, node.end_lineno, replacement, name))
    for start, end, replacement, _ in sorted(changes, reverse=True):
        lines[start:end] = [replacement]
    result = b"".join(lines)
    _, verified = _functions(result, relative_path)
    if any(not _is_stub(node) for node in verified.values()):
        raise ValueError("sanitized_stub_verification_failed")
    return result, {
        "path": relative_path,
        "functions": list(TARGETS[relative_path]),
        "modified_functions": [name for _, _, _, name in changes],
        "input_sha256": _sha(raw),
        "output_sha256": _sha(result),
        "changed": result != raw,
    }


def sanitize_public_runtime(staging_root: str | Path, *, verify_only: bool = False) -> dict[str, Any]:
    """清理完整 staging，或 verify_only 校验；不接受工具自身的源码根目录。

    成功回执不含绝对路径。所有源文件先完成结构检查；发生版本漂移时不写文件。
    调用者应在干净临时目录完成 staging，再创建公开 Git 仓库。
    """
    supplied = Path(staging_root).absolute()
    if not supplied.is_dir():
        raise ValueError("staging_root_missing")
    if supplied.is_symlink() or supplied.resolve() != supplied:
        raise ValueError("staging_root_must_be_plain_absolute_directory")
    root = supplied.resolve()
    if root == Path(__file__).resolve().parents[1]:
        raise ValueError("never_sanitize_source_workspace")
    if (root / ".git").exists():
        raise ValueError("sanitize_before_git_initialization")
    planned: list[tuple[Path, bytes, bytes, dict[str, Any]]] = []
    for relative in TARGETS:
        path = root / relative
        _regular_path(path, root)
        original = path.read_bytes()
        result, receipt = sanitize_bytes(original, relative, verify_only=verify_only)
        planned.append((path, original, result, receipt))
    # 在第一笔写入前再检查一次；仅操作本工具独立 staging 的已列明文件。
    for path, original, _, _ in planned:
        _regular_path(path, root)
        if path.read_bytes() != original:
            raise ValueError("staging_changed_during_sanitization")
    if not verify_only:
        for path, original, result, _ in planned:
            if result == original:
                continue
            fd, temporary = tempfile.mkstemp(prefix=".public-sanitize-", suffix=".tmp", dir=path.parent)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(result)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
    return {
        "status": "verified" if verify_only else "sanitized",
        "schema": "cc-auditor-public-runtime-sanitization/1",
        "error_code": ERROR_CODE,
        "target_count": sum(len(names) for names in TARGETS.values()),
        "files": [receipt for _, _, _, receipt in planned],
        "network_operations": 0,
        "scope": "listed_legacy_active_probe_function_bodies_only",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="仅在独立公开 staging 禁用旧主动探针，不采集环境。")
    parser.add_argument("staging_root", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args(argv)
    print(json.dumps(sanitize_public_runtime(args.staging_root, verify_only=args.verify_only), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
