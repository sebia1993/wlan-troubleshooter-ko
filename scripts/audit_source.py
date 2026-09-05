#!/usr/bin/env python3
"""Fail-closed static checks for code that must remain fully offline.

The audit intentionally excludes only this exact file.  The implementation
contains the forbidden names it searches for, so scanning itself would create
false positives.  A different file with the same name is still audited.
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
import os
from pathlib import Path
import re
import sys
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

try:
    import tomllib as _tomllib
except ImportError:  # Python 3.9 fallback is intentionally dependency-free.
    _tomllib = None


_SELF_PATH = Path(__file__).resolve()

_SOURCE_SUFFIXES = {
    ".bat",
    ".cjs",
    ".cmd",
    ".css",
    ".htm",
    ".html",
    ".js",
    ".json",
    ".jsx",
    ".lua",
    ".mjs",
    ".ps1",
    ".py",
    ".pyw",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
}

_SKIPPED_CACHE_DIRECTORIES = {
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
}

# Tests intentionally contain forbidden canaries.  Only the repository's exact
# top-level tests/ tree is excluded; a src/tests/ or app/tests/ directory remains
# in scope so production code cannot hide behind a common directory name.
_SKIPPED_TOP_LEVEL_DIRECTORIES = {".git", ".venv", "build", "dist", "tests", "venv"}

_OWN_RUNTIME_PACKAGES = {"wlan_troubleshooter_ko"}

# Runtime imports are an exact, reviewed subset rather than every stdlib module.
# This keeps network-capable or side-effectful modules such as antigravity,
# multiprocessing.connection and wsgiref unavailable unless the policy itself
# is deliberately reviewed and changed.
_APPROVED_RUNTIME_STDLIB_MODULES = frozenset({
    "__future__",
    "argparse",
    "dataclasses",
    "hashlib",
    "hmac",
    "html",
    "ipaddress",
    "json",
    "math",
    "os",
    "pathlib",
    "re",
    "stat",
    "struct",
    "subprocess",
    "tempfile",
    "threading",
    "time",
    "tkinter",
    "typing",
    "unicodedata",
})

_FORBIDDEN_MODULES = (
    "aiohttp",
    "anthropic",
    "boto3",
    "botocore",
    "ftplib",
    "google.cloud",
    "http",
    "httpx",
    "imaplib",
    "langchain",
    "litellm",
    "mcp",
    "ollama",
    "openai",
    "paramiko",
    "poplib",
    "requests",
    "smtplib",
    "socket",
    "socketserver",
    "ssl",
    "telnetlib",
    "urllib.request",
    "urllib3",
    "websocket",
    "websockets",
    "webbrowser",
    "xmlrpc.client",
    "xmlrpc.server",
)

_SUBPROCESS_CALLS = {
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.run",
}

_PROCESS_REFLECTION_CALLS = {
    "builtins.getattr",
    "builtins.vars",
    "getattr",
    "vars",
}

_ASYNCIO_NETWORK_METHODS = {
    "connect_accepted_socket",
    "create_connection",
    "create_datagram_endpoint",
    "create_server",
    "create_unix_connection",
    "create_unix_server",
    "getaddrinfo",
    "getnameinfo",
    "sock_accept",
    "sock_connect",
    "sock_recv",
    "sock_recv_into",
    "sock_recvfrom",
    "sock_recvfrom_into",
    "sock_sendall",
    "sock_sendfile",
    "sock_sendto",
    "start_tls",
}

# Source-level URL literals remain forbidden in product code.  Exact supply
# chain URLs live only in tests/portable_build/supply-chain.json, which is not
# shipped as runtime code and is independently constrained by repository tests.
_URL_PATTERN = re.compile(r"(?i)\b(?:https?|ftp|wss?)://")
_HOST_PORT_PATTERN = re.compile(
    r"(?i)(?:^|[^A-Za-z0-9_.-])(?:localhost|[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+):[0-9]{2,5}(?:[^0-9]|$)"
)
_DOMAIN_PATTERN = re.compile(
    r"(?i)(?:^|[^A-Za-z0-9_.-])(?:api\.|www\.|telemetry\.|update\.|updates\.)?[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?::[0-9]{2,5})?(?:/[^\s\"'<>]*)?"
)

_HTML_FORBIDDEN_PATTERNS = (
    ("HTML_SCRIPT_TAG", re.compile(r"(?is)<\s*script\b")),
    ("HTML_IFRAME_TAG", re.compile(r"(?is)<\s*iframe\b")),
    ("HTML_OBJECT_TAG", re.compile(r"(?is)<\s*object\b")),
    ("HTML_EMBED_TAG", re.compile(r"(?is)<\s*embed\b")),
    ("HTML_BASE_TAG", re.compile(r"(?is)<\s*base\b")),
    ("HTML_META_REFRESH", re.compile(r"(?is)<\s*meta\b[^>]*http-equiv\s*=\s*['\"]?refresh")),
    ("HTML_EVENT_HANDLER", re.compile(r"(?is)\son[a-z0-9_-]+\s*=")),
    ("HTML_JAVASCRIPT_URI", re.compile(r"(?is)javascript\s*:")),
    ("HTML_CSS_IMPORT", re.compile(r"(?is)@import\s+(?:url\s*\()?")),
    ("HTML_EXTERNAL_CSS_URL", re.compile(r"(?is)url\s*\(\s*['\"]?\s*(?:https?:)?//")),
    ("HTML_EXTERNAL_CSS_IMAGE", re.compile(r"(?is)(?:background(?:-image)?|content|cursor|list-style(?:-image)?)\s*:[^;{}]*url\s*\(")),
)

# Static string reconstruction is bounded to avoid turning the audit into an
# unbounded evaluator while still catching split or formatted URL literals.
_MAX_STATIC_STRING_LENGTH = 65536

# Process creation is approved only for two constrained uses.  Product runtime
# may execute the bundled TShark through the exact helper in tshark/runner.py;
# the repository audit may execute the local Git binary through
# scripts/audit_repository.py.  Every other process call remains forbidden.
_APPROVED_PROCESS_HELPERS = {
    ("scripts/audit_repository.py", "_run_git"),
    ("src/wlan_troubleshooter_ko/tshark/runner.py", "_execute"),
}


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    code: str
    message: str


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _is_skipped(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    if not relative.parts:
        return False
    if relative.parts[0] in _SKIPPED_TOP_LEVEL_DIRECTORIES:
        return True
    return any(part in _SKIPPED_CACHE_DIRECTORIES for part in relative.parts)


def _iter_source_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if path == _SELF_PATH:
            continue
        if _is_skipped(path, root):
            continue
        if path.is_file() and path.suffix.casefold() in _SOURCE_SUFFIXES:
            yield path


def _display_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _module_is_forbidden(name: str) -> bool:
    return any(name == item or name.startswith(item + ".") for item in _FORBIDDEN_MODULES)


def _string_findings(path: str, line: int, value: str) -> List[Finding]:
    findings = []
    for match in _URL_PATTERN.finditer(value):
        findings.append(
            Finding(path, line + value.count("\n", 0, match.start()), "NETWORK_ENDPOINT", "network endpoint literal is forbidden")
        )
    for match in _HOST_PORT_PATTERN.finditer(value):
        findings.append(
            Finding(path, line + value.count("\n", 0, match.start()), "NETWORK_ENDPOINT", "network endpoint literal is forbidden")
        )
    for match in _DOMAIN_PATTERN.finditer(value):
        findings.append(
            Finding(path, line + value.count("\n", 0, match.start()), "NETWORK_ENDPOINT", "network endpoint literal is forbidden")
        )
    for code, pattern in _HTML_FORBIDDEN_PATTERNS:
        if code == "HTML_CSS_IMPORT" and not (";" in value or "\n" in value):
            continue
        if code in {"HTML_EXTERNAL_CSS_URL", "HTML_EXTERNAL_CSS_IMAGE"} and ")" not in value:
            continue
        if code not in {
            "HTML_CSS_IMPORT",
            "HTML_EXTERNAL_CSS_URL",
            "HTML_EXTERNAL_CSS_IMAGE",
            "HTML_JAVASCRIPT_URI",
        } and "<" not in value:
            continue
        for match in pattern.finditer(value):
            findings.append(
                Finding(
                    path,
                    line + value.count("\n", 0, match.start()),
                    code,
                    "generated offline HTML must not load or execute external/active content",
                )
            )
    return findings


class _PythonVisitor(ast.NodeVisitor):
    def __init__(self, display_path: str) -> None:
        self.display_path = display_path
        self.findings: List[Finding] = []
        self.import_aliases: Dict[str, str] = {}
        self.static_strings: Dict[str, str] = {}
        self.static_sequences: Dict[str, Tuple[str, ...]] = {}
        self.function_stack: List[str] = []
        self._finding_keys: Set[Tuple[str, int, str, str]] = set()
        self._direct_process_call_nodes: Set[int] = set()

    def _add(self, node: ast.AST, code: str, message: str) -> None:
        self._append(
            Finding(self.display_path, int(getattr(node, "lineno", 1)), code, message)
        )

    def _append(self, finding: Finding) -> None:
        key = (finding.path, finding.line, finding.code, finding.message)
        if key not in self._finding_keys:
            self._finding_keys.add(key)
            self.findings.append(finding)

    def _resolve_name(self, name: str) -> str:
        seen: Set[str] = set()
        while name not in seen:
            seen.add(name)
            first, separator, remainder = name.partition(".")
            replacement = self.import_aliases.get(first)
            if replacement is None:
                break
            name = replacement + (separator + remainder if separator else "")
        return name

    def _callable_name(self, node: ast.AST) -> Optional[str]:
        name = _call_name(node)
        if name:
            return self._resolve_name(name)
        if isinstance(node, ast.Attribute) and node.attr in _ASYNCIO_NETWORK_METHODS:
            return "event_loop." + node.attr
        if (
            isinstance(node, ast.Call)
            and len(node.args) == 2
            and not node.keywords
            and self._callable_name(node.func) in {"getattr", "builtins.getattr"}
        ):
            owner = _call_name(node.args[0])
            attribute = _constant_string(node.args[1], self.static_strings)
            if owner and attribute and attribute.isidentifier():
                return self._resolve_name(owner) + "." + attribute
        return None

    def _remember_assignment(self, target: ast.AST, value: ast.AST) -> None:
        if not isinstance(target, ast.Name):
            return
        static_value = _constant_string(value, self.static_strings)
        if static_value is None:
            self.static_strings.pop(target.id, None)
        else:
            self.static_strings[target.id] = static_value

        if isinstance(value, (ast.List, ast.Tuple)):
            sequence = []
            for element in value.elts:
                item = _constant_string(element, self.static_strings)
                if item is None:
                    sequence = []
                    break
                sequence.append(item)
            if sequence:
                self.static_sequences[target.id] = tuple(sequence)
            else:
                self.static_sequences.pop(target.id, None)
        else:
            self.static_sequences.pop(target.id, None)

        callable_name = self._callable_name(value)
        if callable_name is None:
            self.import_aliases.pop(target.id, None)
        else:
            self.import_aliases[target.id] = callable_name

    def _check_static_string(self, node: ast.AST) -> None:
        value = _constant_string(node, self.static_strings)
        if value is None or isinstance(node, ast.Constant):
            return
        self._check_string_value(node, value)

    def _check_string_value(self, node: ast.AST, value: str) -> None:
        line = int(getattr(node, "lineno", 1))
        for finding in _string_findings(self.display_path, line, value):
            self._append(finding)

    def _process_import_is_approved(self) -> bool:
        return self.display_path in {
            "scripts/audit_repository.py",
            "src/wlan_troubleshooter_ko/tshark/runner.py",
        }

    def _is_subprocess_module_reference(self, node: ast.AST) -> bool:
        name = _call_name(node)
        return bool(name and self._resolve_name(name) == "subprocess")

    def _is_subprocess_reflection(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call) or not node.args:
            return False
        callable_name = self._callable_name(node.func)
        return (
            callable_name in _PROCESS_REFLECTION_CALLS
            and self._is_subprocess_module_reference(node.args[0])
        )

    def _is_subprocess_namespace_mapping(self, node: ast.AST) -> bool:
        if self._is_subprocess_reflection(node):
            return True
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "__dict__"
            and self._is_subprocess_module_reference(node.value)
        )

    def _check_runtime_import(self, node: ast.AST, module_name: str) -> None:
        runtime_path = self.display_path.replace("\\", "/")
        if not runtime_path.startswith("src/"):
            return
        top_level = module_name.split(".", 1)[0]
        if (
            top_level in _OWN_RUNTIME_PACKAGES
            or top_level in _APPROVED_RUNTIME_STDLIB_MODULES
        ):
            return
        self._add(
            node,
            "UNAPPROVED_RUNTIME_IMPORT",
            "runtime imports must use only the application package or Python standard library",
        )

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local_name = alias.asname or alias.name.split(".", 1)[0]
            canonical_name = alias.name if alias.asname else local_name
            self.import_aliases[local_name] = canonical_name
            if alias.name == "subprocess" and not self._process_import_is_approved():
                self._add(
                    node,
                    "UNAPPROVED_PROCESS_IMPORT",
                    "subprocess is approved only for the repository Git audit",
                )
            elif alias.name == "subprocess" and alias.asname is not None:
                self._add(
                    node,
                    "UNAPPROVED_PROCESS_REFERENCE",
                    "approved process modules must use the exact subprocess name",
                )
            if _module_is_forbidden(alias.name):
                self._add(node, "FORBIDDEN_IMPORT", "forbidden module import: " + alias.name)
            self._check_runtime_import(node, alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        candidates = [module]
        candidates.extend(module + "." + alias.name if module else alias.name for alias in node.names)
        for alias in node.names:
            local_name = alias.asname or alias.name
            self.import_aliases[local_name] = module + "." + alias.name if module else alias.name
        for candidate in candidates:
            if candidate.startswith("subprocess") and not self._process_import_is_approved():
                self._add(
                    node,
                    "UNAPPROVED_PROCESS_IMPORT",
                    "subprocess is approved only for the repository Git audit",
                )
                break
            if candidate.startswith("subprocess") and self._process_import_is_approved():
                self._add(
                    node,
                    "UNAPPROVED_PROCESS_REFERENCE",
                    "from-import process references are not approved",
                )
                break
        for candidate in candidates:
            if candidate and _module_is_forbidden(candidate):
                self._add(node, "FORBIDDEN_IMPORT", "forbidden module import: " + candidate)
                break
        if node.level == 0:
            self._check_runtime_import(node, module)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._remember_assignment(target, node.value)
        self._check_static_string(node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._remember_assignment(node.target, node.value)
            self._check_static_string(node.value)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if isinstance(node.target, ast.Name) and isinstance(node.op, ast.Add):
            left = self.static_strings.get(node.target.id)
            right = _constant_string(node.value, self.static_strings)
            if (
                left is not None
                and right is not None
                and len(left) + len(right) <= _MAX_STATIC_STRING_LENGTH
            ):
                combined = left + right
                self.static_strings[node.target.id] = combined
                self._check_string_value(node, combined)
            else:
                self.static_strings.pop(node.target.id, None)
            self.import_aliases.pop(node.target.id, None)
            self.static_sequences.pop(node.target.id, None)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self._remember_assignment(node.target, node.value)
        self._check_static_string(node.value)
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        self._check_static_string(node)
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        self._check_static_string(node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self._check_static_string(node)
        name = self._callable_name(node.func)
        syntactic_name = _call_name(node.func)
        if self._process_import_is_approved() and self._is_subprocess_reflection(node):
            self._add(
                node,
                "UNAPPROVED_PROCESS_REFERENCE",
                "reflective subprocess module access is forbidden",
            )
        if syntactic_name in _SUBPROCESS_CALLS:
            self._direct_process_call_nodes.add(id(node.func))
        if name in _FORBIDDEN_CALLS:
            code = "NETWORK_CALL" if _FORBIDDEN_CALLS[name].startswith("network ") else "DYNAMIC_EXEC"
            self._add(node, code, _FORBIDDEN_CALLS[name] + " is forbidden")
        elif name and name.startswith("os.spawn"):
            self._add(node, "SHELL_PROCESS", "os.spawn process creation is forbidden")

        method_name = node.func.attr if isinstance(node.func, ast.Attribute) else None
        if (name and name.rsplit(".", 1)[-1] in _ASYNCIO_NETWORK_METHODS) or (
            method_name in _ASYNCIO_NETWORK_METHODS
        ):
            self._add(node, "NETWORK_CALL", "event-loop network operation is forbidden")
        if name in _SUBPROCESS_CALLS and not self._process_call_is_approved(node, name):
            self._add(
                node,
                "SHELL_PROCESS",
                "process execution is not in an approved constrained helper",
            )
        elif name == "subprocess.Popen" and self._process_import_is_approved():
            shell_keyword = next(
                (item for item in node.keywords if item.arg == "shell"),
                None,
            )
            if shell_keyword is None or not _is_exact_bool(shell_keyword.value, False):
                self._add(
                    node,
                    "UNSAFE_SUBPROCESS",
                    "approved subprocess.Popen must set shell=False",
                )
            stdin_keyword = next(
                (item for item in node.keywords if item.arg == "stdin"),
                None,
            )
            if stdin_keyword is None or not (
                isinstance(stdin_keyword.value, ast.Attribute)
                and _call_name(stdin_keyword.value) == "subprocess.DEVNULL"
            ):
                self._add(
                    node,
                    "UNSAFE_SUBPROCESS",
                    "approved subprocess.Popen must disable stdin",
                )
            for keyword_name in ("cwd", "env"):
                keyword = next(
                    (item for item in node.keywords if item.arg == keyword_name),
                    None,
                )
                if keyword is None or (
                    isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is None
                ):
                    self._add(
                        node,
                        "UNSAFE_SUBPROCESS",
                        "approved subprocess.Popen must set explicit " + keyword_name,
                    )
            executable_keyword = next(
                (item for item in node.keywords if item.arg == "executable"),
                None,
            )
            if executable_keyword is None:
                self._add(
                    node,
                    "UNSAFE_SUBPROCESS",
                    "approved subprocess.Popen must pin executable explicitly",
                )
            args_keyword = next(
                (item for item in node.keywords if item.arg == "args"),
                None,
            )
            if args_keyword is None:
                self._add(
                    node,
                    "UNSAFE_SUBPROCESS",
                    "approved subprocess.Popen must pass an explicit args sequence",
                )
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if node.id in _FORBIDDEN_REFLECTION_NAMES:
            self._add(
                node,
                "DYNAMIC_EXEC",
                "reflective builtins access is forbidden",
            )
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        name = self._callable_name(node)
        if name in _FORBIDDEN_CALLS:
            code = "NETWORK_CALL" if _FORBIDDEN_CALLS[name].startswith("network ") else "DYNAMIC_EXEC"
            self._add(node, code, _FORBIDDEN_CALLS[name] + " reference is forbidden")
        if (
            self._process_import_is_approved()
            and node.attr == "__dict__"
            and self._is_subprocess_module_reference(node.value)
        ):
            self._add(
                node,
                "UNAPPROVED_PROCESS_REFERENCE",
                "subprocess module reflection is forbidden",
            )
        self.generic_visit(node)

    def _process_call_is_approved(self, node: ast.Call, name: str) -> bool:
        if name not in _SUBPROCESS_CALLS:
            return False
        if not self.function_stack:
            return False
        return (self.display_path, self.function_stack[-1]) in _APPROVED_PROCESS_HELPERS


def _call_name(node: ast.AST) -> Optional[str]:
    parts = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def _constant_string(
    node: ast.AST,
    static_strings: Optional[Dict[str, str]] = None,
) -> Optional[str]:
    strings = {} if static_strings is None else static_strings
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return strings.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _constant_string(node.left, strings)
        right = _constant_string(node.right, strings)
        if left is None or right is None or len(left) + len(right) > _MAX_STATIC_STRING_LENGTH:
            return None
        return left + right
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                formatted = _constant_string(value.value, strings)
                if formatted is None:
                    return None
                parts.append(formatted)
            else:
                return None
        result = "".join(parts)
        return result if len(result) <= _MAX_STATIC_STRING_LENGTH else None
    if isinstance(node, ast.Call):
        name = _call_name(node.func)
        if name in {"str", "builtins.str"} and len(node.args) == 1 and not node.keywords:
            value = node.args[0]
            if isinstance(value, ast.Constant) and isinstance(value.value, (str, int, float)):
                return str(value.value)
        if (
            name in {"format", "str.format", "builtins.format"}
            and node.args
            and not node.keywords
        ):
            template = _constant_string(node.args[0], strings)
            if template is None:
                return None
            values = []
            for argument in node.args[1:]:
                item = _constant_string(argument, strings)
                if item is None:
                    return None
                values.append(item)
            try:
                result = template.format(*values)
            except (IndexError, KeyError, ValueError):
                return None
            return result if len(result) <= _MAX_STATIC_STRING_LENGTH else None
    return None


def _is_exact_bool(node: ast.AST, expected: bool) -> bool:
    return isinstance(node, ast.Constant) and type(node.value) is bool and node.value is expected


def _is_direct_subprocess_constant(node: ast.AST) -> bool:
    return isinstance(node, ast.Attribute) and _call_name(node) in {
        "subprocess.DEVNULL",
        "subprocess.PIPE",
        "subprocess.STDOUT",
    }


def _is_explicit_environment_mapping(node: ast.AST) -> bool:
    return isinstance(node, (ast.Dict, ast.Name))


def _check_approved_process_call(
    display_path: str,
    node: ast.Call,
    name: str,
    findings: List[Finding],
) -> None:
    if name not in _SUBPROCESS_CALLS:
        return
    if not isinstance(node.func, ast.Attribute):
        return
    if name == "subprocess.Popen":
        if node.args:
            findings.append(
                Finding(
                    display_path,
                    node.lineno,
                    "UNSAFE_SUBPROCESS",
                    "approved subprocess.Popen must use keyword-only arguments",
                )
            )
        arguments = {item.arg: item.value for item in node.keywords if item.arg is not None}
        if "args" not in arguments:
            findings.append(
                Finding(
                    display_path,
                    node.lineno,
                    "UNSAFE_SUBPROCESS",
                    "approved subprocess.Popen must pass args= explicitly",
                )
            )
        if "executable" not in arguments:
            findings.append(
                Finding(
                    display_path,
                    node.lineno,
                    "UNSAFE_SUBPROCESS",
                    "approved subprocess.Popen must pin executable explicitly",
                )
            )
        if not _is_exact_bool(arguments.get("shell"), False):
            findings.append(
                Finding(
                    display_path,
                    node.lineno,
                    "UNSAFE_SUBPROCESS",
                    "approved subprocess.Popen must set shell=False",
                )
            )
        if not _is_direct_subprocess_constant(arguments.get("stdin")):
            findings.append(
                Finding(
                    display_path,
                    node.lineno,
                    "UNSAFE_SUBPROCESS",
                    "approved subprocess.Popen must set stdin to a direct subprocess constant",
                )
            )
        for key in ("cwd", "env"):
            if key not in arguments or not _is_explicit_environment_mapping(arguments[key]):
                findings.append(
                    Finding(
                        display_path,
                        node.lineno,
                        "UNSAFE_SUBPROCESS",
                        "approved subprocess.Popen must set an explicit " + key,
                    )
                )
    elif name in {"subprocess.run", "subprocess.check_call", "subprocess.check_output", "subprocess.call"}:
        if not node.args:
            findings.append(
                Finding(
                    display_path,
                    node.lineno,
                    "UNSAFE_SUBPROCESS",
                    "approved subprocess call must use an explicit argument sequence",
                )
            )


def _audit_python(path: Path, display_path: str) -> List[Finding]:
    try:
        raw = path.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            return [Finding(display_path, 1, "UTF8_BOM", "UTF-8 BOM is forbidden")]
        source = raw.decode("utf-8")
        tree = ast.parse(source, filename=display_path)
    except (OSError, UnicodeError, SyntaxError) as exc:
        return [Finding(display_path, 1, "PYTHON_PARSE", str(exc))]
    visitor = _PythonVisitor(display_path)
    visitor.visit(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = visitor._callable_name(node.func)
            if name in _SUBPROCESS_CALLS and (display_path, visitor.function_stack[-1] if visitor.function_stack else "") in _APPROVED_PROCESS_HELPERS:
                _check_approved_process_call(display_path, node, name, visitor.findings)
    return sorted(visitor.findings, key=lambda item: (item.line, item.code, item.message))


def _audit_text(path: Path, display_path: str) -> List[Finding]:
    try:
        raw = path.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            return [Finding(display_path, 1, "UTF8_BOM", "UTF-8 BOM is forbidden")]
        value = raw.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        return [Finding(display_path, 1, "TEXT_READ", str(exc))]
    return _string_findings(display_path, 1, value)


def run_audit(root: Path) -> Tuple[List[Finding], int]:
    findings = []
    count = 0
    for path in sorted(_iter_source_files(root)):
        display_path = _display_path(path, root)
        count += 1
        if path.suffix.casefold() in {".py", ".pyw"}:
            findings.extend(_audit_python(path, display_path))
        else:
            findings.extend(_audit_text(path, display_path))
    return findings, count


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    arguments = build_parser().parse_args(argv)
    root = arguments.root.resolve()
    findings, count = run_audit(root)
    if findings:
        print(
            "offline source audit FAILED ({0} finding(s), {1} file(s) scanned)".format(
                len(findings),
                count,
            )
        )
        for finding in findings:
            print(
                "{0}:{1}: {2}: {3}".format(
                    finding.path,
                    finding.line,
                    finding.code,
                    finding.message,
                )
            )
        return 1
    print("offline source audit passed ({0} file(s) scanned)".format(count))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
