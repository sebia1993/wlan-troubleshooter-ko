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

_FORBIDDEN_CALLS = {
    "__import__": "dynamic import",
    "asyncio.create_subprocess_shell": "shell subprocess",
    "asyncio.create_subprocess_exec": "process creation",
    "asyncio.open_connection": "network connection",
    "asyncio.start_server": "network server",
    "builtins.__import__": "dynamic import",
    "builtins.compile": "dynamic code compilation",
    "builtins.eval": "dynamic evaluation",
    "builtins.exec": "dynamic execution",
    "compile": "dynamic code compilation",
    "eval": "dynamic evaluation",
    "exec": "dynamic execution",
    "importlib.import_module": "dynamic import",
    "os.popen": "shell process",
    "os.startfile": "external handler launch",
    "os.system": "shell process",
    "os.execl": "process replacement",
    "os.execle": "process replacement",
    "os.execlp": "process replacement",
    "os.execlpe": "process replacement",
    "os.execv": "process replacement",
    "os.execve": "process replacement",
    "os.execvp": "process replacement",
    "os.execvpe": "process replacement",
    "os.posix_spawn": "process creation",
    "os.posix_spawnp": "process creation",
    "subprocess.getoutput": "shell process",
    "subprocess.getstatusoutput": "shell process",
}

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
}

_MAX_STATIC_STRING_LENGTH = 1_000_000

_URI_RE = re.compile(r"(?i)\b(?:https?|wss?|ftps?|ssh|telnet|ldap|ldaps|smb|nfs|rpcap):")
_PROTOCOL_RELATIVE_RE = re.compile(
    r"(?i)(?:^|[\s\"'(=:])//[a-z0-9._-]+(?::\d+)?(?:[/\s\"')]|$)"
)
_UNC_RE = re.compile(r"(?i)(?:^|[\s\"'(=])\\\\[a-z0-9._-]+\\")
_LOCAL_ENDPOINT_RE = re.compile(
    r"(?i)\b(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}\b"
)

_RAW_FORBIDDEN_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    (
        "NET_COMMAND",
        re.compile(
            r"(?i)\b(?:curl|wget|ssh|scp|sftp|telnet|ftp|nc|netcat|nslookup|dig)(?:\.exe)?\b"
        ),
    ),
    (
        "NET_COMMAND",
        re.compile(
            r"(?i)\b(?:Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|DownloadFile|WebClient|HttpClient|TcpClient|UdpClient)\b"
        ),
    ),
    (
        "NET_COMMAND",
        re.compile(r"(?i)\b(?:XMLHttpRequest|WebSocket|EventSource|fetch)\s*\("),
    ),
    (
        "FORBIDDEN_PACKAGE",
        re.compile(
            r"(?i)(?:^|[\s\"'])"
            r"(?:aiohttp|anthropic|httpx|langchain|litellm|mcp|ollama|openai|paramiko|requests|urllib3|websockets?)"
            r"(?:$|[\s\"'<=>,;\[])"
        ),
    ),
    ("DYNAMIC_EXEC", re.compile(r"(?i)\b(?:Invoke-Expression|iex)\b")),
    (
        "SHELL_COMMAND",
        re.compile(
            r"(?i)\b(?:cmd(?:\.exe)?\s+/c|powershell(?:\.exe)?\s+-command|pwsh(?:\.exe)?\s+-command)\b"
        ),
    ),
)

_HTML_FORBIDDEN_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("HTML_SCRIPT", re.compile(r"(?i)<\s*script\b")),
    ("HTML_EVENT_HANDLER", re.compile(r"(?i)\son[a-z][a-z0-9_-]*\s*=")),
    ("HTML_ACTIVE_ELEMENT", re.compile(r"(?i)<\s*(?:iframe|object|embed|base|link|form)\b")),
    (
        "HTML_META_REFRESH",
        re.compile(r"(?is)<\s*meta\b[^>]*http-equiv\s*=\s*[\"']?refresh\b"),
    ),
    (
        "HTML_EXTERNAL_ATTRIBUTE",
        re.compile(
            r"(?ix)\b(?:src|href|poster|action)\s*=\s*(?:"
            r'"\s*(?!\#|data:|\")[^\"]+'
            r"|'\s*(?!\#|data:|')[^']+"
            r"|(?![\"']|\#|data:)[^\s>]+)"
        ),
    ),
    ("HTML_SRCSET", re.compile(r"(?i)\bsrcset\s*=")),
    ("HTML_CSS_IMPORT", re.compile(r"(?i)@import\b")),
    (
        "HTML_EXTERNAL_CSS_URL",
        re.compile(r"(?i)\burl\s*\("),
    ),
    (
        "HTML_EXTERNAL_CSS_IMAGE",
        re.compile(r"(?i)(?:\bimage|\bimage-set|-webkit-image-set|\bcross-fade|\belement)\s*\("),
    ),
    ("HTML_JAVASCRIPT_URI", re.compile(r"(?i)javascript\s*:")),
)


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    code: str
    message: str


@dataclass(frozen=True)
class AuditReport:
    scanned_files: int
    findings: Tuple[Finding, ...]


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _call_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        if parent:
            return parent + "." + node.attr
    return None


def _constant_string(node: ast.AST, names: Dict[str, str]) -> Optional[str]:
    """Evaluate only bounded, side-effect-free string construction."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return names.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _constant_string(node.left, names)
        right = _constant_string(node.right, names)
        if left is None or right is None:
            return None
        if len(left) + len(right) > _MAX_STATIC_STRING_LENGTH:
            return None
        return left + right
    if isinstance(node, ast.JoinedStr):
        parts: List[str] = []
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                if value.conversion != -1 or value.format_spec is not None:
                    return None
                part = _constant_string(value.value, names)
            else:
                part = _constant_string(value, names)
            if part is None:
                return None
            parts.append(part)
            if sum(len(item) for item in parts) > _MAX_STATIC_STRING_LENGTH:
                return None
        return "".join(parts)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and not node.keywords
        and len(node.args) == 1
    ):
        separator = _constant_string(node.func.value, names)
        values_node = node.args[0]
        if separator is None or not isinstance(values_node, (ast.List, ast.Tuple)):
            return None
        values: List[str] = []
        for element in values_node.elts:
            value = _constant_string(element, names)
            if value is None:
                return None
            values.append(value)
        result = separator.join(values)
        if len(result) <= _MAX_STATIC_STRING_LENGTH:
            return result
    return None


def _module_is_forbidden(module_name: str) -> bool:
    return any(
        module_name == forbidden or module_name.startswith(forbidden + ".")
        for forbidden in _FORBIDDEN_MODULES
    )


def _string_findings(path: str, line: int, value: str) -> List[Finding]:
    findings: List[Finding] = []
    if _URI_RE.search(value) or _PROTOCOL_RELATIVE_RE.search(value) or _UNC_RE.search(value):
        findings.append(
            Finding(path, line, "EXTERNAL_URI", "external URI literal is forbidden")
        )
    if _LOCAL_ENDPOINT_RE.search(value):
        findings.append(
            Finding(path, line, "NETWORK_ENDPOINT", "network endpoint literal is forbidden")
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

        if name in _SUBPROCESS_CALLS:
            approved_git_wrapper = (
                self.display_path == "scripts/audit_repository.py"
                and self.function_stack
                and self.function_stack[-1] == "_run_git"
                and name == "subprocess.run"
                and syntactic_name == "subprocess.run"
            )
            approved_tshark_probe = (
                self.display_path == "src/wlan_troubleshooter_ko/tshark/runner.py"
                and self.function_stack
                and self.function_stack[-1] == "probe_bundle_runtime"
                and name == "subprocess.Popen"
                and syntactic_name == "subprocess.Popen"
            )
            if not approved_git_wrapper and not approved_tshark_probe:
                self._add(
                    node,
                    "UNAPPROVED_PROCESS",
                    "process creation is not approved for this source location",
                )
            shell_keywords = [keyword for keyword in node.keywords if keyword.arg == "shell"]
            if not shell_keywords:
                self._add(
                    node,
                    "SHELL_NOT_EXPLICIT",
                    "subprocess calls must specify shell=False explicitly",
                )
            elif not (
                len(shell_keywords) == 1
                and isinstance(shell_keywords[0].value, ast.Constant)
                and shell_keywords[0].value.value is False
            ):
                self._add(node, "SHELL_ENABLED", "subprocess shell must be literal False")

            command_node: Optional[ast.AST] = node.args[0] if node.args else None
            if command_node is None:
                for keyword in node.keywords:
                    if keyword.arg == "args":
                        command_node = keyword.value
                        break
            if isinstance(command_node, (ast.Constant, ast.JoinedStr)):
                self._add(
                    node,
                    "COMMAND_NOT_SEQUENCE",
                    "subprocess command must be an argument sequence, not a string",
                )
            executable_node: Optional[ast.AST] = None
            executable_value: Optional[str] = None
            if isinstance(command_node, (ast.List, ast.Tuple)) and command_node.elts:
                executable_node = command_node.elts[0]
                executable_value = _constant_string(executable_node, self.static_strings)
            elif isinstance(command_node, ast.Name):
                sequence = self.static_sequences.get(command_node.id)
                if sequence:
                    executable_node = command_node
                    executable_value = sequence[0]
            if executable_node is not None and executable_value is not None:
                for code, pattern in _RAW_FORBIDDEN_PATTERNS:
                    if code == "NET_COMMAND" and pattern.search(executable_value):
                        self._add(
                            executable_node,
                            "NET_COMMAND",
                            "network-capable command is forbidden",
                        )
                        break

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if (
            self._process_import_is_approved()
            and self._is_subprocess_namespace_mapping(node.value)
        ):
            self._add(
                node,
                "UNAPPROVED_PROCESS_REFERENCE",
                "subscripted subprocess namespace access is forbidden",
            )
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        raw_name = _call_name(node)
        resolved_name = self._resolve_name(raw_name) if raw_name else ""
        is_process_callable = any(
            resolved_name == process_name or resolved_name.startswith(process_name + ".")
            for process_name in _SUBPROCESS_CALLS
        )
        if (
            (is_process_callable and id(node) not in self._direct_process_call_nodes)
            or resolved_name.startswith("subprocess.__")
        ):
            self._add(
                node,
                "UNAPPROVED_PROCESS_REFERENCE",
                "indirect subprocess API references are forbidden",
            )
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            for finding in _string_findings(
                self.display_path, int(getattr(node, "lineno", 1)), node.value
            ):
                self._append(finding)
        self.generic_visit(node)


def _scan_raw_text(display_path: str, suffix: str, text: str) -> List[Finding]:
    findings: List[Finding] = []
    for match in _URI_RE.finditer(text):
        findings.append(
            Finding(
                display_path,
                _line_number(text, match.start()),
                "EXTERNAL_URI",
                "external URI literal is forbidden",
            )
        )
    for match in _PROTOCOL_RELATIVE_RE.finditer(text):
        findings.append(
            Finding(
                display_path,
                _line_number(text, match.start()),
                "EXTERNAL_URI",
                "protocol-relative URI is forbidden",
            )
        )
    for match in _UNC_RE.finditer(text):
        findings.append(
            Finding(
                display_path,
                _line_number(text, match.start()),
                "EXTERNAL_URI",
                "UNC network path is forbidden",
            )
        )
    for match in _LOCAL_ENDPOINT_RE.finditer(text):
        findings.append(
            Finding(
                display_path,
                _line_number(text, match.start()),
                "NETWORK_ENDPOINT",
                "network endpoint literal is forbidden",
            )
        )
    for code, pattern in _RAW_FORBIDDEN_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(
                Finding(
                    display_path,
                    _line_number(text, match.start()),
                    code,
                    "forbidden network or dynamic execution primitive",
                )
            )
    if suffix in {".htm", ".html", ".css"}:
        for code, pattern in _HTML_FORBIDDEN_PATTERNS:
            for match in pattern.finditer(text):
                findings.append(
                    Finding(
                        display_path,
                        _line_number(text, match.start()),
                        code,
                        "offline HTML must not load or execute external/active content",
                    )
                )
    return findings


def _strip_toml_comment(line: str) -> str:
    quote: Optional[str] = None
    escaped = False
    result: List[str] = []
    for character in line:
        if escaped:
            result.append(character)
            escaped = False
            continue
        if character == "\\" and quote == '"':
            result.append(character)
            escaped = True
            continue
        if quote is not None:
            result.append(character)
            if character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
            result.append(character)
            continue
        if character == "#":
            break
        result.append(character)
    return "".join(result)


def _toml_bracket_delta(value: str) -> int:
    quote: Optional[str] = None
    escaped = False
    delta = 0
    for character in value:
        if escaped:
            escaped = False
            continue
        if character == "\\" and quote == '"':
            escaped = True
            continue
        if quote is not None:
            if character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
        elif character == "[":
            delta += 1
        elif character == "]":
            delta -= 1
    return delta


def _normalise_toml_name(value: str) -> str:
    parts = []
    for part in value.split("."):
        cleaned = part.strip()
        if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in {'"', "'"}:
            cleaned = cleaned[1:-1]
        parts.append(cleaned.lower().replace("_", "-"))
    return ".".join(parts)


def _semantic_dependency_findings(
    display_path: str, document: Dict[str, object]
) -> List[Finding]:
    findings: List[Finding] = []

    def add(code: str, message: str) -> None:
        finding = Finding(display_path, 1, code, message)
        if finding not in findings:
            findings.append(finding)

    project = document.get("project")
    if project is not None and not isinstance(project, dict):
        add("DEPENDENCY_DECLARATION_INVALID", "project metadata must be a TOML table")
    elif isinstance(project, dict):
        if "dependencies" in project and project["dependencies"] != []:
            add("RUNTIME_DEPENDENCY", "project runtime dependencies must be empty")
        if "optional-dependencies" in project and project["optional-dependencies"] != {}:
            add("RUNTIME_DEPENDENCY", "project optional dependencies must be empty")
        if "dynamic" in project:
            dynamic = project["dynamic"]
            if not isinstance(dynamic, list) or not all(
                isinstance(value, str) for value in dynamic
            ):
                add(
                    "DEPENDENCY_DECLARATION_INVALID",
                    "project dynamic metadata must be a string array",
                )
            elif any(
                value.lower().replace("_", "-")
                in {"dependencies", "optional-dependencies"}
                for value in dynamic
            ):
                add("RUNTIME_DEPENDENCY", "dynamic runtime dependencies are forbidden")

    tool = document.get("tool")
    if tool is not None and not isinstance(tool, dict):
        add("DEPENDENCY_DECLARATION_INVALID", "tool metadata must be a TOML table")
    elif isinstance(tool, dict):
        dependency_keys = {
            "dependencies",
            "optional-dependencies",
            "runtime-dependencies",
        }

        def walk_tool(value: object) -> None:
            if isinstance(value, list):
                for child in value:
                    walk_tool(child)
                return
            if not isinstance(value, dict):
                return
            for raw_key, child in value.items():
                key = raw_key.lower().replace("_", "-")
                if key in dependency_keys:
                    expected_empty = {} if isinstance(child, dict) else []
                    if child != expected_empty:
                        add(
                            "RUNTIME_DEPENDENCY",
                            "tool-managed runtime dependencies must be empty",
                        )
                    continue
                walk_tool(child)

        walk_tool(tool)
    return findings


def _fallback_dependency_manifest_findings(display_path: str, text: str) -> List[Finding]:
    """Check a restricted TOML subset when Python has no stdlib tomllib."""
    findings: List[Finding] = []
    section = ""
    pending_line = 0
    pending_value = ""
    pending_depth = 0
    pending_kind = ""

    def reject_nonempty(line: int, value: str) -> None:
        compact = re.sub(r"\s+", "", value)
        if compact != "[]":
            findings.append(
                Finding(
                    display_path,
                    line,
                    "RUNTIME_DEPENDENCY",
                    "runtime dependency declarations must be a literal empty array",
                )
            )

    def reject_dynamic_dependencies(line: int, value: str) -> None:
        if re.search(r"(?i)[\"']dependencies[\"']", value):
            findings.append(
                Finding(
                    display_path,
                    line,
                    "RUNTIME_DEPENDENCY",
                    "dynamic runtime dependencies are forbidden",
                )
            )

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = _strip_toml_comment(raw_line).strip()
        if pending_line:
            pending_value += line
            pending_depth += _toml_bracket_delta(line)
            if pending_depth <= 0:
                if pending_kind == "dynamic":
                    reject_dynamic_dependencies(pending_line, pending_value)
                else:
                    reject_nonempty(pending_line, pending_value)
                pending_line = 0
                pending_value = ""
                pending_depth = 0
                pending_kind = ""
            continue
        if not line:
            continue
        if line.startswith("["):
            if not line.endswith("]") or line.startswith("[["):
                if "dependenc" in line.lower():
                    findings.append(
                        Finding(
                            display_path,
                            line_number,
                            "DEPENDENCY_DECLARATION_INVALID",
                            "cannot safely parse dependency table declaration",
                        )
                    )
                section = ""
                continue
            if "\\" in line or '"' in line or "'" in line:
                findings.append(
                    Finding(
                        display_path,
                        line_number,
                        "DEPENDENCY_DECLARATION_INVALID",
                        "quoted TOML table keys require Python 3.11 or newer validation",
                    )
                )
                section = ""
                continue
            section = _normalise_toml_name(line[1:-1])
            continue

        assignment = re.match(
            r'^(?:"([^"]+)"|\'([^\']+)\'|([A-Za-z0-9_.-]+))\s*=\s*(.*)$', line
        )
        if assignment is None:
            if "dependenc" in line.lower():
                findings.append(
                    Finding(
                        display_path,
                        line_number,
                        "DEPENDENCY_DECLARATION_INVALID",
                        "cannot safely parse dependency declaration",
                    )
                )
            continue
        raw_key = next(value for value in assignment.groups()[:3] if value is not None)
        if assignment.group(1) is not None and "\\" in raw_key:
            findings.append(
                Finding(
                    display_path,
                    line_number,
                    "DEPENDENCY_DECLARATION_INVALID",
                    "escaped TOML keys require Python 3.11 or newer semantic validation",
                )
            )
            continue
        key = _normalise_toml_name(raw_key)
        value = assignment.group(4).strip()

        if section == "" and key in {"project", "tool"} and value.startswith("{"):
            findings.append(
                Finding(
                    display_path,
                    line_number,
                    "DEPENDENCY_DECLARATION_INVALID",
                    "inline project or tool tables require Python 3.11 or newer validation",
                )
            )
            continue
        if section.startswith("tool.") and value.startswith("{"):
            findings.append(
                Finding(
                    display_path,
                    line_number,
                    "DEPENDENCY_DECLARATION_INVALID",
                    "inline tool tables require Python 3.11 or newer semantic validation",
                )
            )
            continue

        if section == "project" and key == "dynamic":
            depth = _toml_bracket_delta(value)
            if value.startswith("[") and depth > 0:
                pending_line = line_number
                pending_value = value
                pending_depth = depth
                pending_kind = "dynamic"
            else:
                reject_dynamic_dependencies(line_number, value)
            continue

        key_leaf = key.rsplit(".", 1)[-1]
        is_dependency_array = key_leaf in {
            "dependencies",
            "optional-dependencies",
            "runtime-dependencies",
        }
        is_optional_group = section.startswith("project.optional-dependencies")
        is_tool_dependency_table = section.startswith("tool.") and section.endswith(
            ".dependencies"
        )
        if not (is_dependency_array or is_optional_group or is_tool_dependency_table):
            continue
        if is_tool_dependency_table:
            findings.append(
                Finding(
                    display_path,
                    line_number,
                    "RUNTIME_DEPENDENCY",
                    "tool-managed runtime dependency tables are forbidden",
                )
            )
            continue
        if not value.startswith("["):
            reject_nonempty(line_number, value)
            continue
        depth = _toml_bracket_delta(value)
        if depth <= 0:
            reject_nonempty(line_number, value)
        else:
            pending_line = line_number
            pending_value = value
            pending_depth = depth
            pending_kind = "dependency"

    if pending_line:
        findings.append(
            Finding(
                display_path,
                pending_line,
                "DEPENDENCY_DECLARATION_INVALID",
                "unterminated dependency declaration",
            )
        )
    return findings


def _dependency_manifest_findings(display_path: str, text: str) -> List[Finding]:
    """Reject runtime dependencies using semantic TOML parsing when available."""
    if _tomllib is None:
        return _fallback_dependency_manifest_findings(display_path, text)
    try:
        document = _tomllib.loads(text)
    except (TypeError, ValueError):
        return [
            Finding(
                display_path,
                1,
                "TOML_INVALID",
                "pyproject.toml could not be parsed safely",
            )
        ]
    if not isinstance(document, dict):
        return [
            Finding(
                display_path,
                1,
                "TOML_INVALID",
                "pyproject.toml root must be a table",
            )
        ]
    return _semantic_dependency_findings(display_path, document)


def audit_file(path: Path, display_path: str) -> List[Finding]:
    suffix = path.suffix.lower()
    if suffix == ".lua":
        return [Finding(display_path, 1, "LUA_SOURCE", "Lua source is forbidden")]
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return [
            Finding(display_path, 1, "SOURCE_UNREADABLE", "cannot read source: " + str(exc))
        ]

    if suffix in {".py", ".pyw"}:
        try:
            tree = ast.parse(text, filename=display_path)
        except SyntaxError as exc:
            return [
                Finding(
                    display_path,
                    int(exc.lineno or 1),
                    "PYTHON_SYNTAX",
                    "cannot parse Python source: " + str(exc.msg),
                )
            ]
        visitor = _PythonVisitor(display_path)
        visitor.visit(tree)
        return visitor.findings

    findings = _scan_raw_text(display_path, suffix, text)
    if suffix == ".toml" and Path(display_path).name.lower() == "pyproject.toml":
        findings.extend(_dependency_manifest_findings(display_path, text))
    return findings


def _iter_source_files(root: Path) -> Iterable[Tuple[Path, str, Optional[Finding]]]:
    for current, directory_names, file_names in os.walk(str(root), followlinks=False):
        current_path = Path(current)
        kept_directories = []
        for directory_name in sorted(directory_names):
            directory_path = current_path / directory_name
            if directory_name in _SKIPPED_CACHE_DIRECTORIES:
                continue
            if current_path == root and directory_name in _SKIPPED_TOP_LEVEL_DIRECTORIES:
                continue
            if directory_path.is_symlink():
                relative = directory_path.relative_to(root).as_posix()
                yield directory_path, relative, Finding(
                    relative, 1, "SOURCE_SYMLINK", "source directory symlinks are forbidden"
                )
                continue
            kept_directories.append(directory_name)
        directory_names[:] = kept_directories

        for file_name in sorted(file_names):
            path = current_path / file_name
            if path.suffix.lower() not in _SOURCE_SUFFIXES:
                continue
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                yield path, relative, Finding(
                    relative, 1, "SOURCE_SYMLINK", "source file symlinks are forbidden"
                )
                continue
            yield path, relative, None


def audit_tree(root: Path) -> AuditReport:
    try:
        root = root.resolve(strict=True)
    except OSError as exc:
        return AuditReport(
            0,
            (Finding(str(root), 1, "ROOT_INVALID", "cannot resolve audit root: " + str(exc)),),
        )
    if not root.is_dir():
        return AuditReport(
            0, (Finding(str(root), 1, "ROOT_INVALID", "audit root is not a directory"),)
        )

    findings: List[Finding] = []
    scanned_files = 0
    for path, relative, discovery_finding in _iter_source_files(root):
        if discovery_finding is not None:
            findings.append(discovery_finding)
            continue
        try:
            candidate = path.resolve(strict=True)
        except OSError as exc:
            findings.append(
                Finding(relative, 1, "SOURCE_UNREADABLE", "cannot resolve source: " + str(exc))
            )
            continue
        if candidate == _SELF_PATH:
            continue
        scanned_files += 1
        findings.extend(audit_file(candidate, relative))

    findings.sort(key=lambda item: (item.path, item.line, item.code, item.message))
    return AuditReport(scanned_files, tuple(findings))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "root",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root (defaults to the parent of scripts/)",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    arguments = _build_parser().parse_args(argv)
    report = audit_tree(arguments.root)
    for finding in report.findings:
        print(
            "{0}:{1}: {2}: {3}".format(
                finding.path, finding.line, finding.code, finding.message
            )
        )
    if report.findings:
        print(
            "offline source audit FAILED ({0} finding(s), {1} file(s) scanned)".format(
                len(report.findings), report.scanned_files
            ),
            file=sys.stderr,
        )
        return 1
    print("offline source audit passed ({0} file(s) scanned)".format(report.scanned_files))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
