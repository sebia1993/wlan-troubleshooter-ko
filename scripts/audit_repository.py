#!/usr/bin/env python3
"""Reject tracked captures, private artifacts, and generated analysis output."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import gzip
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import List, Optional, Sequence, Tuple


_CAPTURE_SUFFIXES = (
    ".cap",
    ".cap.gz",
    ".erf",
    ".etl",
    ".etl.gz",
    ".pcap",
    ".pcap.gz",
    ".pcapng",
    ".pcapng.gz",
)

_CAPTURE_MAGICS = {
    bytes.fromhex("d4c3b2a1"),
    bytes.fromhex("a1b2c3d4"),
    bytes.fromhex("4d3cb2a1"),
    bytes.fromhex("a1b23c4d"),
    bytes.fromhex("0a0d0d0a"),
}

_PRIVATE_PROFILE_DIRECTORIES = {
    "customer",
    "enterprise",
    "local",
    "private",
    "sensitive",
    "site-specific",
}

_PRIVATE_PROFILE_NAME_MARKERS = (
    ".local.",
    ".private.",
    ".secret.",
    ".sensitive.",
)

_PRIVATE_PROFILE_EXACT_NAMES = {
    ".env",
    "credentials.json",
    "secrets.json",
}

_PRIVATE_PROFILE_NAME_PREFIXES = (
    "customer.",
    "local.",
    "private.",
    "site-specific.",
)

_SENSITIVE_EXACT_NAMES = {
    ".env",
    "credentials.json",
    "secrets.json",
    "device-config.txt",
    "running-config.txt",
    "startup-config.txt",
}

_SENSITIVE_NAME_SUFFIXES = (
    ".local.json",
    ".private.json",
    ".secret.json",
    ".credentials.json",
)

_GENERATED_OR_PRIVATE_DIRECTORIES = {
    ".analysis",
    ".venv",
    "build",
    "captures",
    "dist",
    "extracted",
    "logs",
    "pcaps",
    "reports",
    "tmp",
    "venv",
    "work",
}

_EXTRACTED_OUTPUT_EXACT_NAMES = {
    "analysis.json",
    "events.json",
    "findings.json",
    "normalized-events.json",
    "normalized.json",
    "packets.json",
    "sessions.json",
    "timeline.json",
}

_REPORT_OUTPUT_SUFFIXES = {
    ".csv",
    ".htm",
    ".html",
    ".json",
    ".pdf",
    ".tsv",
    ".xml",
}

_DEVICE_CONFIGURATION_SUFFIXES = {
    ".cfg",
    ".conf",
}

_UNAPPROVED_BINARY_SUFFIXES = {
    ".a",
    ".bin",
    ".cab",
    ".com",
    ".dll",
    ".dylib",
    ".exe",
    ".jar",
    ".lib",
    ".msi",
    ".msix",
    ".msp",
    ".o",
    ".obj",
    ".pyc",
    ".pyd",
    ".scr",
    ".so",
    ".sys",
    ".wasm",
    ".whl",
}

_ARCHIVE_SUFFIXES = (
    ".7z",
    ".bz2",
    ".gz",
    ".rar",
    ".tar",
    ".tar.bz2",
    ".tar.gz",
    ".tar.xz",
    ".tbz2",
    ".tgz",
    ".txz",
    ".xz",
    ".zip",
)

_EXECUTABLE_MAGICS = (
    b"MZ",
    b"\x7fELF",
    bytes.fromhex("feedface"),
    bytes.fromhex("feedfacf"),
    bytes.fromhex("cefaedfe"),
    bytes.fromhex("cffaedfe"),
    bytes.fromhex("cafebabe"),
    bytes.fromhex("bebafeca"),
    bytes.fromhex("0061736d"),
    b"!<arch>\n",
    bytes.fromhex("d0cf11e0a1b11ae1"),
)

_ARCHIVE_MAGICS = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    bytes.fromhex("377abcaf271c"),
    bytes.fromhex("526172211a0700"),
    bytes.fromhex("526172211a070100"),
    bytes.fromhex("1f8b"),
    b"BZh",
    bytes.fromhex("fd377a585a00"),
)

_LOG_OUTPUT_PATTERN = re.compile(r"(?i)\.log(?:\.\d+|\.(?:gz|zip))?$")
_REPORT_NAME_TOKEN_PATTERN = re.compile(r"[^a-z0-9]+")

_ALLOWED_VENDOR_METADATA = {
    "vendor/wireshark/README.md",
    "vendor/wireshark/manifest.example.json",
}

_MAX_TRACKED_FILE_BYTES = 64 * 1024 * 1024
_OBJECT_ID_PATTERN = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


@dataclass(frozen=True)
class Finding:
    path: str
    code: str
    message: str


@dataclass(frozen=True)
class AuditReport:
    mode: str
    scanned_files: int
    findings: Tuple[Finding, ...]


@dataclass(frozen=True)
class TrackedFile:
    path: Path
    mode: str
    object_id: str


def _run_git(root: Path, arguments: Sequence[str]) -> subprocess.CompletedProcess:
    command = ["git", "-C", str(root)] + list(arguments)
    return subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=20,
        shell=False,
    )


def _looks_like_git_worktree(root: Path) -> bool:
    return any((candidate / ".git").exists() for candidate in (root,) + tuple(root.parents))


def _tracked_files(
    root: Path,
) -> Tuple[Optional[Path], Optional[List[TrackedFile]], List[Finding]]:
    try:
        probe = _run_git(root, ["rev-parse", "--is-inside-work-tree"])
    except (OSError, subprocess.SubprocessError) as exc:
        if _looks_like_git_worktree(root):
            return None, None, [
                Finding(".", "GIT_UNAVAILABLE", "cannot inspect tracked files: " + str(exc))
            ]
        return None, None, []
    if probe.returncode != 0 or probe.stdout.strip() != b"true":
        if _looks_like_git_worktree(root):
            return None, None, [
                Finding(
                    ".",
                    "GIT_ERROR",
                    "cannot confirm Git worktree state: "
                    + probe.stderr.decode("utf-8", errors="replace").strip(),
                )
            ]
        return None, None, []

    top_level = _run_git(root, ["rev-parse", "--show-toplevel"])
    if top_level.returncode != 0:
        return None, None, [
            Finding(
                ".",
                "GIT_ERROR",
                "cannot resolve repository root: "
                + top_level.stderr.decode("utf-8", errors="replace").strip(),
            )
        ]
    repository_root = Path(os.fsdecode(top_level.stdout.rstrip(b"\r\n"))).resolve()

    listed = _run_git(repository_root, ["ls-files", "--stage", "-z", "--"])
    if listed.returncode != 0:
        return repository_root, None, [
            Finding(
                ".",
                "GIT_ERROR",
                "cannot list tracked files: "
                + listed.stderr.decode("utf-8", errors="replace").strip(),
            )
        ]

    paths: List[TrackedFile] = []
    findings: List[Finding] = []
    for raw_record in listed.stdout.split(b"\0"):
        if not raw_record:
            continue
        metadata, separator, raw_path = raw_record.partition(b"\t")
        metadata_parts = metadata.split()
        if not separator or len(metadata_parts) != 3:
            findings.append(
                Finding(".", "GIT_INDEX_INVALID", "cannot parse a tracked index entry")
            )
            continue
        mode = metadata_parts[0].decode("ascii", errors="replace")
        object_id = metadata_parts[1].decode("ascii", errors="replace")
        stage = metadata_parts[2]
        relative_text = os.fsdecode(raw_path)
        pure_path = PurePosixPath(relative_text)
        if pure_path.is_absolute() or ".." in pure_path.parts:
            findings.append(
                Finding(relative_text, "TRACKED_PATH_INVALID", "tracked path escapes repository")
            )
            continue
        if stage != b"0" or not _OBJECT_ID_PATTERN.fullmatch(object_id):
            findings.append(
                Finding(relative_text, "GIT_INDEX_INVALID", "unmerged or invalid index entry")
            )
            continue
        paths.append(
            TrackedFile(repository_root.joinpath(*pure_path.parts), mode, object_id)
        )
    return repository_root, paths, findings


def _filesystem_files(root: Path) -> List[Path]:
    files: List[Path] = []
    for current, directory_names, file_names in os.walk(str(root), followlinks=False):
        directory_names[:] = sorted(name for name in directory_names if name != ".git")
        current_path = Path(current)
        files.extend(current_path / name for name in sorted(file_names))
    return files


def _is_capture_name(relative_path: str) -> bool:
    lowered = relative_path.lower()
    return lowered.endswith(_CAPTURE_SUFFIXES)


def _is_private_profile_path(relative_path: str) -> bool:
    pure_path = PurePosixPath(relative_path.lower())
    parts = pure_path.parts
    try:
        profile_index = parts.index("profiles")
    except ValueError:
        return False
    profile_tail = parts[profile_index + 1 :]
    if any(part in _PRIVATE_PROFILE_DIRECTORIES for part in profile_tail[:-1]):
        return True
    if not profile_tail:
        return False
    name = profile_tail[-1]
    if name.endswith((".json", ".yaml", ".yml")) and not name.endswith(".example.json"):
        return True
    return (
        name in _PRIVATE_PROFILE_EXACT_NAMES
        or any(marker in name for marker in _PRIVATE_PROFILE_NAME_MARKERS)
        or name.startswith(_PRIVATE_PROFILE_NAME_PREFIXES)
        or name.startswith(("local-", "private-", "customer-", "site-specific-"))
    )


def _is_sensitive_file_path(relative_path: str) -> bool:
    name = PurePosixPath(relative_path.casefold()).name
    return (
        name in _SENSITIVE_EXACT_NAMES
        or name.startswith(".env.")
        or name.endswith(_SENSITIVE_NAME_SUFFIXES)
    )


def _example_profile_is_synthetic(content: bytes, relative_path: str) -> bool:
    pure_path = PurePosixPath(relative_path.lower())
    if "profiles" not in pure_path.parts or not pure_path.name.endswith(".example.json"):
        return True
    try:
        value = json.loads(content.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return False
    expected_fields = {
        "schema_version",
        "profile_version",
        "profile_id",
        "display_name",
        "synthetic",
        "radius_servers",
        "dhcp_servers",
        "dns_servers",
        "vlans",
    }
    return (
        isinstance(value, dict)
        and set(value) == expected_fields
        and type(value.get("schema_version")) is int
        and value["schema_version"] == 1
        and isinstance(value.get("profile_version"), str)
        and bool(value["profile_version"])
        and value.get("profile_id") == "SYNTHETIC-EXAMPLE"
        and value.get("display_name") == "문서용 예시 사이트"
        and value.get("synthetic") is True
        and all(
            value.get(key) == []
            for key in ("radius_servers", "dhcp_servers", "dns_servers", "vlans")
        )
    )


def _capture_magic(content: bytes) -> Optional[bytes]:
    prefix = content[:4]
    if prefix in _CAPTURE_MAGICS:
        return prefix
    if prefix.startswith(b"\x1f\x8b"):
        with gzip.GzipFile(fileobj=io.BytesIO(content), mode="rb") as handle:
            inner_prefix = handle.read(4)
        if inner_prefix in _CAPTURE_MAGICS:
            return inner_prefix
    return None


def _read_index_blob(root: Path, tracked: TrackedFile) -> bytes:
    size_result = _run_git(root, ["cat-file", "-s", tracked.object_id])
    if size_result.returncode != 0:
        raise OSError("cannot read tracked object size")
    try:
        size = int(size_result.stdout.strip())
    except ValueError as exc:
        raise OSError("tracked object size is invalid") from exc
    if size < 0 or size > _MAX_TRACKED_FILE_BYTES:
        raise OSError("tracked file exceeds the inspection size limit")
    blob_result = _run_git(root, ["cat-file", "blob", tracked.object_id])
    if blob_result.returncode != 0 or len(blob_result.stdout) != size:
        raise OSError("cannot read the exact tracked object")
    return blob_result.stdout


def _is_generated_or_private_output(relative_path: str) -> bool:
    return any(
        part.casefold() in _GENERATED_OR_PRIVATE_DIRECTORIES
        for part in PurePosixPath(relative_path).parts
    )


def _is_log_output_name(relative_path: str) -> bool:
    name = PurePosixPath(relative_path).name
    return _LOG_OUTPUT_PATTERN.search(name) is not None


def _is_report_output_name(relative_path: str) -> bool:
    path = PurePosixPath(relative_path.casefold())
    if path.suffix not in _REPORT_OUTPUT_SUFFIXES:
        return False
    tokens = {
        token
        for token in _REPORT_NAME_TOKEN_PATTERN.split(path.stem)
        if token
    }
    return "report" in tokens


def _is_extracted_output_name(relative_path: str) -> bool:
    name = PurePosixPath(relative_path.casefold()).name
    return name in _EXTRACTED_OUTPUT_EXACT_NAMES


def _is_device_configuration_name(relative_path: str) -> bool:
    return PurePosixPath(relative_path.casefold()).suffix in _DEVICE_CONFIGURATION_SUFFIXES


def _is_unapproved_binary_name(relative_path: str) -> bool:
    return PurePosixPath(relative_path.casefold()).suffix in _UNAPPROVED_BINARY_SUFFIXES


def _is_archive_name(relative_path: str) -> bool:
    return relative_path.casefold().endswith(_ARCHIVE_SUFFIXES)


def _unsafe_payload_magic(content: bytes) -> Optional[str]:
    if any(content.startswith(magic) for magic in _EXECUTABLE_MAGICS):
        return "EXECUTABLE_MAGIC"
    if any(content.startswith(magic) for magic in _ARCHIVE_MAGICS):
        return "ARCHIVE_MAGIC"
    if len(content) >= 262 and content[257:262] == b"ustar":
        return "ARCHIVE_MAGIC"
    if content.startswith(b"%PDF-"):
        return "REPORT_MAGIC"
    if content.startswith(b"SQLite format 3\x00"):
        return "DATABASE_MAGIC"
    return None


def _is_unapproved_vendor_payload(relative_path: str) -> bool:
    normalized = relative_path.replace("\\", "/")
    lowered = normalized.casefold()
    return lowered.startswith("vendor/wireshark/") and normalized not in _ALLOWED_VENDOR_METADATA


def audit_repository(root: Path) -> AuditReport:
    try:
        requested_root = root.resolve(strict=True)
    except OSError as exc:
        return AuditReport(
            "invalid",
            0,
            (Finding(str(root), "ROOT_INVALID", "cannot resolve audit root: " + str(exc)),),
        )
    if not requested_root.is_dir():
        return AuditReport(
            "invalid",
            0,
            (Finding(str(requested_root), "ROOT_INVALID", "audit root is not a directory"),),
        )

    try:
        repository_root, tracked, discovery_findings = _tracked_files(requested_root)
    except (OSError, subprocess.SubprocessError) as exc:
        return AuditReport(
            "git",
            0,
            (Finding(".", "GIT_ERROR", "cannot inspect repository: " + str(exc)),),
        )

    if tracked is None and discovery_findings:
        return AuditReport("git", 0, tuple(discovery_findings))
    if tracked is None:
        repository_root = requested_root
        candidates = _filesystem_files(repository_root)
        mode = "filesystem"
    else:
        candidates = tracked
        mode = "git-tracked"

    assert repository_root is not None
    findings = list(discovery_findings)
    if mode == "git-tracked" and not candidates:
        findings.append(
            Finding(
                ".",
                "EMPTY_INDEX",
                "no tracked files are available for the repository audit",
            )
        )
    scanned_files = 0
    for item in candidates:
        candidate = item.path if isinstance(item, TrackedFile) else item
        try:
            relative = candidate.relative_to(repository_root).as_posix()
        except ValueError:
            findings.append(
                Finding(str(candidate), "PATH_ESCAPE", "candidate path escapes repository")
            )
            continue
        if isinstance(item, TrackedFile) and item.mode not in {"100644", "100755"}:
            findings.append(
                Finding(relative, "TRACKED_SYMLINK", "tracked symlinks are not accepted by this audit")
            )
            continue
        if isinstance(item, TrackedFile):
            try:
                content = _read_index_blob(repository_root, item)
            except (OSError, subprocess.SubprocessError) as exc:
                findings.append(
                    Finding(relative, "FILE_UNREADABLE", "cannot inspect tracked file: " + str(exc))
                )
                continue
        else:
            if candidate.is_symlink():
                findings.append(
                    Finding(relative, "TRACKED_SYMLINK", "symlinks are not accepted by this audit")
                )
                continue
            if not candidate.is_file():
                findings.append(
                    Finding(relative, "TRACKED_FILE_MISSING", "path is not a regular file")
                )
                continue
            try:
                content = candidate.read_bytes()
            except OSError as exc:
                findings.append(
                    Finding(relative, "FILE_UNREADABLE", "cannot inspect file: " + str(exc))
                )
                continue

        scanned_files += 1
        if _is_capture_name(relative):
            findings.append(
                Finding(relative, "CAPTURE_EXTENSION", "packet capture files must not be committed")
            )
        if _is_private_profile_path(relative):
            findings.append(
                Finding(
                    relative,
                    "PRIVATE_PROFILE_PATH",
                    "local or organization-specific profiles must not be committed",
                )
            )
        if _is_sensitive_file_path(relative):
            findings.append(
                Finding(
                    relative,
                    "SENSITIVE_FILE",
                    "credential, environment, or device configuration files must not be committed",
                )
            )
        elif not _example_profile_is_synthetic(content, relative):
            findings.append(
                Finding(
                    relative,
                    "PROFILE_EXAMPLE_NOT_SYNTHETIC",
                    "committable profile examples must explicitly declare synthetic=true",
                )
            )
        if _is_generated_or_private_output(relative):
            findings.append(
                Finding(
                    relative,
                    "GENERATED_OUTPUT",
                    "generated or private analysis output must not be committed",
                )
            )
        if (
            _is_log_output_name(relative)
            or _is_report_output_name(relative)
            or _is_extracted_output_name(relative)
        ):
            findings.append(
                Finding(
                    relative,
                    "GENERATED_OUTPUT_NAME",
                    "logs, reports, and extracted analysis output must not be committed",
                )
            )
        if _is_device_configuration_name(relative):
            findings.append(
                Finding(
                    relative,
                    "DEVICE_CONFIGURATION",
                    "device configuration and backup files must not be committed",
                )
            )
        if _is_unapproved_binary_name(relative):
            findings.append(
                Finding(
                    relative,
                    "BINARY_PAYLOAD",
                    "executable and native binary payloads must not be committed",
                )
            )
        if _is_archive_name(relative):
            findings.append(
                Finding(
                    relative,
                    "ARCHIVE_PAYLOAD",
                    "archives are not accepted in this source-only repository",
                )
            )
        if _is_unapproved_vendor_payload(relative):
            findings.append(
                Finding(
                    relative,
                    "VENDOR_PAYLOAD",
                    "approved Portable TShark payloads must be supplied outside Git",
                )
            )
        try:
            magic = _capture_magic(content)
        except (EOFError, gzip.BadGzipFile) as exc:
            findings.append(
                Finding(relative, "FILE_UNREADABLE", "cannot inspect tracked file: " + str(exc))
            )
            continue
        if magic is not None:
            findings.append(
                Finding(
                    relative,
                    "CAPTURE_MAGIC",
                    "packet capture content is forbidden even when renamed",
                )
            )
        unsafe_magic = _unsafe_payload_magic(content)
        if unsafe_magic is not None:
            findings.append(
                Finding(
                    relative,
                    unsafe_magic,
                    "renamed executable, archive, report, or database payload is forbidden",
                )
            )

    findings.sort(key=lambda item: (item.path, item.code, item.message))
    return AuditReport(mode, scanned_files, tuple(findings))


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
    report = audit_repository(arguments.root)
    for finding in report.findings:
        print("{0}: {1}: {2}".format(finding.path, finding.code, finding.message))
    if report.findings:
        print(
            "repository audit FAILED ({0} finding(s), {1} file(s) scanned, mode={2})".format(
                len(report.findings), report.scanned_files, report.mode
            ),
            file=sys.stderr,
        )
        return 1
    print(
        "repository audit passed ({0} file(s) scanned, mode={1})".format(
            report.scanned_files, report.mode
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
