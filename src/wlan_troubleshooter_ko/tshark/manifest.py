"""Portable TShark 공급망 매니페스트 검증."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, Tuple


_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_VERSION_PATTERN = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}(?:-[0-9A-Za-z.-]+)?$")
_APPROVAL_PATTERN = re.compile(r"^[A-Z0-9][A-Z0-9._-]{2,127}$")
_SAFE_PATH_PATTERN = re.compile(r"^[A-Za-z0-9._/-]+$")
_PLACEHOLDER_SHA256 = "0" * 64
_MAX_MANIFEST_BYTES = 1024 * 1024
_HASH_CHUNK_BYTES = 1024 * 1024
_REPARSE_POINT_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_WINDOWS_RESERVED_NAMES = {
    "aux",
    "con",
    "nul",
    "prn",
    "conin$",
    "conout$",
    *("com{0}".format(index) for index in range(1, 10)),
    *("lpt{0}".format(index) for index in range(1, 10)),
    *("com{0}".format(index) for index in ("¹", "²", "³")),
    *("lpt{0}".format(index) for index in ("¹", "²", "³")),
}


class BundleVerificationError(RuntimeError):
    """Portable TShark 번들이 승인 매니페스트와 일치하지 않는 경우."""


@dataclass(frozen=True)
class VerifiedBundle:
    root: Path
    version: str
    executable: Path
    files: Tuple[Path, ...]
    manifest_sha256: str
    declared_files: Tuple[Tuple[str, str, int], ...]
    root_snapshot: Tuple[int, ...]
    manifest_snapshot: Tuple[int, ...]
    file_snapshots: Tuple[Tuple[Path, Tuple[int, ...]], ...]
    directory_snapshots: Tuple[Tuple[Path, Tuple[int, ...]], ...]


def _safe_relative_path(raw: object) -> Path:
    if (
        not isinstance(raw, str)
        or not raw
        or "\x00" in raw
        or "\\" in raw
        or ":" in raw
        or not _SAFE_PATH_PATTERN.fullmatch(raw)
    ):
        raise BundleVerificationError("번들 파일 경로가 올바르지 않습니다.")
    pure_path = PurePosixPath(raw)
    if pure_path.is_absolute() or any(part in {"", ".", ".."} for part in pure_path.parts):
        raise BundleVerificationError("번들 내부의 상대 경로만 허용합니다.")
    for part in pure_path.parts:
        device_name = part.split(".", 1)[0].rstrip(" .").casefold()
        if part.endswith((" ", ".")) or device_name in _WINDOWS_RESERVED_NAMES:
            raise BundleVerificationError("Windows에서 안전한 번들 파일명만 허용합니다.")
    return Path(*pure_path.parts)


def _reject_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _stat_is_link_or_reparse(file_stat: os.stat_result) -> bool:
    return stat.S_ISLNK(file_stat.st_mode) or bool(
        (getattr(file_stat, "st_file_attributes", 0) or 0) & _REPARSE_POINT_FLAG
    )


def _absolute_path(path: Path) -> Path:
    try:
        return Path(os.path.abspath(os.fspath(path)))
    except (OSError, TypeError, ValueError) as exc:
        raise BundleVerificationError("Portable TShark 경로가 올바르지 않습니다.") from exc


def _path_components(path: Path) -> Iterable[Path]:
    current = Path(path.anchor)
    if path.anchor:
        yield current
        remaining = path.parts[1:]
    else:
        remaining = path.parts
    for part in remaining:
        current = current / part
        yield current


def _reject_linked_components(path: Path) -> Path:
    """해석 전의 모든 기존 경로 구성요소에서 링크와 reparse point를 거부한다."""

    absolute = _absolute_path(path)
    for component in _path_components(absolute):
        try:
            component_stat = os.lstat(component)
        except (OSError, ValueError) as exc:
            raise BundleVerificationError("Portable TShark 경로를 확인할 수 없습니다.") from exc
        if _stat_is_link_or_reparse(component_stat):
            raise BundleVerificationError(
                "Portable TShark 경로에 링크 또는 reparse point를 사용할 수 없습니다."
            )
    return absolute


def _stat_snapshot(file_stat: os.stat_result) -> Tuple[int, ...]:
    return (
        file_stat.st_dev,
        file_stat.st_ino,
        stat.S_IFMT(file_stat.st_mode),
        file_stat.st_nlink,
        file_stat.st_size,
        getattr(file_stat, "st_mtime_ns", int(file_stat.st_mtime * 1_000_000_000)),
        getattr(file_stat, "st_ctime_ns", int(file_stat.st_ctime * 1_000_000_000)),
        getattr(file_stat, "st_file_attributes", 0) or 0,
    )


def _open_regular_readonly(path: Path):
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        return os.fdopen(descriptor, "rb")
    except (OSError, ValueError):
        os.close(descriptor)
        raise


def _stable_file_stats(path: Path, handle) -> Tuple[os.stat_result, os.stat_result]:
    path_stat = os.lstat(path)
    handle_stat = os.fstat(handle.fileno())
    if (
        _stat_is_link_or_reparse(path_stat)
        or _stat_is_link_or_reparse(handle_stat)
        or not stat.S_ISREG(path_stat.st_mode)
        or not stat.S_ISREG(handle_stat.st_mode)
        or path_stat.st_nlink != 1
        or handle_stat.st_nlink != 1
        or _stat_snapshot(path_stat) != _stat_snapshot(handle_stat)
    ):
        raise BundleVerificationError(
            "번들 파일은 링크나 외부 hardlink 별칭이 없는 일반 파일이어야 합니다."
        )
    return path_stat, handle_stat


def _read_regular_file_stably(path: Path, maximum_bytes: int) -> bytes:
    """동일한 열린 파일 핸들의 전후 상태를 확인하며 제한된 바이트를 읽는다."""

    try:
        _reject_linked_components(path)
        with _open_regular_readonly(path) as handle:
            path_before, handle_before = _stable_file_stats(path, handle)
            if handle_before.st_size > maximum_bytes:
                raise BundleVerificationError("승인 매니페스트가 너무 큽니다.")
            value = handle.read(maximum_bytes + 1)
            handle_after = os.fstat(handle.fileno())
        _reject_linked_components(path)
        path_after = os.lstat(path)
    except BundleVerificationError:
        raise
    except OSError as exc:
        raise BundleVerificationError("번들 파일을 안전하게 읽을 수 없습니다.") from exc
    if (
        len(value) > maximum_bytes
        or len(value) != handle_before.st_size
        or _stat_is_link_or_reparse(handle_after)
        or _stat_is_link_or_reparse(path_after)
        or _stat_snapshot(path_before) != _stat_snapshot(handle_after)
        or _stat_snapshot(path_before) != _stat_snapshot(path_after)
    ):
        raise BundleVerificationError("번들 파일이 확인 중 변경됐습니다.")
    return value


def _hash_regular_file_stably(path: Path, expected_size: int) -> Tuple[str, Tuple[int, ...]]:
    """크기와 SHA-256을 동일 핸들에서 계산하고 전후 파일 정체성을 확인한다."""

    digest = hashlib.sha256()
    bytes_read = 0
    try:
        _reject_linked_components(path)
        with _open_regular_readonly(path) as handle:
            path_before, handle_before = _stable_file_stats(path, handle)
            if handle_before.st_size != expected_size:
                raise BundleVerificationError("Portable TShark 파일 크기가 일치하지 않습니다.")
            while True:
                chunk = handle.read(_HASH_CHUNK_BYTES)
                if not chunk:
                    break
                bytes_read += len(chunk)
                if bytes_read > expected_size:
                    raise BundleVerificationError("Portable TShark 파일 크기가 일치하지 않습니다.")
                digest.update(chunk)
            handle_after = os.fstat(handle.fileno())
        _reject_linked_components(path)
        path_after = os.lstat(path)
    except BundleVerificationError:
        raise
    except OSError as exc:
        raise BundleVerificationError("번들 파일을 안전하게 해시할 수 없습니다.") from exc
    if (
        bytes_read != expected_size
        or _stat_is_link_or_reparse(handle_after)
        or _stat_is_link_or_reparse(path_after)
        or _stat_snapshot(path_before) != _stat_snapshot(handle_after)
        or _stat_snapshot(path_before) != _stat_snapshot(path_after)
    ):
        raise BundleVerificationError("번들 파일이 해시 확인 중 변경됐습니다.")
    return digest.hexdigest(), _stat_snapshot(path_after)


def _discover_bundle_files(
    root: Path,
) -> Tuple[Tuple[Path, ...], Tuple[Tuple[Path, Tuple[int, ...]], ...]]:
    """reparse directory를 따라가지 않는 수동 순회로 모든 일반 파일을 찾는다."""

    files = []
    pending = [root]
    directory_snapshots = {}
    try:
        while pending:
            directory = pending.pop()
            _reject_linked_components(directory)
            directory_before = os.lstat(directory)
            if (
                _stat_is_link_or_reparse(directory_before)
                or not stat.S_ISDIR(directory_before.st_mode)
            ):
                raise BundleVerificationError("번들 디렉터리가 안전하지 않습니다.")
            with os.scandir(directory) as entries:
                for entry in entries:
                    entry_path = Path(entry.path)
                    entry_stat = entry.stat(follow_symlinks=False)
                    if _stat_is_link_or_reparse(entry_stat):
                        raise BundleVerificationError(
                            "번들 안의 링크 또는 reparse point는 허용하지 않습니다."
                        )
                    if stat.S_ISDIR(entry_stat.st_mode):
                        pending.append(entry_path)
                    elif stat.S_ISREG(entry_stat.st_mode):
                        files.append(entry_path)
                    else:
                        raise BundleVerificationError(
                            "번들에는 일반 파일과 디렉터리만 허용합니다."
                        )
            _reject_linked_components(directory)
            directory_after = os.lstat(directory)
            if _stat_snapshot(directory_before) != _stat_snapshot(directory_after):
                raise BundleVerificationError("번들 디렉터리가 확인 중 변경됐습니다.")
            directory_snapshots[directory] = _stat_snapshot(directory_after)
        for directory, expected_snapshot in directory_snapshots.items():
            _reject_linked_components(directory)
            if _stat_snapshot(os.lstat(directory)) != expected_snapshot:
                raise BundleVerificationError("번들 디렉터리가 확인 중 변경됐습니다.")
    except BundleVerificationError:
        raise
    except OSError as exc:
        raise BundleVerificationError("Portable TShark 파일 목록을 확인할 수 없습니다.") from exc
    return (
        tuple(files),
        tuple(sorted(directory_snapshots.items(), key=lambda item: str(item[0]))),
    )


def _assert_regular_snapshot(path: Path, expected_snapshot: Tuple[int, ...]) -> None:
    _reject_linked_components(path)
    try:
        current = os.lstat(path)
    except OSError as exc:
        raise BundleVerificationError("번들 파일 정체성을 다시 확인할 수 없습니다.") from exc
    if (
        _stat_is_link_or_reparse(current)
        or not stat.S_ISREG(current.st_mode)
        or current.st_nlink != 1
        or _stat_snapshot(current) != expected_snapshot
    ):
        raise BundleVerificationError("번들 파일이 검증 후 변경됐습니다.")


def _assert_directory_snapshot(path: Path, expected_snapshot: Tuple[int, ...]) -> None:
    _reject_linked_components(path)
    try:
        current = os.lstat(path)
    except OSError as exc:
        raise BundleVerificationError("번들 디렉터리를 다시 확인할 수 없습니다.") from exc
    if (
        _stat_is_link_or_reparse(current)
        or not stat.S_ISDIR(current.st_mode)
        or _stat_snapshot(current) != expected_snapshot
    ):
        raise BundleVerificationError("번들 디렉터리가 검증 후 변경됐습니다.")


def revalidate_bundle_snapshot(bundle: VerifiedBundle) -> None:
    """전체 해시 검증 뒤 보관한 파일·디렉터리 정체성을 실행 직전에 확인한다."""

    _assert_directory_snapshot(bundle.root, bundle.root_snapshot)
    _assert_regular_snapshot(bundle.root / "manifest.json", bundle.manifest_snapshot)
    for path, expected_snapshot in bundle.file_snapshots:
        _assert_regular_snapshot(path, expected_snapshot)
    for path, expected_snapshot in bundle.directory_snapshots:
        _assert_directory_snapshot(path, expected_snapshot)


def verify_bundle(vendor_root: Path) -> VerifiedBundle:
    """전체 허용 파일, SHA-256, 실행 파일, 라이선스 문서를 확인한다."""

    try:
        unchecked_root = _reject_linked_components(vendor_root)
        root = unchecked_root.resolve(strict=True)
        _reject_linked_components(root)
        root_before = os.lstat(root)
    except (OSError, ValueError, BundleVerificationError) as exc:
        raise BundleVerificationError("Portable TShark 디렉터리가 없습니다.") from exc
    if _stat_is_link_or_reparse(root_before) or not stat.S_ISDIR(root_before.st_mode):
        raise BundleVerificationError("Portable TShark 루트는 일반 디렉터리여야 합니다.")
    manifest_path = root / "manifest.json"
    try:
        _reject_linked_components(manifest_path)
        manifest_bytes = _read_regular_file_stably(manifest_path, _MAX_MANIFEST_BYTES)
        manifest = json.loads(
            manifest_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (BundleVerificationError, UnicodeError, ValueError) as exc:
        raise BundleVerificationError("승인된 manifest.json을 읽을 수 없습니다.") from exc
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {
            "schema_version",
            "version",
            "approval_reference",
            "executable",
            "files",
        }
        or type(manifest.get("schema_version")) is not int
        or manifest.get("schema_version") != 1
    ):
        raise BundleVerificationError("지원하지 않는 TShark 매니페스트입니다.")

    version = manifest.get("version")
    approval = manifest.get("approval_reference")
    if (
        not isinstance(version, str)
        or not _VERSION_PATTERN.fullmatch(version)
        or "APPROVED" in version.upper()
    ):
        raise BundleVerificationError("승인된 정확한 TShark 버전이 필요합니다.")
    if not isinstance(approval, str) or not _APPROVAL_PATTERN.fullmatch(approval):
        raise BundleVerificationError("내부 승인 참조가 필요합니다.")

    executable_relative = _safe_relative_path(manifest.get("executable"))
    if executable_relative != Path("tshark.exe"):
        raise BundleVerificationError("승인 실행 파일은 tshark.exe여야 합니다.")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise BundleVerificationError("번들의 전체 파일 해시 목록이 필요합니다.")

    declared: Dict[Path, Tuple[str, int]] = {}
    casefolded_paths = set()
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size_bytes"}:
            raise BundleVerificationError("파일 매니페스트 항목이 올바르지 않습니다.")
        relative = _safe_relative_path(entry.get("path"))
        digest = entry.get("sha256")
        size_bytes = entry.get("size_bytes")
        if (
            not isinstance(digest, str)
            or not _SHA256_PATTERN.fullmatch(digest)
            or digest == _PLACEHOLDER_SHA256
            or type(size_bytes) is not int
            or size_bytes < 0
        ):
            raise BundleVerificationError("실제 SHA-256과 파일 크기가 필요합니다.")
        path_key = relative.as_posix().casefold()
        if relative in declared or path_key in casefolded_paths:
            raise BundleVerificationError("매니페스트에 중복 파일이 있습니다.")
        casefolded_paths.add(path_key)
        declared[relative] = (digest, size_bytes)

    if executable_relative not in declared or Path("COPYING") not in declared:
        raise BundleVerificationError("실행 파일과 COPYING을 모두 매니페스트에 포함해야 합니다.")

    verified = []
    for relative, (expected, expected_size) in declared.items():
        target = root / relative
        try:
            _reject_linked_components(target)
            resolved = target.resolve(strict=True)
            resolved.relative_to(root)
            _reject_linked_components(resolved)
        except (OSError, ValueError, BundleVerificationError) as exc:
            raise BundleVerificationError("번들 파일이 없거나 루트 밖을 가리킵니다.") from exc
        try:
            actual, _snapshot = _hash_regular_file_stably(resolved, expected_size)
        except BundleVerificationError:
            raise
        if not hmac.compare_digest(actual, expected):
            raise BundleVerificationError("Portable TShark 파일 해시가 일치하지 않습니다.")
        verified.append(resolved)

    metadata_paths = {Path("manifest.json"), Path("manifest.example.json"), Path("README.md")}
    discovered, directory_snapshots = _discover_bundle_files(root)
    actual_files = {
        path.relative_to(root)
        for path in discovered
        if path.relative_to(root) not in metadata_paths
    }
    if len({path.as_posix().casefold() for path in actual_files}) != len(actual_files):
        raise BundleVerificationError("Windows에서 충돌하는 번들 파일명이 있습니다.")
    if actual_files != set(declared):
        raise BundleVerificationError("매니페스트에 없는 파일이 번들에 포함돼 있습니다.")

    try:
        manifest_after = _read_regular_file_stably(manifest_path, _MAX_MANIFEST_BYTES)
        manifest_snapshot = _stat_snapshot(os.lstat(manifest_path))
    except (OSError, BundleVerificationError) as exc:
        raise BundleVerificationError("Portable TShark 번들이 확인 중 변경됐습니다.") from exc
    if not hmac.compare_digest(manifest_bytes, manifest_after):
        raise BundleVerificationError("Portable TShark 번들이 확인 중 변경됐습니다.")

    # 첫 번째 파일을 확인한 뒤 다른 파일을 해시하는 동안 그 파일이 바뀌는
    # 순차 검증 race를 막기 위해 전체 선언 파일을 다시 해시한다.
    final_file_snapshots = []
    for relative, (expected, expected_size) in declared.items():
        resolved = root / relative
        actual, final_snapshot = _hash_regular_file_stably(resolved, expected_size)
        if not hmac.compare_digest(actual, expected):
            raise BundleVerificationError("Portable TShark 파일 해시가 일치하지 않습니다.")
        final_file_snapshots.append((resolved, final_snapshot))

    try:
        final_manifest = _read_regular_file_stably(manifest_path, _MAX_MANIFEST_BYTES)
        manifest_snapshot = _stat_snapshot(os.lstat(manifest_path))
        if not hmac.compare_digest(manifest_bytes, final_manifest):
            raise BundleVerificationError("Portable TShark 번들이 확인 중 변경됐습니다.")
        for path, expected_snapshot in final_file_snapshots:
            _assert_regular_snapshot(path, expected_snapshot)
        for directory, expected_snapshot in directory_snapshots:
            _assert_directory_snapshot(directory, expected_snapshot)
        root_after = os.lstat(root)
    except (OSError, BundleVerificationError) as exc:
        raise BundleVerificationError("Portable TShark 번들이 확인 중 변경됐습니다.") from exc
    if (
        _stat_is_link_or_reparse(root_after)
        or _stat_snapshot(root_before) != _stat_snapshot(root_after)
    ):
        raise BundleVerificationError("Portable TShark 번들이 확인 중 변경됐습니다.")

    executable = root / executable_relative
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    declared_files = tuple(
        sorted(
            (relative.as_posix(), digest, size_bytes)
            for relative, (digest, size_bytes) in declared.items()
        )
    )
    return VerifiedBundle(
        root,
        version,
        executable,
        tuple(sorted(verified)),
        manifest_sha256,
        declared_files,
        _stat_snapshot(root_after),
        manifest_snapshot,
        tuple(sorted(final_file_snapshots, key=lambda item: str(item[0]))),
        directory_snapshots,
    )
