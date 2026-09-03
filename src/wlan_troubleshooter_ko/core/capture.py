"""로컬 PCAP/PCAPNG 파일의 최소 안전 검증."""

from __future__ import annotations

import hashlib
import os
import stat
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Optional, Union


PathLike = Union[str, os.PathLike]

_PCAP_MAGIC = {
    bytes.fromhex("d4c3b2a1"),
    bytes.fromhex("a1b2c3d4"),
    bytes.fromhex("4d3cb2a1"),
    bytes.fromhex("a1b23c4d"),
}
_PCAPNG_MAGIC = bytes.fromhex("0a0d0d0a")
_PCAPNG_BYTE_ORDER_MAGIC = {
    bytes.fromhex("1a2b3c4d"),
    bytes.fromhex("4d3c2b1a"),
}


class CaptureValidationError(ValueError):
    """입력 파일이 로컬 캡처 안전 정책을 충족하지 못한 경우."""


@dataclass(frozen=True)
class CaptureInfo:
    """검증이 끝난 캡처의 민감하지 않은 메타데이터."""

    path: Path
    capture_format: str
    size_bytes: int
    sha256: str


def _reject_non_local_path(raw_path: str) -> None:
    if "\x00" in raw_path:
        raise CaptureValidationError("파일 경로에 NUL 문자를 사용할 수 없습니다.")
    if "://" in raw_path or raw_path.startswith(("\\\\", "//")):
        raise CaptureValidationError("로컬 파일 경로만 사용할 수 있습니다.")


def _is_link_or_reparse(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    attributes = getattr(metadata, "st_file_attributes", 0) or 0
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag)


def _reject_linked_components(path: Path) -> Path:
    absolute = Path(os.path.abspath(str(path)))
    _reject_non_local_path(str(absolute))
    anchor = Path(absolute.anchor)
    for parent in reversed(absolute.parents):
        if parent == anchor:
            continue
        if _is_link_or_reparse(parent):
            raise CaptureValidationError("심볼릭 링크나 재분석 지점 경로는 허용하지 않습니다.")
    if _is_link_or_reparse(absolute):
        raise CaptureValidationError("심볼릭 링크나 재분석 지점 캡처는 허용하지 않습니다.")
    return absolute


def _sha256_handle(
    handle: BinaryIO,
    cancel_event: Optional[threading.Event],
    chunk_size: int,
) -> str:
    if chunk_size <= 0:
        raise CaptureValidationError("해시 청크 크기가 올바르지 않습니다.")
    digest = hashlib.sha256()
    handle.seek(0)
    while True:
        if cancel_event is not None and cancel_event.is_set():
            raise CaptureValidationError("파일 확인이 취소됐습니다.")
        chunk = handle.read(chunk_size)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def _same_file_state(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        first.st_size == second.st_size
        and first.st_ino == second.st_ino
        and first.st_dev == second.st_dev
        and first.st_mtime_ns == second.st_mtime_ns
        and first.st_ctime_ns == second.st_ctime_ns
    )


def sha256_file(
    path: Path,
    chunk_size: int = 1024 * 1024,
    cancel_event: Optional[threading.Event] = None,
) -> str:
    try:
        with path.open("rb") as handle:
            return _sha256_handle(handle, cancel_event, chunk_size)
    except CaptureValidationError:
        raise
    except OSError:
        raise CaptureValidationError("캡처 파일 해시를 계산할 수 없습니다.") from None


def validate_capture(
    path_like: PathLike,
    cancel_event: Optional[threading.Event] = None,
) -> CaptureInfo:
    """확장자와 파일 매직을 모두 검사하고 원본 해시를 계산한다."""

    raw_path = os.fspath(path_like)
    if not isinstance(raw_path, str):
        raise CaptureValidationError("파일 경로는 문자열 형식이어야 합니다.")
    _reject_non_local_path(raw_path)
    try:
        expanded = Path(raw_path).expanduser()
    except (OSError, RuntimeError):
        raise CaptureValidationError("파일 경로를 안전하게 확인할 수 없습니다.") from None
    _reject_non_local_path(str(expanded))
    candidate = _reject_linked_components(expanded)
    suffix = candidate.suffix.lower()
    if suffix not in {".pcap", ".pcapng"}:
        raise CaptureValidationError(".pcap 또는 .pcapng 파일만 선택할 수 있습니다.")
    try:
        resolved = candidate.resolve(strict=True)
        with resolved.open("rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise CaptureValidationError("일반 파일만 분석할 수 있습니다.")
            if cancel_event is not None and cancel_event.is_set():
                raise CaptureValidationError("파일 확인이 취소됐습니다.")
            header = handle.read(28)

            if header[:4] in _PCAP_MAGIC:
                if suffix != ".pcap" or len(header) < 24:
                    raise CaptureValidationError(
                        "PCAP 헤더가 잘렸거나 확장자와 일치하지 않습니다."
                    )
                capture_format = "pcap"
            elif header[:4] == _PCAPNG_MAGIC:
                if (
                    suffix != ".pcapng"
                    or len(header) < 28
                    or header[8:12] not in _PCAPNG_BYTE_ORDER_MAGIC
                ):
                    raise CaptureValidationError(
                        "PCAPNG 헤더가 잘렸거나 확장자와 일치하지 않습니다."
                    )
                byte_order = (
                    "little" if header[8:12] == bytes.fromhex("4d3c2b1a") else "big"
                )
                block_length = int.from_bytes(header[4:8], byteorder=byte_order)
                if block_length < 28 or block_length % 4 or block_length > metadata.st_size:
                    raise CaptureValidationError(
                        "PCAPNG Section Header Block 길이가 올바르지 않습니다."
                    )
                handle.seek(block_length - 4)
                trailing_bytes = handle.read(4)
                if len(trailing_bytes) != 4:
                    raise CaptureValidationError("PCAPNG Section Header Block이 잘렸습니다.")
                trailing_length = int.from_bytes(trailing_bytes, byteorder=byte_order)
                if trailing_length != block_length:
                    raise CaptureValidationError(
                        "PCAPNG Section Header Block 길이가 일치하지 않습니다."
                    )
                capture_format = "pcapng"
            else:
                raise CaptureValidationError("지원하는 PCAP/PCAPNG 파일 매직이 아닙니다.")

            digest = _sha256_handle(handle, cancel_event, 1024 * 1024)
            final_open_metadata = os.fstat(handle.fileno())
            if not _same_file_state(metadata, final_open_metadata):
                raise CaptureValidationError("파일이 확인 중 변경됐습니다.")
        path_metadata = resolved.stat()
    except CaptureValidationError:
        raise
    except OSError:
        raise CaptureValidationError("캡처 파일을 안전하게 읽을 수 없습니다.") from None
    if not _same_file_state(metadata, path_metadata):
        raise CaptureValidationError("파일이 확인 중 교체됐습니다.")
    return CaptureInfo(
        path=resolved,
        capture_format=capture_format,
        size_bytes=metadata.st_size,
        sha256=digest,
    )
