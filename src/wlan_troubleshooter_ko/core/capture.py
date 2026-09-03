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
    except (OSError, ValueError):
        raise CaptureValidationError("파일 경로를 안전하게 확인할 수 없습니다.") from None
    return _stat_is_link_or_reparse(metadata)


def _stat_is_link_or_reparse(metadata: os.stat_result) -> bool:
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


def _open_regular_readonly(path: Path):
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        return os.fdopen(descriptor, "rb")
    except (OSError, ValueError):
        os.close(descriptor)
        raise


def _stable_file_stats(path: Path, handle: BinaryIO) -> os.stat_result:
    """경로 안전성과 현재 열린 파일의 정체성을 재개방 핸들로 확인한다.

    Windows의 경로 기반 stat fast path는 일반 파일에서도 ``st_dev``와
    ``st_ino`` 같은 파일 ID 필드를 0으로 돌려줄 수 있다. 따라서 경로
    stat은 링크/reparse point와 파일 형식 확인에만 사용하고, 파일의
    정체성과 상태는 현재 핸들과 같은 경로를 다시 연 핸들의 fstat끼리
    비교한다.
    """

    path_before = os.lstat(path)
    handle_stat = os.fstat(handle.fileno())
    _reject_linked_components(path)
    with _open_regular_readonly(path) as reopened_handle:
        reopened_stat = os.fstat(reopened_handle.fileno())
    _reject_linked_components(path)
    path_after = os.lstat(path)
    if (
        _stat_is_link_or_reparse(path_before)
        or _stat_is_link_or_reparse(path_after)
        or _stat_is_link_or_reparse(handle_stat)
        or _stat_is_link_or_reparse(reopened_stat)
        or not stat.S_ISREG(path_before.st_mode)
        or not stat.S_ISREG(path_after.st_mode)
        or not stat.S_ISREG(handle_stat.st_mode)
        or not stat.S_ISREG(reopened_stat.st_mode)
        or not _same_file_state(handle_stat, reopened_stat)
    ):
        raise CaptureValidationError("파일이 확인 중 교체됐습니다.")
    return handle_stat


def _verify_digest_after_reopen(
    path: Path,
    expected_metadata: os.stat_result,
    expected_digest: str,
    cancel_event: Optional[threading.Event],
) -> None:
    """재개방 파일의 정체성과 전체 해시를 다시 비교한다.

    일부 Windows 파일시스템에서는 같은 크기의 제자리 쓰기가 매우 짧은
    시간 안에 일어나면 mtime/ctime만으로 변경을 놓칠 수 있다. 따라서
    최초 핸들을 닫은 뒤 같은 경로를 다시 열어 파일 정체성과 전체 해시를
    모두 비교한다. 검증 비용보다 민감 캡처의 TOCTOU 차단을 우선한다.
    """

    try:
        with _open_regular_readonly(path) as handle:
            before_hash = _stable_file_stats(path, handle)
            if not _same_file_state(expected_metadata, before_hash):
                raise CaptureValidationError("파일이 확인 중 교체됐습니다.")
            reopened_digest = _sha256_handle(handle, cancel_event, 1024 * 1024)
            after_hash = _stable_file_stats(path, handle)
            if (
                not _same_file_state(before_hash, after_hash)
                or not _same_file_state(expected_metadata, after_hash)
                or reopened_digest != expected_digest
            ):
                raise CaptureValidationError("파일이 확인 중 변경됐습니다.")
    except CaptureValidationError:
        raise
    except OSError:
        raise CaptureValidationError("캡처 파일을 안전하게 다시 확인할 수 없습니다.") from None


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
        # 해석된 별도 경로를 다시 여는 대신, 링크 검사를 마친 원래 절대
        # 경로를 열고 그 경로가 같은 핸들을 가리키는지 반복 확인한다.
        resolved = candidate
        with _open_regular_readonly(resolved) as handle:
            metadata = _stable_file_stats(resolved, handle)
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
            final_open_metadata = _stable_file_stats(resolved, handle)
            if not _same_file_state(metadata, final_open_metadata):
                raise CaptureValidationError("파일이 확인 중 변경됐습니다.")
        # Windows에서 같은 크기의 제자리 쓰기가 파일시각 정밀도에 가려질
        # 수 있으므로 최초 핸들을 닫은 뒤 전체 해시를 다시 검증한다.
        _verify_digest_after_reopen(resolved, metadata, digest, cancel_event)
    except CaptureValidationError:
        raise
    except OSError:
        raise CaptureValidationError("캡처 파일을 안전하게 읽을 수 없습니다.") from None
    return CaptureInfo(
        path=resolved,
        capture_format=capture_format,
        size_bytes=metadata.st_size,
        sha256=digest,
    )
