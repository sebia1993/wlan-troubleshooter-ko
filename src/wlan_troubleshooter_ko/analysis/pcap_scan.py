"""PCAP 컨테이너의 제한된 구조 스캔."""

from __future__ import annotations

import threading
from typing import BinaryIO, Optional, Set

from wlan_troubleshooter_ko.analysis.linktypes import link_type_name
from wlan_troubleshooter_ko.analysis.models import (
    CaptureStructure,
    CaptureStructureError,
    InterfaceSummary,
)
from wlan_troubleshooter_ko.core.capture import CaptureInfo


_PCAP_FORMATS = {
    bytes.fromhex("d4c3b2a1"): ("little", "microsecond"),
    bytes.fromhex("a1b2c3d4"): ("big", "microsecond"),
    bytes.fromhex("4d3cb2a1"): ("little", "nanosecond"),
    bytes.fromhex("a1b23c4d"): ("big", "nanosecond"),
}


def _read_exact(handle: BinaryIO, size: int, message: str) -> bytes:
    data = handle.read(size)
    if len(data) != size:
        raise CaptureStructureError(message)
    return data


def _unsigned(data: bytes, byte_order: str) -> int:
    return int.from_bytes(data, byteorder=byte_order, signed=False)


def _check_cancel(cancel_event: Optional[threading.Event]) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise CaptureStructureError("캡처 구조 점검이 취소됐습니다.")


def scan_pcap(
    handle: BinaryIO,
    capture: CaptureInfo,
    max_records: int,
    max_record_length: int,
    cancel_event: Optional[threading.Event],
) -> CaptureStructure:
    """PCAP 전역 헤더와 레코드 경계를 점검한다."""

    header = _read_exact(handle, 24, "PCAP 전역 헤더가 잘렸습니다.")
    try:
        byte_order, precision = _PCAP_FORMATS[header[:4]]
    except KeyError as exc:
        raise CaptureStructureError("PCAP 바이트 순서를 확인할 수 없습니다.") from exc

    major = _unsigned(header[4:6], byte_order)
    minor = _unsigned(header[6:8], byte_order)
    snaplen = _unsigned(header[16:20], byte_order)
    network_word = _unsigned(header[20:24], byte_order)
    link_type = network_word & 0xFFFF
    warnings: Set[str] = set()
    if (major, minor) != (2, 4):
        warnings.add("일반적인 PCAP 2.4와 다른 버전 헤더입니다.")
    if network_word != link_type:
        warnings.add("Link Type 확장 비트가 있어 하위 16비트 기준으로 분류했습니다.")
    if snaplen == 0:
        warnings.add("Snap Length가 0으로 기록되어 캡처 제한을 확인할 수 없습니다.")

    packets = 0
    truncated = 0
    complete = True
    while handle.tell() < capture.size_bytes:
        _check_cancel(cancel_event)
        if packets >= max_records:
            complete = False
            warnings.add("안전 제한으로 일부 PCAP 레코드만 점검했습니다.")
            break
        remaining = capture.size_bytes - handle.tell()
        if remaining < 16:
            raise CaptureStructureError("PCAP 패킷 레코드 헤더가 잘렸습니다.")
        record = _read_exact(handle, 16, "PCAP 패킷 레코드 헤더가 잘렸습니다.")
        captured_length = _unsigned(record[8:12], byte_order)
        original_length = _unsigned(record[12:16], byte_order)
        if captured_length > original_length:
            raise CaptureStructureError("PCAP 캡처 길이가 원본 패킷 길이보다 큽니다.")
        if captured_length > max_record_length:
            raise CaptureStructureError("PCAP 패킷 레코드 길이가 안전 제한을 초과했습니다.")
        if captured_length > capture.size_bytes - handle.tell():
            raise CaptureStructureError("PCAP 패킷 데이터가 선언 길이보다 짧습니다.")
        if snaplen and captured_length > snaplen:
            warnings.add("일부 패킷의 캡처 길이가 전역 Snap Length보다 큽니다.")
        truncated += int(captured_length < original_length)
        handle.seek(captured_length, 1)
        packets += 1

    interface = InterfaceSummary(
        section_index=0,
        interface_id=0,
        link_type=link_type,
        link_type_name=link_type_name(link_type),
        snaplen=snaplen,
        timestamp_resolution="10^-9" if precision == "nanosecond" else "10^-6",
        packets_scanned=packets,
        truncated_packets_observed=truncated,
    )
    return CaptureStructure(
        capture_format="pcap",
        byte_order=byte_order,
        timestamp_precision=precision,
        sections=1,
        interfaces=(interface,),
        records_scanned=packets,
        packets_scanned=packets,
        truncated_packets_observed=truncated,
        scan_complete=complete,
        warnings=tuple(sorted(warnings)),
    )
