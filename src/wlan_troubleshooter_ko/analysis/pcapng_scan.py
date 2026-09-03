"""PCAPNG 컨테이너의 제한된 구조 스캔."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import BinaryIO, Dict, Optional, Set, Tuple

from wlan_troubleshooter_ko.analysis.linktypes import link_type_name
from wlan_troubleshooter_ko.analysis.models import (
    CaptureStructure,
    CaptureStructureError,
    InterfaceSummary,
)
from wlan_troubleshooter_ko.core.capture import CaptureInfo


_SHB_MAGIC = bytes.fromhex("0a0d0d0a")
_BYTE_ORDERS = {
    bytes.fromhex("4d3c2b1a"): "little",
    bytes.fromhex("1a2b3c4d"): "big",
}
_IDB = 1
_PACKET_BLOCK = 2
_SIMPLE_PACKET_BLOCK = 3
_ENHANCED_PACKET_BLOCK = 6
_MAX_IDB_LENGTH = 1024 * 1024


@dataclass
class _InterfaceState:
    section: int
    identifier: int
    link_type: int
    snaplen: int
    resolution: str = "10^-6"
    packets: int = 0
    truncated: int = 0

    def freeze(self) -> InterfaceSummary:
        return InterfaceSummary(
            section_index=self.section,
            interface_id=self.identifier,
            link_type=self.link_type,
            link_type_name=link_type_name(self.link_type),
            snaplen=self.snaplen,
            timestamp_resolution=self.resolution,
            packets_scanned=self.packets,
            truncated_packets_observed=self.truncated,
        )


def _read_exact(handle: BinaryIO, size: int, message: str) -> bytes:
    data = handle.read(size)
    if len(data) != size:
        raise CaptureStructureError(message)
    return data


def _unsigned(data: bytes, byte_order: str) -> int:
    return int.from_bytes(data, byteorder=byte_order, signed=False)


def _padded(length: int) -> int:
    return (length + 3) & ~3


def _check_cancel(cancel_event: Optional[threading.Event]) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise CaptureStructureError("캡처 구조 점검이 취소됐습니다.")


def _validate_block(total: int, offset: int, size: int, maximum: int) -> None:
    if total < 12 or total % 4:
        raise CaptureStructureError("PCAPNG 블록 길이가 올바르지 않습니다.")
    if total > maximum:
        raise CaptureStructureError("PCAPNG 블록 길이가 안전 제한을 초과했습니다.")
    if offset + total > size:
        raise CaptureStructureError("PCAPNG 블록이 선언 길이보다 짧습니다.")


def _timestamp_resolution(options: bytes, byte_order: str, warnings: Set[str]) -> str:
    result = "10^-6"
    position = 0
    while position + 4 <= len(options):
        code = _unsigned(options[position : position + 2], byte_order)
        length = _unsigned(options[position + 2 : position + 4], byte_order)
        position += 4
        padded = _padded(length)
        if position + padded > len(options):
            warnings.add("PCAPNG 인터페이스 옵션 일부가 잘려 기본 시간 해상도를 사용했습니다.")
            break
        value = options[position : position + length]
        if code == 0:
            break
        if code == 9:
            if length != 1:
                warnings.add("PCAPNG 시간 해상도 옵션 길이가 올바르지 않습니다.")
            else:
                raw = value[0]
                result = "2^-{0}".format(raw & 0x7F) if raw & 0x80 else "10^-{0}".format(raw)
        position += padded
    return result


def _packet_lengths(
    handle: BinaryIO,
    block_type: int,
    byte_order: str,
) -> Tuple[int, int, int]:
    raw = _read_exact(handle, 20, "PCAPNG 패킷 블록이 잘렸습니다.")
    interface = (
        _unsigned(raw[0:4], byte_order)
        if block_type == _ENHANCED_PACKET_BLOCK
        else _unsigned(raw[0:2], byte_order)
    )
    captured = _unsigned(raw[12:16], byte_order)
    original = _unsigned(raw[16:20], byte_order)
    return interface, captured, original


def _freeze(states: Dict[Tuple[int, int], _InterfaceState]) -> Tuple[InterfaceSummary, ...]:
    return tuple(states[key].freeze() for key in sorted(states))


def scan_pcapng(
    handle: BinaryIO,
    capture: CaptureInfo,
    max_records: int,
    max_block_length: int,
    cancel_event: Optional[threading.Event],
) -> CaptureStructure:
    """PCAPNG 섹션·인터페이스·패킷 블록 경계를 점검한다."""

    section = -1
    byte_order: Optional[str] = None
    byte_orders: Set[str] = set()
    states: Dict[Tuple[int, int], _InterfaceState] = {}
    interface_counts: Dict[int, int] = {}
    warnings: Set[str] = set()
    records = 0
    packets = 0
    complete = True

    while handle.tell() < capture.size_bytes:
        _check_cancel(cancel_event)
        if records >= max_records:
            complete = False
            warnings.add("안전 제한으로 일부 PCAPNG 블록만 점검했습니다.")
            break
        offset = handle.tell()
        if capture.size_bytes - offset < 8:
            raise CaptureStructureError("PCAPNG 블록 헤더가 잘렸습니다.")
        header = _read_exact(handle, 8, "PCAPNG 블록 헤더가 잘렸습니다.")
        type_bytes = header[:4]
        length_bytes = header[4:8]

        if type_bytes == _SHB_MAGIC:
            bom = _read_exact(handle, 4, "PCAPNG Section Header Block이 잘렸습니다.")
            try:
                byte_order = _BYTE_ORDERS[bom]
            except KeyError as exc:
                raise CaptureStructureError("PCAPNG 바이트 순서를 확인할 수 없습니다.") from exc
            total = _unsigned(length_bytes, byte_order)
            _validate_block(total, offset, capture.size_bytes, max_block_length)
            if total < 28:
                raise CaptureStructureError("PCAPNG Section Header Block 길이가 너무 짧습니다.")
            section += 1
            interface_counts[section] = 0
            byte_orders.add(byte_order)
            block_type = 0x0A0D0D0A
        else:
            if byte_order is None or section < 0:
                raise CaptureStructureError("PCAPNG 첫 블록은 Section Header Block이어야 합니다.")
            total = _unsigned(length_bytes, byte_order)
            _validate_block(total, offset, capture.size_bytes, max_block_length)
            block_type = _unsigned(type_bytes, byte_order)

        block_end = offset + total
        if block_type == _IDB:
            if total > _MAX_IDB_LENGTH:
                raise CaptureStructureError("PCAPNG 인터페이스 블록이 안전 제한을 초과했습니다.")
            body = _read_exact(
                handle,
                total - 12,
                "PCAPNG 인터페이스 블록이 잘렸습니다.",
            )
            if len(body) < 8:
                raise CaptureStructureError("PCAPNG 인터페이스 설명이 너무 짧습니다.")
            link_type = _unsigned(body[0:2], byte_order)
            snaplen = _unsigned(body[4:8], byte_order)
            identifier = interface_counts[section]
            interface_counts[section] += 1
            states[(section, identifier)] = _InterfaceState(
                section=section,
                identifier=identifier,
                link_type=link_type,
                snaplen=snaplen,
                resolution=_timestamp_resolution(body[8:], byte_order, warnings),
            )
        elif block_type in {_ENHANCED_PACKET_BLOCK, _PACKET_BLOCK}:
            if total < 32:
                raise CaptureStructureError("PCAPNG 패킷 블록 길이가 너무 짧습니다.")
            interface, captured, original = _packet_lengths(handle, block_type, byte_order)
            if captured > original:
                raise CaptureStructureError("PCAPNG 캡처 길이가 원본 패킷 길이보다 큽니다.")
            if 8 + 20 + _padded(captured) + 4 > total:
                raise CaptureStructureError("PCAPNG 패킷 데이터 길이가 블록 길이와 일치하지 않습니다.")
            state = states.get((section, interface))
            if state is None:
                warnings.add("정의되지 않은 PCAPNG 인터페이스를 참조한 패킷이 있습니다.")
            else:
                state.packets += 1
                state.truncated += int(captured < original)
                if state.snaplen and captured > state.snaplen:
                    warnings.add("일부 패킷의 캡처 길이가 인터페이스 Snap Length보다 큽니다.")
            packets += 1
        elif block_type == _SIMPLE_PACKET_BLOCK:
            if total < 16:
                raise CaptureStructureError("PCAPNG Simple Packet Block 길이가 너무 짧습니다.")
            original = _unsigned(
                _read_exact(handle, 4, "PCAPNG Simple Packet Block이 잘렸습니다."),
                byte_order,
            )
            stored_padded = total - 16
            state = states.get((section, 0))
            if state is None:
                warnings.add("인터페이스가 없는 PCAPNG Simple Packet Block이 있습니다.")
            else:
                expected = min(original, state.snaplen) if state.snaplen else original
                if _padded(expected) > stored_padded:
                    raise CaptureStructureError("PCAPNG Simple Packet Block 데이터가 선언 길이보다 짧습니다.")
                state.packets += 1
                state.truncated += int(expected < original)
            warnings.add("Simple Packet Block은 캡처 길이를 정밀하게 구분하지 못할 수 있습니다.")
            packets += 1

        handle.seek(block_end - 4)
        trailing = _unsigned(
            _read_exact(handle, 4, "PCAPNG 블록 종료 길이가 잘렸습니다."),
            byte_order,
        )
        if trailing != total:
            raise CaptureStructureError("PCAPNG 블록 시작·종료 길이가 일치하지 않습니다.")
        records += 1

    if section < 0:
        raise CaptureStructureError("PCAPNG Section Header Block이 없습니다.")
    interfaces = _freeze(states)
    truncated = sum(item.truncated_packets_observed for item in interfaces)
    order = next(iter(byte_orders)) if len(byte_orders) == 1 else "mixed"
    return CaptureStructure(
        capture_format="pcapng",
        byte_order=order,
        timestamp_precision="per-interface",
        sections=section + 1,
        interfaces=interfaces,
        records_scanned=records,
        packets_scanned=packets,
        truncated_packets_observed=truncated,
        scan_complete=complete,
        warnings=tuple(sorted(warnings)),
    )
