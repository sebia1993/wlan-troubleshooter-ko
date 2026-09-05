"""PCAPNG Interface Statistics Block을 별도 bounded pass로 읽는다."""

from __future__ import annotations

import threading
from dataclasses import dataclass, replace
from typing import BinaryIO, Dict, List, Optional, Set, Tuple

from wlan_troubleshooter_ko.analysis.models import (
    CaptureStructure,
    CaptureStructureError,
    InterfaceStatisticsObservation,
)
from wlan_troubleshooter_ko.core.capture import CaptureInfo


_SHB_MAGIC = bytes.fromhex("0a0d0d0a")
_BYTE_ORDERS = {
    bytes.fromhex("4d3c2b1a"): "little",
    bytes.fromhex("1a2b3c4d"): "big",
}
_ISB = 5
_MAX_ISB_LENGTH = 1024 * 1024
_SUPPORTED = {2, 3, 4, 5, 6, 7, 8}


@dataclass(frozen=True)
class _Statistics:
    section: int
    interface: int
    observation: int
    ifrecv: Optional[int]
    ifdrop: Optional[int]
    filteraccept: Optional[int]
    osdrop: Optional[int]
    usrdeliv: Optional[int]
    start_time_present: bool
    end_time_present: bool


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


def _options(
    data: bytes,
    byte_order: str,
    warnings: Set[str],
) -> Tuple[Dict[int, int], bool, bool]:
    values: Dict[int, int] = {}
    seen: Set[int] = set()
    start_present = False
    end_present = False
    position = 0
    while position < len(data):
        if len(data) - position < 4:
            raise CaptureStructureError("PCAPNG 통계 옵션 헤더가 잘렸습니다.")
        code = _unsigned(data[position : position + 2], byte_order)
        length = _unsigned(data[position + 2 : position + 4], byte_order)
        position += 4
        padded = _padded(length)
        if position + padded > len(data):
            raise CaptureStructureError("PCAPNG 통계 옵션 값이 잘렸습니다.")
        if code == 0:
            if length != 0:
                raise CaptureStructureError("PCAPNG 옵션 종료 길이는 0이어야 합니다.")
            if any(data[position + padded :]):
                raise CaptureStructureError("PCAPNG 옵션 종료 뒤에 값이 있습니다.")
            break
        value = data[position : position + length]
        if code in _SUPPORTED:
            if code in seen:
                raise CaptureStructureError("PCAPNG 인터페이스 통계 옵션이 중복됐습니다.")
            seen.add(code)
            if length != 8:
                warnings.add("PCAPNG 인터페이스 통계 옵션 길이가 8바이트가 아니어서 값을 사용하지 않았습니다.")
            elif code == 2:
                start_present = True
            elif code == 3:
                end_present = True
            else:
                values[code] = _unsigned(value, byte_order)
        position += padded
    return values, start_present, end_present


def _counter_state(item: _Statistics) -> str:
    drops = tuple(
        value for value in (item.ifdrop, item.osdrop) if value is not None
    )
    if any(value > 0 for value in drops):
        return "reported-drop-observed"
    if drops:
        return "zero-reported-drop-counters"
    return "statistics-without-drop-counters"


def enrich_pcapng_interface_statistics(
    handle: BinaryIO,
    capture: CaptureInfo,
    structure: CaptureStructure,
    max_records: int,
    max_block_length: int,
    cancel_event: Optional[threading.Event],
) -> CaptureStructure:
    """ISB를 읽고 Counter 원문과 절대 시간을 분리한 구조를 반환한다."""

    if structure.capture_format != "pcapng":
        raise CaptureStructureError("PCAPNG 구조 결과가 필요합니다.")
    interface_keys = {
        (item.section_index, item.interface_id) for item in structure.interfaces
    }
    aliases = {
        key: "IFACE-" + str(index)
        for index, key in enumerate(sorted(interface_keys), start=1)
    }
    counts: Dict[Tuple[int, int], int] = {}
    collected: List[_Statistics] = []
    warnings = set(structure.warnings)
    section = -1
    byte_order: Optional[str] = None
    records = 0
    handle.seek(0)

    while handle.tell() < capture.size_bytes:
        _check_cancel(cancel_event)
        if records >= max_records:
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
            section += 1
            block_type = 0x0A0D0D0A
        else:
            if byte_order is None or section < 0:
                raise CaptureStructureError("PCAPNG 첫 블록은 Section Header Block이어야 합니다.")
            block_type = _unsigned(type_bytes, byte_order)
        total = _unsigned(length_bytes, byte_order)
        _validate_block(total, offset, capture.size_bytes, max_block_length)
        block_end = offset + total

        if block_type == _ISB:
            if total < 24:
                raise CaptureStructureError("PCAPNG Interface Statistics Block 길이가 너무 짧습니다.")
            if total > _MAX_ISB_LENGTH:
                raise CaptureStructureError("PCAPNG Interface Statistics Block이 안전 제한을 초과했습니다.")
            body = _read_exact(
                handle,
                total - 12,
                "PCAPNG Interface Statistics Block이 잘렸습니다.",
            )
            interface = _unsigned(body[0:4], byte_order)
            values, start_present, end_present = _options(
                body[12:],
                byte_order,
                warnings,
            )
            key = (section, interface)
            if key not in interface_keys:
                warnings.add("정의되지 않은 PCAPNG 인터페이스를 참조한 통계 블록이 있습니다.")
            else:
                observation = counts.get(key, 0) + 1
                counts[key] = observation
                collected.append(
                    _Statistics(
                        section=section,
                        interface=interface,
                        observation=observation,
                        ifrecv=values.get(4),
                        ifdrop=values.get(5),
                        filteraccept=values.get(6),
                        osdrop=values.get(7),
                        usrdeliv=values.get(8),
                        start_time_present=start_present,
                        end_time_present=end_present,
                    )
                )

        handle.seek(block_end - 4)
        trailing = _unsigned(
            _read_exact(handle, 4, "PCAPNG 블록 종료 길이가 잘렸습니다."),
            byte_order,
        )
        if trailing != total:
            raise CaptureStructureError("PCAPNG 블록 시작·종료 길이가 일치하지 않습니다.")
        records += 1

    observations = tuple(
        InterfaceStatisticsObservation(
            interface_alias=aliases[(item.section, item.interface)],
            section_index=item.section,
            interface_id=item.interface,
            observation_index=item.observation,
            counter_state=_counter_state(item),
            ifrecv=item.ifrecv,
            ifdrop=item.ifdrop,
            filteraccept=item.filteraccept,
            osdrop=item.osdrop,
            usrdeliv=item.usrdeliv,
            block_timestamp_present=True,
            start_time_present=item.start_time_present,
            end_time_present=item.end_time_present,
            absolute_timestamps_serialized=False,
            capture_loss_excluded=False,
            root_cause_confirmed=False,
        )
        for item in collected
    )
    return replace(
        structure,
        warnings=tuple(sorted(warnings)),
        interface_statistics_state=(
            "observed" if observations else "no-interface-statistics"
        ),
        interface_statistics=observations,
    )
