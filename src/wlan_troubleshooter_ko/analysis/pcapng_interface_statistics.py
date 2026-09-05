"""Parse PCAPNG Interface Statistics Blocks without exposing identifiers.

Only standard unsigned 64-bit packet counters are retained. Interface names,
comments, absolute timestamps, option bytes and capture paths are ignored and
never serialized. Reported drops lower capture confidence but never prove that
a particular protocol packet was lost or identify a root cause.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import BinaryIO, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from wlan_troubleshooter_ko.core.capture import CaptureInfo


_SHB_TYPE = b"\x0a\x0d\x0d\x0a"
_IDB_TYPE = 0x00000001
_ISB_TYPE = 0x00000005
_LITTLE_BOM = b"\x4d\x3c\x2b\x1a"
_BIG_BOM = b"\x1a\x2b\x3c\x4d"
_COUNTER_OPTIONS: Mapping[int, str] = {
    4: "ifrecv",
    5: "ifdrop",
    6: "filteraccept",
    7: "osdrop",
    8: "usrdeliv",
}
_COUNTER_ORDER = ("ifrecv", "ifdrop", "filteraccept", "osdrop", "usrdeliv")
_MAX_BLOCKS = 2_000_000
_MAX_SECTIONS = 4_096
_MAX_INTERFACES = 65_536
_MAX_ISB_BLOCKS = 200_000
_MAX_OPTIONS_PER_BLOCK = 4_096
_MAX_BLOCK_BYTES = 64 * 1024 * 1024
_READ_CHUNK = 1024 * 1024


class PcapngInterfaceStatisticsError(ValueError):
    """The PCAPNG structure or its statistics blocks are unsafe to trust."""


@dataclass(frozen=True)
class CounterObservation:
    name: str
    observations: int
    first_value: Optional[int]
    last_value: Optional[int]
    progression: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "observations": self.observations,
            "first_value": self.first_value,
            "last_value": self.last_value,
            "progression": self.progression,
        }


@dataclass(frozen=True)
class InterfaceStatistics:
    interface_alias: str
    section_index: int
    interface_id: int
    statistics_blocks: int
    state: str
    counters: Tuple[CounterObservation, ...]
    raw_interface_identifiers_serialized: bool = False
    absolute_timestamps_serialized: bool = False
    specific_packet_loss_confirmed: bool = False
    root_cause_confirmed: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "interface_alias": self.interface_alias,
            "section_index": self.section_index,
            "interface_id": self.interface_id,
            "statistics_blocks": self.statistics_blocks,
            "state": self.state,
            "counters": [item.to_dict() for item in self.counters],
            "raw_interface_identifiers_serialized": self.raw_interface_identifiers_serialized,
            "absolute_timestamps_serialized": self.absolute_timestamps_serialized,
            "specific_packet_loss_confirmed": self.specific_packet_loss_confirmed,
            "root_cause_confirmed": self.root_cause_confirmed,
        }


@dataclass(frozen=True)
class PcapngInterfaceStatisticsReport:
    supported_capture_format: bool
    complete: bool
    state: str
    sections_observed: int
    interfaces_defined: int
    statistics_blocks_observed: int
    interfaces_with_statistics: int
    interfaces: Tuple[InterfaceStatistics, ...]
    raw_interface_identifiers_serialized: bool
    absolute_timestamps_serialized: bool
    capture_loss_excluded: bool
    specific_packet_loss_confirmed: bool
    root_cause_confirmed: bool
    cautions: Tuple[str, ...]

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema_version": 1,
            "supported_capture_format": self.supported_capture_format,
            "complete": self.complete,
            "state": self.state,
            "sections_observed": self.sections_observed,
            "interfaces_defined": self.interfaces_defined,
            "statistics_blocks_observed": self.statistics_blocks_observed,
            "interfaces_with_statistics": self.interfaces_with_statistics,
            "interfaces": [item.to_dict() for item in self.interfaces],
            "raw_interface_identifiers_serialized": self.raw_interface_identifiers_serialized,
            "absolute_timestamps_serialized": self.absolute_timestamps_serialized,
            "capture_loss_excluded": self.capture_loss_excluded,
            "specific_packet_loss_confirmed": self.specific_packet_loss_confirmed,
            "root_cause_confirmed": self.root_cause_confirmed,
            "cautions": list(self.cautions),
        }


@dataclass
class _InterfaceAccumulator:
    alias: str
    section_index: int
    interface_id: int
    statistics_blocks: int
    counters: Dict[str, List[int]]


def _cancelled(cancel_event: Optional[threading.Event]) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise PcapngInterfaceStatisticsError(
            "PCAPNG 인터페이스 통계 점검이 취소되었습니다."
        )


def _read_exact(handle: BinaryIO, length: int) -> bytes:
    if length < 0 or length > _MAX_BLOCK_BYTES:
        raise PcapngInterfaceStatisticsError(
            "PCAPNG 블록 길이가 안전 범위를 벗어났습니다."
        )
    chunks = bytearray()
    remaining = length
    while remaining:
        value = handle.read(min(remaining, _READ_CHUNK))
        if not value:
            raise PcapngInterfaceStatisticsError(
                "PCAPNG 블록이 선언된 길이보다 짧습니다."
            )
        chunks.extend(value)
        remaining -= len(value)
    return bytes(chunks)


def _uint(raw: bytes, byte_order: str) -> int:
    if byte_order not in {"little", "big"}:
        raise PcapngInterfaceStatisticsError(
            "PCAPNG 바이트 순서가 올바르지 않습니다."
        )
    return int.from_bytes(raw, byteorder=byte_order, signed=False)


def _block_length(
    raw: bytes,
    byte_order: str,
    *,
    minimum: int,
    offset: int,
    file_size: int,
) -> int:
    if len(raw) != 4:
        raise PcapngInterfaceStatisticsError(
            "PCAPNG 블록 길이 필드가 올바르지 않습니다."
        )
    value = _uint(raw, byte_order)
    if (
        value < minimum
        or value % 4
        or value > _MAX_BLOCK_BYTES
        or value > file_size - offset
    ):
        raise PcapngInterfaceStatisticsError(
            "PCAPNG 블록 길이가 올바르지 않습니다."
        )
    return value


def _validate_input(capture: CaptureInfo) -> None:
    if not isinstance(capture, CaptureInfo):
        raise PcapngInterfaceStatisticsError(
            "검증된 캡처 정보가 필요합니다."
        )
    if (
        not capture.path.is_absolute()
        or not capture.path.is_file()
        or capture.size_bytes < 0
        or not isinstance(capture.sha256, str)
        or len(capture.sha256) != 64
    ):
        raise PcapngInterfaceStatisticsError(
            "검증된 로컬 캡처 파일을 사용할 수 없습니다."
        )
    try:
        current_size = capture.path.stat().st_size
    except OSError:
        raise PcapngInterfaceStatisticsError(
            "캡처 파일 크기를 안전하게 확인할 수 없습니다."
        ) from None
    if current_size != capture.size_bytes:
        raise PcapngInterfaceStatisticsError(
            "캡처 파일 크기가 기존 검증 이후 변경되었습니다."
        )


def _iter_options(
    data: bytes,
    byte_order: str,
) -> Iterable[Tuple[int, bytes]]:
    offset = 0
    count = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise PcapngInterfaceStatisticsError(
                "PCAPNG 옵션 헤더가 블록 끝에서 잘렸습니다."
            )
        code = _uint(data[offset : offset + 2], byte_order)
        length = _uint(data[offset + 2 : offset + 4], byte_order)
        offset += 4
        count += 1
        if count > _MAX_OPTIONS_PER_BLOCK:
            raise PcapngInterfaceStatisticsError(
                "PCAPNG 옵션 수가 안전 제한을 초과했습니다."
            )
        if code == 0:
            if length != 0:
                raise PcapngInterfaceStatisticsError(
                    "PCAPNG 옵션 종료 항목 길이가 0이 아닙니다."
                )
            if any(data[offset:]):
                raise PcapngInterfaceStatisticsError(
                    "PCAPNG 옵션 종료 뒤에 0이 아닌 데이터가 있습니다."
                )
            return

        padded_length = (length + 3) & ~3
        if padded_length > len(data) - offset:
            raise PcapngInterfaceStatisticsError(
                "PCAPNG 옵션 값이 선언된 길이보다 짧습니다."
            )
        raw = data[offset : offset + length]
        padding = data[offset + length : offset + padded_length]
        if any(padding):
            raise PcapngInterfaceStatisticsError(
                "PCAPNG 옵션 패딩이 0이 아닙니다."
            )
        offset += padded_length
        yield code, raw


def _validate_ignored_options(data: bytes, byte_order: str) -> None:
    for _code, _raw in _iter_options(data, byte_order):
        pass


def _counter_options(data: bytes, byte_order: str) -> Dict[str, int]:
    counters: Dict[str, int] = {}
    for code, raw in _iter_options(data, byte_order):
        name = _COUNTER_OPTIONS.get(code)
        if name is None:
            continue
        if name in counters:
            raise PcapngInterfaceStatisticsError(
                "동일 ISB에 같은 Counter 옵션이 중복됐습니다."
            )
        if len(raw) != 8:
            raise PcapngInterfaceStatisticsError(
                "PCAPNG ISB Counter 옵션 길이가 8바이트가 아닙니다."
            )
        counters[name] = _uint(raw, byte_order)
    return counters


def _progression(values: Sequence[int]) -> str:
    if not values:
        return "not-reported"
    if len(values) == 1:
        return "single-value-observed"
    if any(current < previous for previous, current in zip(values, values[1:])):
        return "counter-decrease-observed"
    if any(current > previous for previous, current in zip(values, values[1:])):
        return "counter-increase-observed"
    return "counter-unchanged-observed"


def _interface_state(
    values: Mapping[str, Sequence[int]],
    statistics_blocks: int,
) -> str:
    if statistics_blocks == 0:
        return "no-interface-statistics"
    drop_values = tuple(values.get("ifdrop", ())) + tuple(
        values.get("osdrop", ())
    )
    if not drop_values:
        return "statistics-without-drop-counters"
    if any(value > 0 for value in drop_values):
        return "reported-drop-observed"
    return "zero-reported-drop-counters"


def _report_state(
    interfaces: Sequence[InterfaceStatistics],
    statistics_blocks: int,
) -> str:
    if statistics_blocks == 0:
        return "no-interface-statistics"
    states = {item.state for item in interfaces}
    if "reported-drop-observed" in states:
        return "reported-drop-observed"
    if "zero-reported-drop-counters" in states:
        return "zero-reported-drop-counters"
    return "statistics-without-drop-counters"


def _unsupported_report() -> PcapngInterfaceStatisticsReport:
    return PcapngInterfaceStatisticsReport(
        supported_capture_format=False,
        complete=True,
        state="unsupported-capture-format",
        sections_observed=0,
        interfaces_defined=0,
        statistics_blocks_observed=0,
        interfaces_with_statistics=0,
        interfaces=(),
        raw_interface_identifiers_serialized=False,
        absolute_timestamps_serialized=False,
        capture_loss_excluded=False,
        specific_packet_loss_confirmed=False,
        root_cause_confirmed=False,
        cautions=(
            "일반 PCAP에는 PCAPNG Interface Statistics Block 구조가 없습니다.",
            "통계 블록을 사용할 수 없다는 사실은 캡처 손실이 없다는 뜻이 아닙니다.",
        ),
    )


def _freeze_interface(
    value: _InterfaceAccumulator,
) -> InterfaceStatistics:
    counters = tuple(
        CounterObservation(
            name=name,
            observations=len(value.counters[name]),
            first_value=(
                None if not value.counters[name] else value.counters[name][0]
            ),
            last_value=(
                None if not value.counters[name] else value.counters[name][-1]
            ),
            progression=_progression(value.counters[name]),
        )
        for name in _COUNTER_ORDER
    )
    return InterfaceStatistics(
        interface_alias=value.alias,
        section_index=value.section_index,
        interface_id=value.interface_id,
        statistics_blocks=value.statistics_blocks,
        state=_interface_state(value.counters, value.statistics_blocks),
        counters=counters,
    )


def inspect_pcapng_interface_statistics(
    capture: CaptureInfo,
    *,
    cancel_event: Optional[threading.Event] = None,
) -> PcapngInterfaceStatisticsReport:
    """Return identifier-free standard ISB counters for a verified capture."""

    _validate_input(capture)
    _cancelled(cancel_event)
    if capture.capture_format != "pcapng":
        return _unsupported_report()

    section_index = -1
    byte_order: Optional[str] = None
    section_interfaces: List[_InterfaceAccumulator] = []
    all_interfaces: List[_InterfaceAccumulator] = []
    blocks = 0
    sections = 0
    statistics_blocks = 0

    try:
        with capture.path.open("rb") as handle:
            while handle.tell() < capture.size_bytes:
                _cancelled(cancel_event)
                block_offset = handle.tell()
                type_bytes = _read_exact(handle, 4)
                length_bytes = _read_exact(handle, 4)
                blocks += 1
                if blocks > _MAX_BLOCKS:
                    raise PcapngInterfaceStatisticsError(
                        "PCAPNG 블록 수가 안전 제한을 초과했습니다."
                    )

                if type_bytes == _SHB_TYPE:
                    bom = _read_exact(handle, 4)
                    if bom == _LITTLE_BOM:
                        current_order = "little"
                    elif bom == _BIG_BOM:
                        current_order = "big"
                    else:
                        raise PcapngInterfaceStatisticsError(
                            "PCAPNG Section Header의 Byte-Order Magic이 올바르지 않습니다."
                        )
                    total_length = _block_length(
                        length_bytes,
                        current_order,
                        minimum=28,
                        offset=block_offset,
                        file_size=capture.size_bytes,
                    )
                    remainder = _read_exact(handle, total_length - 12)
                    if len(remainder) < 16:
                        raise PcapngInterfaceStatisticsError(
                            "PCAPNG Section Header 고정 필드가 잘렸습니다."
                        )
                    trailing_length = _uint(remainder[-4:], current_order)
                    if trailing_length != total_length:
                        raise PcapngInterfaceStatisticsError(
                            "PCAPNG Section Header의 앞·뒤 길이가 일치하지 않습니다."
                        )
                    _validate_ignored_options(remainder[12:-4], current_order)
                    byte_order = current_order
                    section_index += 1
                    sections += 1
                    if sections > _MAX_SECTIONS:
                        raise PcapngInterfaceStatisticsError(
                            "PCAPNG 섹션 수가 안전 제한을 초과했습니다."
                        )
                    section_interfaces = []
                    continue

                if byte_order is None or section_index < 0:
                    raise PcapngInterfaceStatisticsError(
                        "Section Header Block보다 앞에 다른 PCAPNG 블록이 있습니다."
                    )

                block_type = _uint(type_bytes, byte_order)
                minimum = 20 if block_type == _IDB_TYPE else 24 if block_type == _ISB_TYPE else 12
                total_length = _block_length(
                    length_bytes,
                    byte_order,
                    minimum=minimum,
                    offset=block_offset,
                    file_size=capture.size_bytes,
                )
                body = _read_exact(handle, total_length - 12)
                trailing_length = _uint(_read_exact(handle, 4), byte_order)
                if trailing_length != total_length:
                    raise PcapngInterfaceStatisticsError(
                        "PCAPNG 블록의 앞·뒤 길이가 일치하지 않습니다."
                    )

                if block_type == _IDB_TYPE:
                    if len(body) < 8:
                        raise PcapngInterfaceStatisticsError(
                            "PCAPNG Interface Description Block 고정 필드가 잘렸습니다."
                        )
                    _validate_ignored_options(body[8:], byte_order)
                    if len(all_interfaces) >= _MAX_INTERFACES:
                        raise PcapngInterfaceStatisticsError(
                            "PCAPNG 인터페이스 수가 안전 제한을 초과했습니다."
                        )
                    interface = _InterfaceAccumulator(
                        alias="IFACE-" + str(len(all_interfaces) + 1),
                        section_index=section_index,
                        interface_id=len(section_interfaces),
                        statistics_blocks=0,
                        counters={name: [] for name in _COUNTER_ORDER},
                    )
                    section_interfaces.append(interface)
                    all_interfaces.append(interface)

                elif block_type == _ISB_TYPE:
                    if len(body) < 12:
                        raise PcapngInterfaceStatisticsError(
                            "PCAPNG Interface Statistics Block 고정 필드가 잘렸습니다."
                        )
                    interface_id = _uint(body[:4], byte_order)
                    if interface_id >= len(section_interfaces):
                        raise PcapngInterfaceStatisticsError(
                            "Interface Statistics Block이 선언되지 않은 Interface ID를 참조합니다."
                        )
                    statistics_blocks += 1
                    if statistics_blocks > _MAX_ISB_BLOCKS:
                        raise PcapngInterfaceStatisticsError(
                            "PCAPNG Interface Statistics Block 수가 안전 제한을 초과했습니다."
                        )
                    counters = _counter_options(body[12:], byte_order)
                    interface = section_interfaces[interface_id]
                    interface.statistics_blocks += 1
                    for name, value in counters.items():
                        interface.counters[name].append(value)

            if handle.tell() != capture.size_bytes:
                raise PcapngInterfaceStatisticsError(
                    "PCAPNG 블록 경계가 파일 크기와 일치하지 않습니다."
                )
    except PcapngInterfaceStatisticsError:
        raise
    except OSError:
        raise PcapngInterfaceStatisticsError(
            "PCAPNG 인터페이스 통계를 안전하게 읽을 수 없습니다."
        ) from None

    frozen = tuple(_freeze_interface(item) for item in all_interfaces)
    state = _report_state(frozen, statistics_blocks)
    cautions = [
        "Interface Statistics Block Counter는 캡처 도구가 기록한 메타데이터입니다.",
        "드롭 Counter가 0이어도 캡처 손실이 없었다는 뜻은 아닙니다.",
        "Interface Statistics Block이 없어도 캡처 손실이 없었다는 뜻은 아닙니다.",
        "양수 드롭 Counter는 특정 패킷 누락이나 RF·AP·단말·SPAN 장애를 확정하지 않습니다.",
        "여러 누적 Counter 스냅샷은 합산하지 않고 첫·마지막 값과 변화 방향만 제공합니다.",
    ]
    if statistics_blocks == 0:
        cautions.insert(
            0,
            "PCAPNG에서 Interface Statistics Block을 관찰하지 못했습니다.",
        )
    if any(
        counter.progression == "counter-decrease-observed"
        for interface in frozen
        for counter in interface.counters
    ):
        cautions.insert(
            0,
            "파일 순서상 Counter 감소가 관찰됐지만 초기화·재시작·wrap 중 하나로 확정하지 않습니다.",
        )

    return PcapngInterfaceStatisticsReport(
        supported_capture_format=True,
        complete=True,
        state=state,
        sections_observed=sections,
        interfaces_defined=len(frozen),
        statistics_blocks_observed=statistics_blocks,
        interfaces_with_statistics=sum(
            item.statistics_blocks > 0 for item in frozen
        ),
        interfaces=frozen,
        raw_interface_identifiers_serialized=False,
        absolute_timestamps_serialized=False,
        capture_loss_excluded=False,
        specific_packet_loss_confirmed=False,
        root_cause_confirmed=False,
        cautions=tuple(cautions),
    )
