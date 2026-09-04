"""Parse PCAPNG Interface Statistics Blocks without exposing identifiers.

Only standard unsigned 64-bit packet counters are retained. Interface names,
comments, absolute timestamps, option bytes and capture paths are ignored and
never serialized. Reported drops lower capture confidence but never prove that
a particular protocol packet was lost or identify a root cause.
"""

from __future__ import annotations

import hashlib
import struct
import threading
from dataclasses import dataclass
from pathlib import Path
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


def _same_capture(left: CaptureInfo, right: CaptureInfo) -> bool:
    return (
        left.path == right.path
        and left.capture_format == right.capture_format
        and left.size_bytes == right.size_bytes
        and left.sha256 == right.sha256
    )


def _fingerprint(path: Path, capture_format: str) -> CaptureInfo:
    try:
        size = path.stat().st_size
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(_READ_CHUNK)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as exc:
        raise PcapngInterfaceStatisticsError(
            "캡처 파일 지문을 안전하게 확인할 수 없습니다."
        ) from exc
    return CaptureInfo(
        path=path,
        capture_format=capture_format,
        size_bytes=size,
        sha256=digest.hexdigest(),
    )


def _validate_expected_capture(capture: CaptureInfo) -> CaptureInfo:
    if not isinstance(capture, CaptureInfo):
        raise PcapngInterfaceStatisticsError(
            "검증된 캡처 정보가 필요합니다."
        )
    if not capture.path.is_absolute() or not capture.path.is_file():
        raise PcapngInterfaceStatisticsError(
            "검증된 로컬 캡처 파일을 사용할 수 없습니다."
        )
    observed = _fingerprint(capture.path, capture.capture_format)
    if not _same_capture(observed, capture):
        raise PcapngInterfaceStatisticsError(
            "캡처 파일이 기존 검증 이후 변경되었습니다."
        )
    return observed


def _block_length(raw: bytes, endian: str) -> int:
    if len(raw) != 4:
        raise PcapngInterfaceStatisticsError(
            "PCAPNG 블록 길이 필드가 올바르지 않습니다."
        )
    value = struct.unpack(endian + "I", raw)[0]
    if value < 12 or value % 4 or value > _MAX_BLOCK_BYTES:
        raise PcapngInterfaceStatisticsError(
            "PCAPNG 블록 길이가 올바르지 않습니다."
        )
    return value


def _section_header(
    length_bytes: bytes,
    handle: BinaryIO,
) -> Tuple[str, int, bytes]:
    bom = _read_exact(handle, 4)
    if bom == _LITTLE_BOM:
        endian = "<"
    elif bom == _BIG_BOM:
        endian = ">"
    else:
        raise PcapngInterfaceStatisticsError(
            "PCAPNG Section Header의 Byte-Order Magic이 올바르지 않습니다."
        )
    total_length = _block_length(length_bytes, endian)
    if total_length < 28:
        raise PcapngInterfaceStatisticsError(
            "PCAPNG Section Header 길이가 너무 짧습니다."
        )
    remainder = _read_exact(handle, total_length - 12)
    if struct.unpack(endian + "I", remainder[-4:])[0] != total_length:
        raise PcapngInterfaceStatisticsError(
            "PCAPNG Section Header의 앞·뒤 길이가 일치하지 않습니다."
        )
    return endian, total_length, bom + remainder[:-4]


def _options(
    data: bytes,
    endian: str,
) -> Dict[str, int]:
    offset = 0
    count = 0
    counters: Dict[str, int] = {}
    found_end = False
    while offset < len(data):
        if len(data) - offset < 4:
            raise PcapngInterfaceStatisticsError(
                "PCAPNG ISB 옵션 헤더가 잘렸습니다."
            )
        code, length = struct.unpack_from(endian + "HH", data, offset)
        offset += 4
        count += 1
        if count > _MAX_OPTIONS_PER_BLOCK:
            raise PcapngInterfaceStatisticsError(
                "PCAPNG ISB 옵션 수가 안전 제한을 초과했습니다."
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
            found_end = True
            break
        padded = (length + 3) & ~3
        if padded > len(data) - offset:
            raise PcapngInterfaceStatisticsError(
                "PCAPNG ISB 옵션 값이 선언된 길이보다 짧습니다."
            )
        raw = data[offset : offset + length]
        padding = data[offset + length : offset + padded]
        if any(padding):
            raise PcapngInterfaceStatisticsError(
                "PCAPNG ISB 옵션 패딩이 0이 아닙니다."
            )
        offset += padded
        name = _COUNTER_OPTIONS.get(code)
        if name is None:
            continue
        if length != 8:
            raise PcapngInterfaceStatisticsError(
                "PCAPNG ISB Counter 옵션 길이가 8바이트가 아닙니다."
            )
        if name in counters:
            raise PcapngInterfaceStatisticsError(
                "동일 ISB에 같은 Counter 옵션이 중복됐습니다."
            )
        counters[name] = struct.unpack(endian + "Q", raw)[0]
    if data and not found_end:
        # PCAPNG permits options that consume the exact remaining body without
        # an explicit end option. Accept that canonical bounded form.
        if offset != len(data):
            raise PcapngInterfaceStatisticsError(
                "PCAPNG ISB 옵션 영역을 완전히 처리하지 못했습니다."
            )
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


def _interface_state(values: Mapping[str, Sequence[int]], isb_count: int) -> str:
    if isb_count == 0:
        return "no-interface-statistics"
    drop_values = tuple(values.get("ifdrop", ())) + tuple(values.get("osdrop", ()))
    if not drop_values:
        return "statistics-without-drop-counters"
    if any(value > 0 for value in drop_values):
        return "reported-drop-observed"
    return "zero-reported-drop-counters"


def _report_state(interfaces: Sequence[InterfaceStatistics], isb_count: int) -> str:
    if isb_count == 0:
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


def inspect_pcapng_interface_statistics(
    capture: CaptureInfo,
    *,
    cancel_event: Optional[threading.Event] = None,
) -> PcapngInterfaceStatisticsReport:
    """Return identifier-free standard ISB counters for a verified capture."""

    before = _validate_expected_capture(capture)
    if capture.capture_format != "pcapng":
        return _unsupported_report()

    section_index = -1
    endian: Optional[str] = None
    section_interfaces = 0
    blocks = 0
    sections = 0
    isb_blocks = 0
    interfaces: Dict[Tuple[int, int], _InterfaceAccumulator] = {}
    aliases = 0

    try:
        with capture.path.open("rb") as handle:
            while True:
                _cancelled(cancel_event)
                type_bytes = handle.read(4)
                if not type_bytes:
                    break
                if len(type_bytes) != 4:
                    raise PcapngInterfaceStatisticsError(
                        "PCAPNG 블록 종류 필드가 잘렸습니다."
                    )
                length_bytes = _read_exact(handle, 4)
                blocks += 1
                if blocks > _MAX_BLOCKS:
                    raise PcapngInterfaceStatisticsError(
                        "PCAPNG 블록 수가 안전 제한을 초과했습니다."
                    )

                if type_bytes == _SHB_TYPE:
                    endian, _total_length, _body = _section_header(
                        length_bytes,
                        handle,
                    )
                    sections += 1
                    if sections > _MAX_SECTIONS:
                        raise PcapngInterfaceStatisticsError(
                            "PCAPNG 섹션 수가 안전 제한을 초과했습니다."
                        )
                    section_index += 1
                    section_interfaces = 0
                    continue

                if endian is None or section_index < 0:
                    raise PcapngInterfaceStatisticsError(
                        "PCAPNG 첫 블록이 Section Header가 아닙니다."
                    )
                total_length = _block_length(length_bytes, endian)
                remainder = _read_exact(handle, total_length - 8)
                if struct.unpack(endian + "I", remainder[-4:])[0] != total_length:
                    raise PcapngInterfaceStatisticsError(
                        "PCAPNG 블록의 앞·뒤 길이가 일치하지 않습니다."
                    )
                body = remainder[:-4]
                block_type = struct.unpack(endian + "I", type_bytes)[0]

                if block_type == _IDB_TYPE:
                    if len(body) < 8:
                        raise PcapngInterfaceStatisticsError(
                            "PCAPNG Interface Description Block이 너무 짧습니다."
                        )
                    if len(interfaces) >= _MAX_INTERFACES:
                        raise PcapngInterfaceStatisticsError(
                            "PCAPNG 인터페이스 수가 안전 제한을 초과했습니다."
                        )
                    key = (section_index, section_interfaces)
                    aliases += 1
                    interfaces[key] = _InterfaceAccumulator(
                        alias="IFACE-" + str(aliases),
                        section_index=section_index,
                        interface_id=section_interfaces,
                        statistics_blocks=0,
                        counters={name: [] for name in _COUNTER_ORDER},
                    )
                    section_interfaces += 1
                    continue

                if block_type != _ISB_TYPE:
                    continue
                isb_blocks += 1
                if isb_blocks > _MAX_ISB_BLOCKS:
                    raise PcapngInterfaceStatisticsError(
                        "PCAPNG Interface Statistics Block 수가 안전 제한을 초과했습니다."
                    )
                if len(body) < 12:
                    raise PcapngInterfaceStatisticsError(
                        "PCAPNG Interface Statistics Block이 너무 짧습니다."
                    )
                interface_id = struct.unpack_from(endian + "I", body, 0)[0]
                key = (section_index, interface_id)
                accumulator = interfaces.get(key)
                if accumulator is None:
                    raise PcapngInterfaceStatisticsError(
                        "PCAPNG ISB가 정의되지 않은 Interface ID를 참조합니다."
                    )
                counters = _options(body[12:], endian)
                accumulator.statistics_blocks += 1
                for name, value in counters.items():
                    accumulator.counters[name].append(value)
    except OSError as exc:
        raise PcapngInterfaceStatisticsError(
            "PCAPNG 인터페이스 통계를 안전하게 읽을 수 없습니다."
        ) from exc

    if sections == 0:
        raise PcapngInterfaceStatisticsError(
            "PCAPNG Section Header를 찾을 수 없습니다."
        )

    after = _fingerprint(capture.path, capture.capture_format)
    if not _same_capture(before, after):
        raise PcapngInterfaceStatisticsError(
            "PCAPNG 통계 분석 중 캡처 파일이 변경되었습니다."
        )

    frozen_interfaces = []
    for key in sorted(interfaces):
        item = interfaces[key]
        counters = tuple(
            CounterObservation(
                name=name,
                observations=len(item.counters[name]),
                first_value=(
                    item.counters[name][0]
                    if item.counters[name]
                    else None
                ),
                last_value=(
                    item.counters[name][-1]
                    if item.counters[name]
                    else None
                ),
                progression=_progression(item.counters[name]),
            )
            for name in _COUNTER_ORDER
        )
        frozen_interfaces.append(
            InterfaceStatistics(
                interface_alias=item.alias,
                section_index=item.section_index,
                interface_id=item.interface_id,
                statistics_blocks=item.statistics_blocks,
                state=_interface_state(
                    item.counters,
                    item.statistics_blocks,
                ),
                counters=counters,
            )
        )
    frozen = tuple(frozen_interfaces)
    state = _report_state(frozen, isb_blocks)
    cautions = [
        "0으로 보고된 드롭 Counter는 캡처 손실이 없었다는 증명이 아닙니다.",
        "Interface Statistics Block이 없다는 사실은 캡처 손실이 없다는 뜻이 아닙니다.",
        "양의 드롭 Counter는 특정 EAPOL·DHCP·DNS·TCP 패킷 누락을 확정하지 않습니다.",
        "캡처 도구·운영체제·드라이버·SPAN·무선 채널 중 책임 위치를 확정하지 않습니다.",
        "실제 인터페이스 이름과 절대 ISB timestamp는 결과에 기록하지 않습니다.",
    ]
    if state == "reported-drop-observed":
        cautions.insert(
            0,
            "하나 이상의 인터페이스에서 캡처 도구가 보고한 양의 드롭 Counter가 관찰됐습니다.",
        )
    elif state == "statistics-without-drop-counters":
        cautions.insert(
            0,
            "ISB는 있으나 ifdrop·osdrop Counter가 제공되지 않았습니다.",
        )

    return PcapngInterfaceStatisticsReport(
        supported_capture_format=True,
        complete=True,
        state=state,
        sections_observed=sections,
        interfaces_defined=len(frozen),
        statistics_blocks_observed=isb_blocks,
        interfaces_with_statistics=sum(
            1 for item in frozen if item.statistics_blocks > 0
        ),
        interfaces=frozen,
        raw_interface_identifiers_serialized=False,
        absolute_timestamps_serialized=False,
        capture_loss_excluded=False,
        specific_packet_loss_confirmed=False,
        root_cause_confirmed=False,
        cautions=tuple(cautions),
    )
