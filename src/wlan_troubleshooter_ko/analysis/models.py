"""캡처 사전 점검의 불변 결과 모델."""

from dataclasses import dataclass
from typing import Dict, Optional, Tuple


class CaptureStructureError(ValueError):
    """캡처 컨테이너 구조를 안전하게 해석할 수 없는 경우."""


@dataclass(frozen=True)
class InterfaceSummary:
    section_index: int
    interface_id: int
    link_type: int
    link_type_name: str
    snaplen: int
    timestamp_resolution: str
    packets_scanned: int
    truncated_packets_observed: int

    def to_dict(self) -> Dict[str, object]:
        return {
            "section_index": self.section_index,
            "interface_id": self.interface_id,
            "link_type": self.link_type,
            "link_type_name": self.link_type_name,
            "snaplen": self.snaplen,
            "timestamp_resolution": self.timestamp_resolution,
            "packets_scanned": self.packets_scanned,
            "truncated_packets_observed": self.truncated_packets_observed,
        }


@dataclass(frozen=True)
class InterfaceStatisticsObservation:
    """하나의 PCAPNG Interface Statistics Block 관찰 결과."""

    interface_alias: str
    section_index: int
    interface_id: int
    observation_index: int
    counter_state: str
    ifrecv: Optional[int]
    ifdrop: Optional[int]
    filteraccept: Optional[int]
    osdrop: Optional[int]
    usrdeliv: Optional[int]
    block_timestamp_present: bool
    start_time_present: bool
    end_time_present: bool
    absolute_timestamps_serialized: bool = False
    capture_loss_excluded: bool = False
    root_cause_confirmed: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "interface_alias": self.interface_alias,
            "section_index": self.section_index,
            "interface_id": self.interface_id,
            "observation_index": self.observation_index,
            "counter_state": self.counter_state,
            "ifrecv": self.ifrecv,
            "ifdrop": self.ifdrop,
            "filteraccept": self.filteraccept,
            "osdrop": self.osdrop,
            "usrdeliv": self.usrdeliv,
            "block_timestamp_present": self.block_timestamp_present,
            "start_time_present": self.start_time_present,
            "end_time_present": self.end_time_present,
            "absolute_timestamps_serialized": self.absolute_timestamps_serialized,
            "capture_loss_excluded": self.capture_loss_excluded,
            "root_cause_confirmed": self.root_cause_confirmed,
        }


@dataclass(frozen=True)
class CaptureStructure:
    capture_format: str
    byte_order: str
    timestamp_precision: str
    sections: int
    interfaces: Tuple[InterfaceSummary, ...]
    records_scanned: int
    packets_scanned: int
    truncated_packets_observed: int
    scan_complete: bool
    warnings: Tuple[str, ...]
    interface_statistics_state: str = "no-interface-statistics"
    interface_statistics: Tuple[InterfaceStatisticsObservation, ...] = ()

    def to_dict(self) -> Dict[str, object]:
        return {
            "capture_format": self.capture_format,
            "byte_order": self.byte_order,
            "timestamp_precision": self.timestamp_precision,
            "sections": self.sections,
            "interfaces": [item.to_dict() for item in self.interfaces],
            "records_scanned": self.records_scanned,
            "packets_scanned": self.packets_scanned,
            "truncated_packets_observed": self.truncated_packets_observed,
            "scan_complete": self.scan_complete,
            "warnings": list(self.warnings),
            "interface_statistics_state": self.interface_statistics_state,
            "interface_statistics": [
                item.to_dict() for item in self.interface_statistics
            ],
        }


@dataclass(frozen=True)
class CaptureCapabilityReport:
    capture_kind: str
    capture_kind_label: str
    summary: str
    has_80211_link_type: bool
    has_radiotap_link_type: bool
    has_ip_path_link_type: bool
    available_checks: Tuple[str, ...]
    unavailable_checks: Tuple[str, ...]
    cautions: Tuple[str, ...]

    def to_dict(self) -> Dict[str, object]:
        return {
            "capture_kind": self.capture_kind,
            "capture_kind_label": self.capture_kind_label,
            "summary": self.summary,
            "has_80211_link_type": self.has_80211_link_type,
            "has_radiotap_link_type": self.has_radiotap_link_type,
            "has_ip_path_link_type": self.has_ip_path_link_type,
            "available_checks": list(self.available_checks),
            "unavailable_checks": list(self.unavailable_checks),
            "cautions": list(self.cautions),
        }
