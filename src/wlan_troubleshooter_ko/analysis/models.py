"""캡처 사전 점검의 불변 결과 모델."""

from dataclasses import dataclass
from typing import Dict, Tuple


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
