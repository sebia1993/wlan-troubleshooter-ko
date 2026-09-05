"""캡처 구조 스캔을 실행하고 초급자용 분석 가능 범위를 분류한다."""

from __future__ import annotations

import threading
from typing import Iterable, List, Optional

from wlan_troubleshooter_ko.analysis.linktypes import (
    IP_PATH_LINK_TYPES,
    PPI_LINK_TYPES,
    RADIOTAP_LINK_TYPES,
    WLAN_LINK_TYPES,
)
from wlan_troubleshooter_ko.analysis.models import (
    CaptureCapabilityReport,
    CaptureStructure,
    CaptureStructureError,
    InterfaceSummary,
)
from wlan_troubleshooter_ko.analysis.pcap_scan import scan_pcap
from wlan_troubleshooter_ko.analysis.pcapng_scan import scan_pcapng
from wlan_troubleshooter_ko.analysis.pcapng_statistics import (
    enrich_pcapng_interface_statistics,
)
from wlan_troubleshooter_ko.core.capture import (
    CaptureInfo,
    CaptureValidationError,
    validate_capture,
)


_DEFAULT_MAX_RECORDS = 1_000_000
_DEFAULT_MAX_BLOCK_LENGTH = 64 * 1024 * 1024
_DEFAULT_MAX_RECORD_LENGTH = 64 * 1024 * 1024


def _check_cancel(cancel_event: Optional[threading.Event]) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise CaptureStructureError("캡처 구조 점검이 취소됐습니다.")


def _assert_unchanged(
    capture: CaptureInfo,
    cancel_event: Optional[threading.Event],
) -> None:
    try:
        current = validate_capture(capture.path, cancel_event=cancel_event)
    except CaptureValidationError as exc:
        raise CaptureStructureError("캡처 파일이 구조 점검 중 변경됐습니다.") from exc
    if (
        current.capture_format != capture.capture_format
        or current.size_bytes != capture.size_bytes
        or current.sha256 != capture.sha256
    ):
        raise CaptureStructureError("캡처 파일이 구조 점검 중 변경됐습니다.")


def inspect_capture_structure(
    capture: CaptureInfo,
    *,
    max_records: int = _DEFAULT_MAX_RECORDS,
    max_block_length: int = _DEFAULT_MAX_BLOCK_LENGTH,
    max_record_length: int = _DEFAULT_MAX_RECORD_LENGTH,
    cancel_event: Optional[threading.Event] = None,
) -> CaptureStructure:
    """검증된 캡처의 컨테이너 구조만 bounded scan으로 점검한다."""

    if not isinstance(capture, CaptureInfo):
        raise CaptureStructureError("검증된 캡처 정보가 필요합니다.")
    if not 1 <= max_records <= 10_000_000:
        raise CaptureStructureError("레코드 점검 제한이 허용 범위를 벗어났습니다.")
    if not 64 * 1024 <= max_block_length <= 256 * 1024 * 1024:
        raise CaptureStructureError("블록 길이 제한이 허용 범위를 벗어났습니다.")
    if not 64 * 1024 <= max_record_length <= 256 * 1024 * 1024:
        raise CaptureStructureError("패킷 길이 제한이 허용 범위를 벗어났습니다.")
    _check_cancel(cancel_event)
    try:
        with capture.path.open("rb") as handle:
            if capture.capture_format == "pcap":
                result = scan_pcap(
                    handle,
                    capture,
                    max_records,
                    max_record_length,
                    cancel_event,
                )
            elif capture.capture_format == "pcapng":
                result = scan_pcapng(
                    handle,
                    capture,
                    max_records,
                    max_block_length,
                    cancel_event,
                )
                result = enrich_pcapng_interface_statistics(
                    handle,
                    capture,
                    result,
                    max_records,
                    max_block_length,
                    cancel_event,
                )
            else:
                raise CaptureStructureError("지원하지 않는 캡처 형식입니다.")
    except CaptureStructureError:
        raise
    except OSError:
        raise CaptureStructureError("캡처 구조를 안전하게 읽을 수 없습니다.") from None
    _check_cancel(cancel_event)
    _assert_unchanged(capture, cancel_event)
    return result


def _extend_once(target: List[str], values: Iterable[str]) -> None:
    for value in values:
        if value not in target:
            target.append(value)


def classify_capture_capabilities(
    structure: CaptureStructure,
) -> CaptureCapabilityReport:
    """Link Type만으로 확인 가능한 항목과 판단할 수 없는 항목을 분리한다."""

    link_types = {item.link_type for item in structure.interfaces}
    has_wlan = bool(link_types & WLAN_LINK_TYPES)
    has_radiotap = bool(link_types & RADIOTAP_LINK_TYPES)
    has_ip_path = bool(link_types & IP_PATH_LINK_TYPES)
    has_non_wlan = bool(link_types - WLAN_LINK_TYPES)

    if has_wlan and has_non_wlan:
        kind = "mixed"
        label = "무선 Air Capture와 비무선 인터페이스가 혼합된 캡처"
        summary = "인터페이스별 캡처 지점을 구분한 뒤 단계별로 분석해야 합니다."
    elif has_radiotap:
        kind = "wireless-air-radiotap"
        label = "Radiotap이 포함된 무선 Air Capture"
        summary = "802.11 관리 프레임과 RF 메타데이터 존재 여부를 후속 분석할 수 있습니다."
    elif has_wlan:
        kind = "wireless-air-no-radiotap"
        label = "Radiotap이 없는 IEEE 802.11 캡처"
        summary = "802.11 프레임은 볼 수 있지만 RSSI·채널 메타데이터는 확인할 수 없습니다."
    elif has_ip_path:
        kind = "wired-or-controller"
        label = "유선·컨트롤러 측 캡처"
        summary = "IP 통신 단계는 후속 확인할 수 있지만 Association과 RF 상태는 판단할 수 없습니다."
    else:
        kind = "unknown"
        label = "인터페이스 유형을 확인할 수 없는 캡처"
        summary = "캡처 구조는 읽었지만 분석 가능한 네트워크 계층을 확정할 수 없습니다."

    available = ["캡처 형식·인터페이스·패킷 잘림 사전 점검"]
    unavailable: List[str] = []
    cautions = ["Link Type은 해당 프로토콜이 실제로 포함됐다는 증거가 아닙니다."]
    if has_wlan:
        available.append("802.11 인증·Association·Deauthentication 프레임 존재 여부(후속 TShark 확인 필요)")
    else:
        unavailable.append("802.11 Association·Deauthentication·로밍 프레임 분석")
    if has_radiotap:
        available.append("Radiotap 기반 RSSI·채널·데이터율·Retry 메타데이터 존재 여부(후속 확인 필요)")
    else:
        unavailable.append("RSSI·SNR·채널·무선 Retry 분석")
    if has_ip_path:
        available.append("DHCP·DNS·ARP·TCP·TLS 패킷 존재 여부(후속 TShark 확인 필요)")
    else:
        unavailable.append("IP 계층 DHCP·DNS·TCP 연결 분석")
    if structure.interface_statistics:
        available.append("PCAPNG Interface Statistics Block 카운터 관찰")
        if any(
            item.counter_state == "reported-drop-observed"
            for item in structure.interface_statistics
        ):
            cautions.append("PCAPNG 통계에 0보다 큰 드롭 카운터가 있지만 특정 장애 패킷 누락이나 근본 원인을 확정하지 않습니다.")
        else:
            cautions.append("PCAPNG 드롭 카운터가 없거나 0이어도 캡처 손실이 없었다고 확정하지 않습니다.")
    elif structure.capture_format == "pcapng":
        cautions.append("PCAPNG 인터페이스 통계(Interface Statistics Block)가 없어 캡처 도구 드롭 카운터를 확인할 수 없습니다.")
    if link_types & PPI_LINK_TYPES:
        cautions.append("PPI는 내부 캡슐화를 확인하기 전 802.11·RF·IP 캡처로 확정하지 않습니다.")
    if structure.truncated_packets_observed:
        cautions.append("잘린 패킷이 있어 상위 프로토콜 해석이 불완전할 수 있습니다.")
    if not structure.scan_complete:
        cautions.append("안전 제한으로 일부 레코드만 점검해 전체 개수는 확정값이 아닙니다.")
    if kind == "mixed":
        cautions.append("혼합 캡처는 인터페이스별 결과를 합쳐 단정하면 안 됩니다.")
    _extend_once(cautions, structure.warnings)

    return CaptureCapabilityReport(
        capture_kind=kind,
        capture_kind_label=label,
        summary=summary,
        has_80211_link_type=has_wlan,
        has_radiotap_link_type=has_radiotap,
        has_ip_path_link_type=has_ip_path,
        available_checks=tuple(available),
        unavailable_checks=tuple(unavailable),
        cautions=tuple(sorted(set(cautions))),
    )
