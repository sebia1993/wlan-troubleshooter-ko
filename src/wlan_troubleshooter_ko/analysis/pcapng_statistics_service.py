"""Security wrapper for the identifier-free PCAPNG ISB parser."""

from __future__ import annotations

import threading
from typing import Optional

from wlan_troubleshooter_ko.analysis.pcapng_interface_statistics import (
    PcapngInterfaceStatisticsError,
    PcapngInterfaceStatisticsReport,
    inspect_pcapng_interface_statistics as _inspect_pcapng_interface_statistics,
)
from wlan_troubleshooter_ko.core.capture import (
    CaptureInfo,
    CaptureValidationError,
    validate_capture,
)


def _same_capture(left: CaptureInfo, right: CaptureInfo) -> bool:
    return (
        left.path == right.path
        and left.capture_format == right.capture_format
        and left.size_bytes == right.size_bytes
        and left.sha256 == right.sha256
    )


def inspect_pcapng_interface_statistics(
    expected_capture: CaptureInfo,
    *,
    cancel_event: Optional[threading.Event] = None,
) -> PcapngInterfaceStatisticsReport:
    """Revalidate links, object identity and SHA-256 around ISB parsing."""

    if not isinstance(expected_capture, CaptureInfo):
        raise PcapngInterfaceStatisticsError(
            "검증된 캡처 정보가 필요합니다."
        )
    try:
        before = validate_capture(
            expected_capture.path,
            cancel_event=cancel_event,
        )
    except CaptureValidationError as exc:
        raise PcapngInterfaceStatisticsError(
            "PCAPNG 통계 점검 전에 캡처를 다시 검증하지 못했습니다."
        ) from exc
    if not _same_capture(before, expected_capture):
        raise PcapngInterfaceStatisticsError(
            "캡처 파일이 기존 검증과 PCAPNG 통계 점검 사이에 변경됐습니다."
        )

    report = _inspect_pcapng_interface_statistics(
        expected_capture,
        cancel_event=cancel_event,
    )

    try:
        after = validate_capture(
            expected_capture.path,
            cancel_event=cancel_event,
        )
    except CaptureValidationError as exc:
        raise PcapngInterfaceStatisticsError(
            "PCAPNG 통계 점검 후 캡처를 다시 검증하지 못했습니다."
        ) from exc
    if not _same_capture(after, expected_capture):
        raise PcapngInterfaceStatisticsError(
            "캡처 파일이 PCAPNG 통계 점검 중 변경됐습니다."
        )
    return report
