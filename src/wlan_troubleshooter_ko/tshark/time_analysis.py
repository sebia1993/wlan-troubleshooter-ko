"""Run the dedicated capture-relative time profile with bundle safeguards."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Optional

from wlan_troubleshooter_ko.analysis.capture_time_boundaries import (
    CaptureTimeBoundaryReport,
    build_capture_time_boundaries,
    build_capture_time_index,
)
from wlan_troubleshooter_ko.core.capture import CaptureInfo
from wlan_troubleshooter_ko.tshark.catalog import parse_field_catalog
from wlan_troubleshooter_ko.tshark.inventory import (
    run_field_catalog_text,
    run_profile_fields_text,
)
from wlan_troubleshooter_ko.tshark.profiles import (
    load_field_profiles,
    resolve_profile,
)
from wlan_troubleshooter_ko.tshark.runner import TSharkExecutionError


def _same_capture(left: Optional[CaptureInfo], right: CaptureInfo) -> bool:
    return (
        left is not None
        and left.path == right.path
        and left.capture_format == right.capture_format
        and left.size_bytes == right.size_bytes
        and left.sha256 == right.sha256
    )


def run_capture_time_boundary_analysis(
    vendor_root: Path,
    capture_path: Path,
    workspace_root: Path,
    profile_path: Path,
    transaction_report: object,
    *,
    expected_capture: CaptureInfo,
    expected_bundle_version: str,
    expected_manifest_sha256: str,
    expected_frames: Optional[int],
    timeout_seconds: int = 180,
    cancel_event: Optional[threading.Event] = None,
) -> CaptureTimeBoundaryReport:
    """Execute the minimal timestamp profile and return relative-only values."""

    if not workspace_root.is_dir():
        raise TSharkExecutionError(
            "캡처 상대 시간 분석 작업공간이 준비되지 않았습니다."
        )
    if (
        capture_path != expected_capture.path
        or not isinstance(expected_bundle_version, str)
        or not expected_bundle_version
        or not isinstance(expected_manifest_sha256, str)
        or len(expected_manifest_sha256) != 64
    ):
        raise TSharkExecutionError(
            "캡처 상대 시간 분석의 캡처·TShark 기준 정보가 올바르지 않습니다."
        )

    registry = load_field_profiles(profile_path)
    catalog_result = run_field_catalog_text(
        vendor_root,
        workspace_root / "capture-time-field-catalog",
        timeout_seconds=min(timeout_seconds, 60),
        cancel_event=cancel_event,
    )
    if (
        catalog_result.bundle_version != expected_bundle_version
        or catalog_result.manifest_sha256 != expected_manifest_sha256
    ):
        raise TSharkExecutionError(
            "TShark 번들이 기존 분석과 상대 시간 필드 검사 사이에 변경됐습니다."
        )

    catalog = parse_field_catalog(
        catalog_result.text.splitlines(keepends=True)
    )
    profile = resolve_profile(
        registry,
        catalog,
        "capture-time-boundaries",
    )
    fields_result = run_profile_fields_text(
        vendor_root,
        capture_path,
        workspace_root / "capture-time-boundaries",
        profile,
        timeout_seconds=timeout_seconds,
        cancel_event=cancel_event,
        expected_capture=expected_capture,
    )
    if (
        fields_result.bundle_version != expected_bundle_version
        or fields_result.manifest_sha256 != expected_manifest_sha256
        or fields_result.bundle_version != catalog_result.bundle_version
        or fields_result.manifest_sha256 != catalog_result.manifest_sha256
    ):
        raise TSharkExecutionError(
            "TShark 번들이 캡처 상대 시간 분석 중 변경됐습니다."
        )
    if not _same_capture(fields_result.capture, expected_capture):
        raise TSharkExecutionError(
            "캡처 지문이 기존 분석과 상대 시간 분석 사이에 변경됐습니다."
        )

    index = build_capture_time_index(
        fields_result.text,
        profile,
        expected_frames=expected_frames,
    )
    report = build_capture_time_boundaries(
        index,
        transaction_report,
    )

    del fields_result
    del catalog_result
    return report
