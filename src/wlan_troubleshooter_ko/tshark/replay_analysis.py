"""Run the dedicated EAPOL Replay Counter relation extraction safely.

Raw Replay Counter values exist only in this function's local TShark text and
in the relation builder's transient integers. The returned report contains
only equality/ordering relationships and packet evidence.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Optional

from wlan_troubleshooter_ko.analysis.eapol_replay_relations import (
    EapolReplayRelationReport,
    build_eapol_replay_relations,
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


def run_eapol_replay_relation_analysis(
    vendor_root: Path,
    capture_path: Path,
    workspace_root: Path,
    profile_path: Path,
    handshake_report: object,
    *,
    expected_capture: CaptureInfo,
    expected_bundle_version: str,
    expected_manifest_sha256: str,
    timeout_seconds: int = 180,
    cancel_event: Optional[threading.Event] = None,
) -> EapolReplayRelationReport:
    """Execute the minimal counter profile and return identifier-free relations."""

    if not workspace_root.is_dir():
        raise TSharkExecutionError(
            "Replay Counter 관계 분석 작업공간이 준비되지 않았습니다."
        )
    if (
        not isinstance(expected_bundle_version, str)
        or not expected_bundle_version
        or not isinstance(expected_manifest_sha256, str)
        or len(expected_manifest_sha256) != 64
    ):
        raise TSharkExecutionError(
            "Replay Counter 관계 분석의 TShark 기준 정보가 올바르지 않습니다."
        )

    registry = load_field_profiles(profile_path)
    catalog_result = run_field_catalog_text(
        vendor_root,
        workspace_root / "eapol-replay-field-catalog",
        timeout_seconds=min(timeout_seconds, 60),
        cancel_event=cancel_event,
    )
    if (
        catalog_result.bundle_version != expected_bundle_version
        or catalog_result.manifest_sha256 != expected_manifest_sha256
    ):
        raise TSharkExecutionError(
            "TShark 번들이 기존 분석과 Replay Counter 필드 검사 사이에 변경됐습니다."
        )

    catalog = parse_field_catalog(
        catalog_result.text.splitlines(keepends=True)
    )
    profile = resolve_profile(
        registry,
        catalog,
        "eapol-replay-relations",
    )
    fields_result = run_profile_fields_text(
        vendor_root,
        capture_path,
        workspace_root / "eapol-replay-relations",
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
            "TShark 번들이 Replay Counter 관계 분석 중 변경됐습니다."
        )
    if fields_result.capture is None:
        raise TSharkExecutionError(
            "Replay Counter 관계 분석의 캡처 지문을 확인할 수 없습니다."
        )

    report = build_eapol_replay_relations(
        fields_result.text,
        profile,
        handshake_report,
    )

    # Explicitly release the raw text/result references before leaving the
    # isolated analysis workspace. The public report contains relationships
    # and frame numbers only.
    del fields_result
    del catalog_result
    return report
