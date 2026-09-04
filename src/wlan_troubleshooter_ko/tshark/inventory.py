"""실행 전 준비와 실제 TShark 프로토콜·접속 단계 분석 오케스트레이션."""

from __future__ import annotations

import threading
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Dict, Mapping, Optional, Tuple

from wlan_troubleshooter_ko.analysis.device_journeys import (
    DeviceJourneyReport,
    build_device_journeys,
)
from wlan_troubleshooter_ko.analysis.device_sessions import (
    DeviceSessionReport,
    build_device_sessions,
)
from wlan_troubleshooter_ko.analysis.event_correlation import (
    EventCorrelation,
    build_event_correlation,
)
from wlan_troubleshooter_ko.analysis.event_timeline import (
    EventTimeline,
    build_event_timeline,
)
from wlan_troubleshooter_ko.analysis.protocol_inventory import (
    ProtocolInventory,
    build_protocol_inventory,
)
from wlan_troubleshooter_ko.analysis.transaction_sessions import (
    TransactionSessionReport,
    build_transaction_sessions,
)
from wlan_troubleshooter_ko.core.capture import CaptureInfo, validate_capture
from wlan_troubleshooter_ko.tshark.catalog import FieldCatalog, parse_field_catalog
from wlan_troubleshooter_ko.tshark.manifest import verify_bundle
from wlan_troubleshooter_ko.tshark.policy import (
    build_field_catalog_argv,
    build_profile_argv,
)
from wlan_troubleshooter_ko.tshark.profiles import (
    ResolvedField,
    ResolvedProfile,
    load_field_profiles,
    resolve_profile,
)
from wlan_troubleshooter_ko.tshark.runner import (
    TSharkExecutionError,
    build_isolated_environment,
    probe_bundle_runtime,
)


_TIMELINE_OUTPUT_KEY_ALIASES = {
    "eap_id": "eap_identifier",
    "radius_id": "radius_identifier",
    "dhcp_id": "dhcp_transaction_id",
    "dns_id": "dns_identifier",
    "dns_rcode": "dns_response_code",
}


@dataclass(frozen=True)
class _TSharkTextResult:
    bundle_version: str
    manifest_sha256: str
    text: str
    capture: Optional[CaptureInfo] = None


def _same_capture(first: CaptureInfo, second: CaptureInfo) -> bool:
    return (
        first.path == second.path
        and first.capture_format == second.capture_format
        and first.size_bytes == second.size_bytes
        and first.sha256 == second.sha256
    )


def run_field_catalog_text(
    vendor_root: Path,
    isolation_root: Path,
    *,
    timeout_seconds: int = 60,
    cancel_event: Optional[threading.Event] = None,
    max_stdout_bytes: int = 64 * 1024 * 1024,
) -> _TSharkTextResult:
    before = verify_bundle(vendor_root)
    text = probe_bundle_runtime(
        vendor_root,
        isolation_root,
        timeout_seconds=timeout_seconds,
        cancel_event=cancel_event,
        _mode="field-catalog",
        _max_stdout_bytes=max_stdout_bytes,
    )
    after = verify_bundle(vendor_root)
    if after != before:
        raise TSharkExecutionError("TShark 번들이 필드 검사 중 변경됐습니다.")
    return _TSharkTextResult(after.version, after.manifest_sha256, text)


def run_profile_fields_text(
    vendor_root: Path,
    capture_path: Path,
    isolation_root: Path,
    profile: ResolvedProfile,
    *,
    timeout_seconds: int = 180,
    cancel_event: Optional[threading.Event] = None,
    max_stdout_bytes: int = 64 * 1024 * 1024,
    expected_capture: Optional[CaptureInfo] = None,
) -> _TSharkTextResult:
    """고정 프로파일을 실행하고 동일 캡처 지문을 실행 전후 보장한다."""

    initial_capture = validate_capture(capture_path, cancel_event=cancel_event)
    if expected_capture is not None and not _same_capture(
        expected_capture,
        initial_capture,
    ):
        raise TSharkExecutionError("캡처 파일이 분석 단계 사이에 변경됐습니다.")

    before = verify_bundle(vendor_root)
    text = probe_bundle_runtime(
        vendor_root,
        isolation_root,
        timeout_seconds=timeout_seconds,
        cancel_event=cancel_event,
        _mode="protocol-inventory",
        _capture_path=capture_path,
        _profile=profile,
        _max_stdout_bytes=max_stdout_bytes,
    )
    after = verify_bundle(vendor_root)
    if after != before:
        raise TSharkExecutionError("TShark 번들이 프로토콜 검사 중 변경됐습니다.")

    final_capture = validate_capture(capture_path, cancel_event=cancel_event)
    if not _same_capture(initial_capture, final_capture):
        raise TSharkExecutionError("캡처 파일이 프로토콜 검사 중 변경됐습니다.")
    if expected_capture is not None and not _same_capture(
        expected_capture,
        final_capture,
    ):
        raise TSharkExecutionError("캡처 파일이 분석 단계 사이에 변경됐습니다.")
    return _TSharkTextResult(
        after.version,
        after.manifest_sha256,
        text,
        final_capture,
    )


@dataclass(frozen=True)
class PreparedCatalogInvocation:
    bundle_version: str
    manifest_sha256: str
    arguments: Tuple[str, ...]
    environment: Mapping[str, str]


@dataclass(frozen=True)
class PreparedProtocolInventoryInvocation:
    bundle_version: str
    manifest_sha256: str
    resolved_profile: ResolvedProfile
    arguments: Tuple[str, ...]
    environment: Mapping[str, str]


@dataclass(frozen=True)
class ProtocolInventoryRun:
    """실제 TShark 실행에서 정규화된 공개 분석 결과."""

    bundle_version: str
    manifest_sha256: str
    resolved_profile: ResolvedProfile
    catalog_records: int
    inventory: ProtocolInventory
    event_correlation: Optional[EventCorrelation] = None
    event_timeline: Optional[EventTimeline] = None
    transaction_sessions: Optional[TransactionSessionReport] = None
    device_sessions: Optional[DeviceSessionReport] = None
    device_journeys: Optional[DeviceJourneyReport] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "bundle_version": self.bundle_version,
            "manifest_sha256": self.manifest_sha256,
            "profile_id": self.resolved_profile.profile_id,
            "profile_version": self.resolved_profile.profile_version,
            "resolved_fields": list(self.resolved_profile.headers()),
            "catalog_records": self.catalog_records,
            "inventory": self.inventory.to_dict(),
            "event_correlation": (
                None
                if self.event_correlation is None
                else self.event_correlation.to_dict()
            ),
            "event_timeline": (
                None if self.event_timeline is None else self.event_timeline.to_dict()
            ),
            "transaction_sessions": (
                None
                if self.transaction_sessions is None
                else self.transaction_sessions.to_dict()
            ),
            "device_sessions": (
                None if self.device_sessions is None else self.device_sessions.to_dict()
            ),
            "device_journeys": (
                None if self.device_journeys is None else self.device_journeys.to_dict()
            ),
        }


def adapt_connection_profile_for_timeline(
    profile: ResolvedProfile,
) -> ResolvedProfile:
    """기존 접속 분석 출력 키를 타임라인 모델의 비식별 키로 변환한다."""

    if profile.profile_id != "connection-events":
        raise TSharkExecutionError(
            "접속 이벤트 프로파일만 타임라인으로 변환할 수 있습니다."
        )
    fields = tuple(
        ResolvedField(
            _TIMELINE_OUTPUT_KEY_ALIASES.get(item.output_key, item.output_key),
            item.field_name,
        )
        for item in profile.fields
    )
    output_keys = tuple(item.output_key for item in fields)
    if len(output_keys) != len(set(output_keys)):
        raise TSharkExecutionError("타임라인 출력 키가 중복됐습니다.")
    return ResolvedProfile(
        profile_id="event-timeline",
        profile_version=profile.profile_version,
        display_filter_name=profile.display_filter_name,
        max_packets=profile.max_packets,
        fields=fields,
        missing_optional_fields=tuple(
            sorted(
                _TIMELINE_OUTPUT_KEY_ALIASES.get(item, item)
                for item in profile.missing_optional_fields
            )
        ),
    )


def prepare_field_catalog_invocation(
    vendor_root: Path,
    isolation_root: Path,
) -> PreparedCatalogInvocation:
    """승인 TShark의 고정 `-n -G fields` 호출을 실행 없이 준비한다."""

    bundle = verify_bundle(vendor_root)
    arguments = build_field_catalog_argv(bundle)
    environment = build_isolated_environment(isolation_root)
    return PreparedCatalogInvocation(
        bundle_version=bundle.version,
        manifest_sha256=bundle.manifest_sha256,
        arguments=tuple(arguments),
        environment=environment,
    )


def prepare_protocol_inventory_invocation(
    vendor_root: Path,
    capture_path: Path,
    isolation_root: Path,
    profile_path: Path,
    catalog: FieldCatalog,
    profile_id: str = "protocol-inventory",
) -> PreparedProtocolInventoryInvocation:
    """카탈로그 호환성을 확인한 고정 fields 호출을 실행 없이 준비한다."""

    registry = load_field_profiles(profile_path)
    resolved_profile = resolve_profile(registry, catalog, profile_id)
    bundle = verify_bundle(vendor_root)
    arguments = build_profile_argv(bundle, capture_path, resolved_profile)
    environment = build_isolated_environment(isolation_root)
    return PreparedProtocolInventoryInvocation(
        bundle_version=bundle.version,
        manifest_sha256=bundle.manifest_sha256,
        resolved_profile=resolved_profile,
        arguments=tuple(arguments),
        environment=environment,
    )


def _catalog_and_profile(
    vendor_root: Path,
    workspace_root: Path,
    profile_path: Path,
    profile_id: str,
    timeout_seconds: int,
    cancel_event: Optional[threading.Event],
) -> Tuple[object, FieldCatalog, ResolvedProfile, _TSharkTextResult]:
    registry = load_field_profiles(profile_path)
    catalog_result = run_field_catalog_text(
        vendor_root,
        workspace_root / "field-catalog",
        timeout_seconds=min(timeout_seconds, 60),
        cancel_event=cancel_event,
    )
    catalog = parse_field_catalog(catalog_result.text.splitlines(keepends=True))
    resolved_profile = resolve_profile(registry, catalog, profile_id)
    return registry, catalog, resolved_profile, catalog_result


def _same_verified_runtime(
    first: _TSharkTextResult,
    second: _TSharkTextResult,
) -> bool:
    return (
        first.bundle_version == second.bundle_version
        and first.manifest_sha256 == second.manifest_sha256
    )


def _same_verified_capture(
    first: _TSharkTextResult,
    second: _TSharkTextResult,
) -> bool:
    return (
        first.capture is not None
        and second.capture is not None
        and _same_capture(first.capture, second.capture)
    )


def _prepare_device_link_transactions(
    report: TransactionSessionReport,
) -> Tuple[TransactionSessionReport, int]:
    """생략된 근거가 있는 거래는 단말 연결 입력에서 근거를 제거한다."""

    attempts = []
    incomplete_evidence = 0
    for attempt in report.attempts:
        omitted = attempt.evidence_frames_omitted
        if type(omitted) is not int or omitted < 0:
            raise TSharkExecutionError("거래 시도 근거 생략 수가 올바르지 않습니다.")
        if omitted:
            incomplete_evidence += 1
            attempts.append(
                replace(
                    attempt,
                    evidence_frames=(),
                    display_filter="",
                )
            )
        else:
            attempts.append(attempt)
    return replace(report, attempts=tuple(attempts)), incomplete_evidence


def run_protocol_inventory(
    vendor_root: Path,
    capture_path: Path,
    workspace_root: Path,
    profile_path: Path,
    *,
    expected_frames: Optional[int],
    timeout_seconds: int = 180,
    cancel_event: Optional[threading.Event] = None,
) -> ProtocolInventoryRun:
    """기존 최소 프로파일로 프로토콜 존재 프레임만 집계한다."""

    if not workspace_root.is_dir():
        raise TSharkExecutionError("프로토콜 분석 작업공간이 준비되지 않았습니다.")
    if expected_frames is not None and (
        type(expected_frames) is not int or expected_frames < 0
    ):
        raise TSharkExecutionError("예상 프레임 수가 올바르지 않습니다.")

    registry, catalog, resolved_profile, catalog_result = _catalog_and_profile(
        vendor_root,
        workspace_root,
        profile_path,
        "protocol-inventory",
        timeout_seconds,
        cancel_event,
    )
    fields_result = run_profile_fields_text(
        vendor_root,
        capture_path,
        workspace_root / "protocol-inventory",
        resolved_profile,
        timeout_seconds=timeout_seconds,
        cancel_event=cancel_event,
    )
    if not _same_verified_runtime(catalog_result, fields_result):
        raise TSharkExecutionError(
            "TShark 번들이 필드 검사와 프로토콜 검사 사이에 변경됐습니다."
        )

    inventory = build_protocol_inventory(
        fields_result.text,
        resolved_profile,
        registry.protocol_groups,
        expected_frames=expected_frames,
    )
    return ProtocolInventoryRun(
        bundle_version=fields_result.bundle_version,
        manifest_sha256=fields_result.manifest_sha256,
        resolved_profile=resolved_profile,
        catalog_records=catalog.records_scanned,
        inventory=inventory,
    )


def run_connection_analysis(
    vendor_root: Path,
    capture_path: Path,
    workspace_root: Path,
    profile_path: Path,
    ruleset: Mapping[str, object],
    *,
    expected_frames: Optional[int],
    has_80211_link_type: bool,
    expected_capture: Optional[CaptureInfo] = None,
    timeout_seconds: int = 180,
    cancel_event: Optional[threading.Event] = None,
) -> ProtocolInventoryRun:
    """공개 분석·가명화 출력에서 Finding, 단말 가명과 여정을 만든다."""

    if not workspace_root.is_dir():
        raise TSharkExecutionError("접속 단계 분석 작업공간이 준비되지 않았습니다.")
    if expected_frames is not None and (
        type(expected_frames) is not int or expected_frames < 0
    ):
        raise TSharkExecutionError("예상 프레임 수가 올바르지 않습니다.")

    registry, catalog, resolved_profile, catalog_result = _catalog_and_profile(
        vendor_root,
        workspace_root,
        profile_path,
        "connection-events",
        timeout_seconds,
        cancel_event,
    )
    identity_profile = resolve_profile(registry, catalog, "device-identities")

    fields_result = run_profile_fields_text(
        vendor_root,
        capture_path,
        workspace_root / "connection-events",
        resolved_profile,
        timeout_seconds=timeout_seconds,
        cancel_event=cancel_event,
        expected_capture=expected_capture,
    )
    if not _same_verified_runtime(catalog_result, fields_result):
        raise TSharkExecutionError(
            "TShark 번들이 필드 검사와 접속 단계 검사 사이에 변경됐습니다."
        )

    inventory = build_protocol_inventory(
        fields_result.text,
        resolved_profile,
        registry.protocol_groups,
        expected_frames=expected_frames,
    )
    correlation = build_event_correlation(
        fields_result.text,
        resolved_profile,
        ruleset,
        expected_frames=expected_frames,
        has_80211_link_type=has_80211_link_type,
    )
    timeline = build_event_timeline(
        fields_result.text,
        adapt_connection_profile_for_timeline(resolved_profile),
        expected_frames=expected_frames,
    )
    transaction_sessions = build_transaction_sessions(timeline)
    link_transactions, incomplete_attempt_evidence = (
        _prepare_device_link_transactions(transaction_sessions)
    )

    identity_result = run_profile_fields_text(
        vendor_root,
        capture_path,
        workspace_root / "device-identities",
        identity_profile,
        timeout_seconds=timeout_seconds,
        cancel_event=cancel_event,
        expected_capture=expected_capture,
    )
    if not _same_verified_runtime(fields_result, identity_result):
        raise TSharkExecutionError(
            "TShark 번들이 접속 단계 검사와 단말 가명화 검사 사이에 변경됐습니다."
        )
    if not _same_verified_capture(fields_result, identity_result):
        raise TSharkExecutionError(
            "접속 단계 분석과 단말 가명화 분석의 캡처 지문이 다릅니다."
        )

    device_sessions = build_device_sessions(
        identity_result.text,
        identity_profile,
        link_transactions,
        expected_frames=expected_frames,
    )
    if incomplete_attempt_evidence:
        device_sessions = replace(
            device_sessions,
            complete=False,
            cautions=(
                "근거 프레임이 일부 생략된 거래 시도는 단말에 연결하지 않았습니다.",
                *device_sessions.cautions,
            ),
        )

    device_journeys = build_device_journeys(
        device_sessions,
        transaction_sessions,
    )

    # Raw L2 identifiers exist only in the transient identity output. The
    # returned dataclasses contain aliases and packet evidence only.
    del identity_result
    del link_transactions

    return ProtocolInventoryRun(
        bundle_version=fields_result.bundle_version,
        manifest_sha256=fields_result.manifest_sha256,
        resolved_profile=resolved_profile,
        catalog_records=catalog.records_scanned,
        inventory=inventory,
        event_correlation=correlation,
        event_timeline=timeline,
        transaction_sessions=transaction_sessions,
        device_sessions=device_sessions,
        device_journeys=device_journeys,
    )
