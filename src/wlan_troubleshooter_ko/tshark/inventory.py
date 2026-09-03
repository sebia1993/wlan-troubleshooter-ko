"""실행 전 준비와 실제 Phase 4A 프로토콜 인벤토리 오케스트레이션."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Mapping, Optional, Tuple

from wlan_troubleshooter_ko.analysis.protocol_inventory import (
    ProtocolInventory,
    build_protocol_inventory,
)
from wlan_troubleshooter_ko.core.capture import CaptureInfo, validate_capture
from wlan_troubleshooter_ko.tshark.catalog import FieldCatalog, parse_field_catalog
from wlan_troubleshooter_ko.tshark.manifest import verify_bundle
from wlan_troubleshooter_ko.tshark.policy import (
    build_field_catalog_argv,
    build_profile_argv,
)
from wlan_troubleshooter_ko.tshark.profiles import (
    ResolvedProfile,
    load_field_profiles,
    resolve_profile,
)
from wlan_troubleshooter_ko.tshark.runner import (
    TSharkExecutionError,
    build_isolated_environment,
    probe_bundle_runtime,
)


@dataclass(frozen=True)
class _TSharkTextResult:
    bundle_version: str
    manifest_sha256: str
    text: str


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
) -> _TSharkTextResult:
    initial_capture = validate_capture(capture_path, cancel_event=cancel_event)
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
    return _TSharkTextResult(after.version, after.manifest_sha256, text)


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
    """실제 TShark 실행에서 정규화된 식별자 없는 인벤토리 결과."""

    bundle_version: str
    manifest_sha256: str
    resolved_profile: ResolvedProfile
    catalog_records: int
    inventory: ProtocolInventory

    def to_dict(self) -> Dict[str, object]:
        return {
            "bundle_version": self.bundle_version,
            "manifest_sha256": self.manifest_sha256,
            "profile_id": self.resolved_profile.profile_id,
            "profile_version": self.resolved_profile.profile_version,
            "resolved_fields": list(self.resolved_profile.headers()),
            "catalog_records": self.catalog_records,
            "inventory": self.inventory.to_dict(),
        }


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
    """실제 저장 캡처에서 프로토콜 존재 프레임만 안전하게 집계한다."""

    if not workspace_root.is_dir():
        raise TSharkExecutionError("프로토콜 분석 작업공간이 준비되지 않았습니다.")
    if expected_frames is not None and (
        type(expected_frames) is not int or expected_frames < 0
    ):
        raise TSharkExecutionError("예상 프레임 수가 올바르지 않습니다.")

    registry = load_field_profiles(profile_path)
    catalog_result = run_field_catalog_text(
        vendor_root,
        workspace_root / "field-catalog",
        timeout_seconds=min(timeout_seconds, 60),
        cancel_event=cancel_event,
    )
    catalog = parse_field_catalog(catalog_result.text.splitlines(keepends=True))
    resolved_profile = resolve_profile(registry, catalog, "protocol-inventory")

    fields_result = run_profile_fields_text(
        vendor_root,
        capture_path,
        workspace_root / "protocol-inventory",
        resolved_profile,
        timeout_seconds=timeout_seconds,
        cancel_event=cancel_event,
    )
    if (
        fields_result.bundle_version != catalog_result.bundle_version
        or fields_result.manifest_sha256 != catalog_result.manifest_sha256
    ):
        raise TSharkExecutionError("TShark 번들이 필드 검사와 프로토콜 검사 사이에 변경됐습니다.")

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
