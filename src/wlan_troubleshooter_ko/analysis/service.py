"""캡처 사전 점검, 프로토콜 인벤토리와 접속 단계 Finding을 조정한다."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Union

from wlan_troubleshooter_ko.analysis.event_correlation import EventCorrelationError
from wlan_troubleshooter_ko.analysis.models import (
    CaptureCapabilityReport,
    CaptureStructure,
    CaptureStructureError,
)
from wlan_troubleshooter_ko.analysis.preflight import (
    classify_capture_capabilities,
    inspect_capture_structure,
)
from wlan_troubleshooter_ko.analysis.protocol_inventory import ProtocolInventoryError
from wlan_troubleshooter_ko.core.capture import (
    CaptureInfo,
    CaptureValidationError,
    validate_capture,
)
from wlan_troubleshooter_ko.core.config import ConfigurationError, load_ruleset
from wlan_troubleshooter_ko.core.workspace import AnalysisWorkspace, WorkspaceError
from wlan_troubleshooter_ko.tshark.catalog import FieldCatalogError
from wlan_troubleshooter_ko.tshark.inventory import (
    ProtocolInventoryRun,
    run_connection_analysis,
)
from wlan_troubleshooter_ko.tshark.manifest import BundleVerificationError
from wlan_troubleshooter_ko.tshark.profiles import (
    FieldCompatibilityError,
    FieldProfileError,
)
from wlan_troubleshooter_ko.tshark.runner import TSharkExecutionError
from wlan_troubleshooter_ko.tshark.status import inspect_bundle


PathLike = Union[str, Path]


class CaptureAnalysisError(ValueError):
    """사전 점검조차 안전하게 완료할 수 없는 경우."""


@dataclass(frozen=True)
class CaptureAnalysisResult:
    """경로와 패킷 원문을 포함하지 않는 전체 분석 결과."""

    capture_format: str
    size_bytes: int
    sha256_prefix: str
    structure: CaptureStructure
    capabilities: CaptureCapabilityReport
    inventory_state: str
    inventory_message: str
    protocol_inventory: Optional[ProtocolInventoryRun]

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema_version": 2,
            "capture": {
                "format": self.capture_format,
                "size_bytes": self.size_bytes,
                "sha256_prefix": self.sha256_prefix,
            },
            "structure": self.structure.to_dict(),
            "capabilities": self.capabilities.to_dict(),
            "protocol_inventory_state": self.inventory_state,
            "protocol_inventory_message": self.inventory_message,
            "protocol_inventory": (
                None
                if self.protocol_inventory is None
                else self.protocol_inventory.to_dict()
            ),
        }


def _safe_inventory_failure(exc: Exception) -> str:
    if isinstance(
        exc,
        (
            FieldCompatibilityError,
            TSharkExecutionError,
            EventCorrelationError,
        ),
    ):
        return str(exc)
    if isinstance(
        exc,
        (
            FieldCatalogError,
            FieldProfileError,
            ProtocolInventoryError,
            WorkspaceError,
            ConfigurationError,
        ),
    ):
        return str(exc)
    if isinstance(exc, BundleVerificationError):
        return (
            "내장 TShark 파일이 누락되었거나 변경되었습니다. "
            "배포 ZIP을 다시 압축 해제해 주세요."
        )
    return "접속 단계 분석을 안전하게 완료하지 못했습니다."


def _without_inventory(
    capture: CaptureInfo,
    structure: CaptureStructure,
    capabilities: CaptureCapabilityReport,
    state: str,
    message: str,
) -> CaptureAnalysisResult:
    return CaptureAnalysisResult(
        capture_format=capture.capture_format,
        size_bytes=capture.size_bytes,
        sha256_prefix=capture.sha256[:12],
        structure=structure,
        capabilities=capabilities,
        inventory_state=state,
        inventory_message=message,
        protocol_inventory=None,
    )


def analyze_capture(
    capture_path: PathLike,
    vendor_root: Path,
    profile_path: Path,
    *,
    rules_path: Optional[Path] = None,
    workspace_base: Optional[PathLike] = None,
    timeout_seconds: int = 180,
    cancel_event: Optional[threading.Event] = None,
) -> CaptureAnalysisResult:
    """사전 점검 후 내장 TShark로 접속 단계와 명시적 실패 응답을 분석한다."""

    try:
        capture: CaptureInfo = validate_capture(capture_path, cancel_event=cancel_event)
        structure = inspect_capture_structure(capture, cancel_event=cancel_event)
        capabilities = classify_capture_capabilities(structure)
    except (CaptureValidationError, CaptureStructureError) as exc:
        raise CaptureAnalysisError(str(exc)) from exc
    except Exception:
        raise CaptureAnalysisError(
            "캡처 파일을 안전하게 사전 점검하지 못했습니다."
        ) from None

    bundle_status = inspect_bundle(vendor_root)
    if bundle_status.code == "not_provisioned":
        return _without_inventory(
            capture,
            structure,
            capabilities,
            "unavailable",
            "내장 TShark가 포함되지 않은 소스 실행 모드라 접속 단계 분석을 실행하지 않았습니다.",
        )
    if bundle_status.code != "integrity_verified":
        return _without_inventory(
            capture,
            structure,
            capabilities,
            "failed",
            "내장 TShark 파일이 누락되었거나 변경되었습니다. 배포 ZIP을 다시 압축 해제해 주세요.",
        )

    if rules_path is None:
        rules_path = (
            Path(__file__).resolve().parents[1]
            / "resources"
            / "rules"
            / "v1"
            / "rules.json"
        )
    try:
        ruleset = load_ruleset(rules_path)
    except ConfigurationError as exc:
        return _without_inventory(
            capture,
            structure,
            capabilities,
            "failed",
            str(exc),
        )

    expected_frames = structure.packets_scanned if structure.scan_complete else None
    try:
        with AnalysisWorkspace(base_directory=workspace_base) as workspace:
            inventory_run = run_connection_analysis(
                vendor_root,
                capture.path,
                workspace.root,
                profile_path,
                ruleset,
                expected_frames=expected_frames,
                has_80211_link_type=capabilities.has_80211_link_type,
                timeout_seconds=timeout_seconds,
                cancel_event=cancel_event,
            )
    except Exception as exc:
        return _without_inventory(
            capture,
            structure,
            capabilities,
            "failed",
            _safe_inventory_failure(exc),
        )

    return CaptureAnalysisResult(
        capture_format=capture.capture_format,
        size_bytes=capture.size_bytes,
        sha256_prefix=capture.sha256[:12],
        structure=structure,
        capabilities=capabilities,
        inventory_state="completed",
        inventory_message=(
            "내장 TShark로 프로토콜 존재 인벤토리와 접속 단계 Finding을 완료했습니다."
        ),
        protocol_inventory=inventory_run,
    )
