"""캡처 사전 점검부터 PCAPNG 통계와 EAPOL 관계까지 조정한다."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Union

from wlan_troubleshooter_ko.analysis.capture_observability import (
    CaptureObservabilityError,
    CaptureObservabilityReport,
    build_capture_observability,
)
from wlan_troubleshooter_ko.analysis.device_journeys import DeviceJourneyError
from wlan_troubleshooter_ko.analysis.device_sessions import DeviceSessionError
from wlan_troubleshooter_ko.analysis.eapol_handshakes import (
    EapolHandshakeError,
    EapolHandshakeReport,
    build_eapol_handshakes,
)
from wlan_troubleshooter_ko.analysis.eapol_replay_relations import (
    EapolReplayRelationError,
    EapolReplayRelationReport,
)
from wlan_troubleshooter_ko.analysis.event_correlation import EventCorrelationError
from wlan_troubleshooter_ko.analysis.event_timeline import EventTimelineError
from wlan_troubleshooter_ko.analysis.models import (
    CaptureCapabilityReport,
    CaptureStructure,
    CaptureStructureError,
)
from wlan_troubleshooter_ko.analysis.pcapng_interface_statistics import (
    PcapngInterfaceStatisticsError,
    PcapngInterfaceStatisticsReport,
)
from wlan_troubleshooter_ko.analysis.pcapng_statistics_service import (
    inspect_pcapng_interface_statistics,
)
from wlan_troubleshooter_ko.analysis.preflight import (
    classify_capture_capabilities,
    inspect_capture_structure,
)
from wlan_troubleshooter_ko.analysis.protocol_inventory import ProtocolInventoryError
from wlan_troubleshooter_ko.analysis.transaction_sessions import TransactionSessionError
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
from wlan_troubleshooter_ko.tshark.replay_analysis import (
    run_eapol_replay_relation_analysis,
)
from wlan_troubleshooter_ko.tshark.runner import TSharkExecutionError
from wlan_troubleshooter_ko.tshark.status import inspect_bundle


PathLike = Union[str, Path]


class CaptureAnalysisError(ValueError):
    """사전 점검조차 안전하게 완료할 수 없는 경우."""


@dataclass(frozen=True)
class CaptureAnalysisResult:
    """경로·원본 식별자·키 원문을 포함하지 않는 전체 분석 결과."""

    capture_format: str
    size_bytes: int
    sha256_prefix: str
    structure: CaptureStructure
    capabilities: CaptureCapabilityReport
    inventory_state: str
    inventory_message: str
    protocol_inventory: Optional[ProtocolInventoryRun]
    capture_observability: Optional[CaptureObservabilityReport] = None
    eapol_handshakes: Optional[EapolHandshakeReport] = None
    eapol_replay_relations: Optional[EapolReplayRelationReport] = None
    pcapng_interface_statistics: Optional[PcapngInterfaceStatisticsReport] = None

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
            "pcapng_interface_statistics": (
                None
                if self.pcapng_interface_statistics is None
                else self.pcapng_interface_statistics.to_dict()
            ),
            "protocol_inventory_state": self.inventory_state,
            "protocol_inventory_message": self.inventory_message,
            "protocol_inventory": (
                None
                if self.protocol_inventory is None
                else self.protocol_inventory.to_dict()
            ),
            "capture_observability": (
                None
                if self.capture_observability is None
                else self.capture_observability.to_dict()
            ),
            "eapol_handshakes": (
                None
                if self.eapol_handshakes is None
                else self.eapol_handshakes.to_dict()
            ),
            "eapol_replay_relations": (
                None
                if self.eapol_replay_relations is None
                else self.eapol_replay_relations.to_dict()
            ),
        }


def _safe_inventory_failure(exc: Exception) -> str:
    if isinstance(
        exc,
        (
            FieldCompatibilityError,
            TSharkExecutionError,
            EventCorrelationError,
            EventTimelineError,
            TransactionSessionError,
            DeviceSessionError,
            DeviceJourneyError,
            CaptureObservabilityError,
            EapolHandshakeError,
            EapolReplayRelationError,
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
    return (
        "접속 단계·이벤트·거래·단말 여정·캡처 관찰 가능성·"
        "EAPOL 메시지 및 Replay Counter 관계를 안전하게 완료하지 못했습니다."
    )


def _without_inventory(
    capture: CaptureInfo,
    structure: CaptureStructure,
    capabilities: CaptureCapabilityReport,
    statistics: PcapngInterfaceStatisticsReport,
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
        capture_observability=None,
        eapol_handshakes=None,
        eapol_replay_relations=None,
        pcapng_interface_statistics=statistics,
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
    """로컬 PCAPNG 통계와 내장 TShark 공개 분석을 생성한다."""

    try:
        capture: CaptureInfo = validate_capture(
            capture_path,
            cancel_event=cancel_event,
        )
        structure = inspect_capture_structure(
            capture,
            cancel_event=cancel_event,
        )
        capabilities = classify_capture_capabilities(structure)
        statistics = inspect_pcapng_interface_statistics(
            capture,
            cancel_event=cancel_event,
        )
    except (
        CaptureValidationError,
        CaptureStructureError,
        PcapngInterfaceStatisticsError,
    ) as exc:
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
            statistics,
            "unavailable",
            "내장 TShark가 포함되지 않은 소스 실행 모드라 접속 단계 분석을 실행하지 않았습니다.",
        )
    if bundle_status.code != "integrity_verified":
        return _without_inventory(
            capture,
            structure,
            capabilities,
            statistics,
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
            statistics,
            "failed",
            str(exc),
        )

    expected_frames = (
        structure.packets_scanned if structure.scan_complete else None
    )
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
                expected_capture=capture,
                timeout_seconds=timeout_seconds,
                cancel_event=cancel_event,
            )
            if (
                inventory_run.event_timeline is None
                or inventory_run.transaction_sessions is None
                or inventory_run.device_sessions is None
            ):
                raise CaptureObservabilityError(
                    "후속 분석에 필요한 이벤트·거래·단말 가명 결과가 없습니다."
                )
            observability = build_capture_observability(
                structure,
                inventory_run.event_timeline,
                inventory_run.transaction_sessions,
            )
            eapol_handshakes = build_eapol_handshakes(
                inventory_run.event_timeline,
                inventory_run.device_sessions,
            )
            replay_relations = run_eapol_replay_relation_analysis(
                vendor_root,
                capture.path,
                workspace.root,
                profile_path,
                eapol_handshakes,
                expected_capture=capture,
                expected_bundle_version=inventory_run.bundle_version,
                expected_manifest_sha256=inventory_run.manifest_sha256,
                timeout_seconds=timeout_seconds,
                cancel_event=cancel_event,
            )
    except Exception as exc:
        return _without_inventory(
            capture,
            structure,
            capabilities,
            statistics,
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
            "로컬 PCAPNG 인터페이스 통계와 내장 TShark 프로토콜 인벤토리, "
            "접속 단계 Finding, 비식별 이벤트·거래, 단말 가명·여정, "
            "캡처 관찰 가능성, EAPOL-Key 메시지 순서와 Replay Counter 관계 "
            "분석을 완료했습니다."
        ),
        protocol_inventory=inventory_run,
        capture_observability=observability,
        eapol_handshakes=eapol_handshakes,
        eapol_replay_relations=replay_relations,
        pcapng_interface_statistics=statistics,
    )
