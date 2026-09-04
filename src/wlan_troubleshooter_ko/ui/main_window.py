"""완전 오프라인 WLAN 캡처 분석 GUI."""

from __future__ import annotations

import threading
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Iterable, Optional, Sequence, Tuple

from wlan_troubleshooter_ko.analysis.models import (
    CaptureCapabilityReport,
    CaptureStructure,
)
from wlan_troubleshooter_ko.analysis.service import (
    CaptureAnalysisError,
    CaptureAnalysisResult,
    analyze_capture,
)
from wlan_troubleshooter_ko.core.capture import CaptureInfo
from wlan_troubleshooter_ko.tshark.profiles import FieldProfileError, load_field_profiles
from wlan_troubleshooter_ko.tshark.status import BundleStatus, inspect_bundle


@dataclass(frozen=True)
class CaptureViewState:
    status: str
    detail: str
    valid: bool


_EVENT_LABELS = {
    "eap_request": "EAP 요청",
    "eap_response": "EAP 응답",
    "eap_success": "EAP 성공",
    "eap_failure": "EAP 실패",
    "radius_access_request": "RADIUS Access-Request",
    "radius_access_challenge": "RADIUS Access-Challenge",
    "radius_access_accept": "RADIUS Access-Accept",
    "radius_access_reject": "RADIUS Access-Reject",
    "dhcp_discover": "DHCP Discover",
    "dhcp_offer": "DHCP Offer",
    "dhcp_request": "DHCP Request",
    "dhcp_ack": "DHCP ACK",
    "dhcp_nak": "DHCP NAK",
    "dns_query": "DNS 질의",
    "dns_response_success": "DNS 정상 응답",
    "dns_response_error": "DNS 오류 응답",
    "tcp_syn": "TCP SYN",
    "tcp_syn_ack": "TCP SYN/ACK",
    "tcp_reset": "TCP RST",
    "tcp_retransmission": "TCP 재전송 표시",
    "tls_client_hello": "TLS ClientHello",
    "tls_server_hello": "TLS ServerHello",
    "tls_certificate": "TLS Certificate",
    "tls_finished": "TLS Finished",
}

_EVIDENCE_LABELS = {
    "wlan-management-request": "802.11 관리 요청",
    "wlan-management-response": "802.11 관리 응답",
    "wlan-authentication-request": "802.11 인증 요청",
    "wlan-authentication-response": "802.11 인증 응답",
    "wlan-authentication-frame": "802.11 인증 프레임",
    "wlan-disconnect-frame": "802.11 연결 해제",
    "wlan-eap-supplicant": "무선 EAP Supplicant",
    "ethernet-eap-request": "유선 EAP 요청 대상",
    "ethernet-eap-response": "유선 EAP 응답 송신",
    "ethernet-eap-result": "유선 EAP 결과 대상",
    "ethernet-eapol-supplicant": "EAPOL Supplicant",
    "dhcp-client": "DHCP 클라이언트 송신",
    "known-l2-address": "기확인 L2 주소",
}


def _compact(items: Sequence[str], limit: int = 5) -> str:
    values = tuple(items)
    if not values:
        return "없음"
    visible = list(values[:limit])
    if len(values) > limit:
        visible.append("외 {0}개".format(len(values) - limit))
    return " · ".join(visible)


def _frames(values: Iterable[int]) -> str:
    items = tuple(values)
    return "없음" if not items else ", ".join("#{0:,}".format(value) for value in items)


def _event_labels(values: Iterable[str]) -> str:
    items = tuple(values)
    if not items:
        return "없음"
    return " → ".join(_EVENT_LABELS.get(value, value) for value in items)


def _display_filter(frames: Iterable[int]) -> str:
    values = tuple(frames)
    return " || ".join("frame.number == {0}".format(value) for value in values)


def _portable_status(bundle_status: BundleStatus) -> str:
    resources = Path(__file__).resolve().parents[1] / "resources"
    try:
        registry = load_field_profiles(
            resources / "tshark" / "field-profiles.v1.json"
        )
        events = registry.get_profile("connection-events")
        identities = registry.get_profile("device-identities")
    except FieldProfileError:
        return "분석 프로파일 오류 · 배포본을 다시 받아야 합니다."
    base = (
        "필드 프로파일 {0} · 이벤트 필드 {1}개 · 가명화 필드 {2}개 · "
        "프로토콜 그룹 {3}개"
    ).format(
        registry.profile_version,
        len(events.fields),
        len(identities.fields),
        len(registry.protocol_groups),
    )
    if bundle_status.code == "integrity_verified":
        return base + " · 내장 TShark 무결성 확인됨 · DEVICE-N/AP-N 사용 가능"
    return base + " · 소스 실행 모드 · Portable 배포본은 내장 TShark를 사용합니다."


def _format_preflight(
    capture_format: str,
    size_bytes: int,
    sha256_prefix: str,
    structure: CaptureStructure,
    report: CaptureCapabilityReport,
) -> str:
    return (
        "[1. 캡처 사전 점검]\n"
        "선택 파일: 파일명 비공개 · 형식: {format_name} · 크기: {size:,}바이트 · "
        "SHA-256: {digest}…\n"
        "캡처 유형 추정: {kind}\n"
        "설명: {summary}\n"
        "구조 점검: 인터페이스 {interfaces}개 · 패킷 레코드 {packets:,}개 · "
        "잘린 패킷 {truncated:,}개 · 전체 점검 {complete}\n"
        "형식상 확인 가능: {available}\n"
        "현재 확인 불가: {unavailable}\n"
        "주의: {cautions}"
    ).format(
        format_name=capture_format.upper(),
        size=size_bytes,
        digest=sha256_prefix,
        kind=report.capture_kind_label,
        summary=report.summary,
        interfaces=len(structure.interfaces),
        packets=structure.packets_scanned,
        truncated=structure.truncated_packets_observed,
        complete="완료" if structure.scan_complete else "일부",
        available=_compact(report.available_checks),
        unavailable=_compact(report.unavailable_checks),
        cautions=_compact(report.cautions),
    )


def format_preflight_detail(
    capture: CaptureInfo,
    structure: CaptureStructure,
    report: CaptureCapabilityReport,
) -> str:
    return _format_preflight(
        capture.capture_format,
        capture.size_bytes,
        capture.sha256[:12],
        structure,
        report,
    )


def _format_inventory(result: CaptureAnalysisResult) -> str:
    run = result.protocol_inventory
    if run is None:
        return ""
    inventory = run.inventory
    observed = [
        "- {0}: {1:,}프레임 · 처음 #{2:,} · 마지막 #{3:,}".format(
            item.label_ko,
            item.frame_count,
            item.first_frame,
            item.last_frame,
        )
        for item in inventory.observations
    ]
    if not observed:
        observed.append("- 승인된 프로토콜 그룹이 관찰되지 않았습니다.")
    expected = (
        "알 수 없음"
        if inventory.expected_frames is None
        else "{0:,}".format(inventory.expected_frames)
    )
    return (
        "\n\n[2. 프로토콜 존재 인벤토리]\n"
        "처리 범위: {state}\n"
        "TShark {version} · 관찰 프레임 {frames:,}개 / 사전 점검 {expected}개 · "
        "잘린 프레임 {truncated:,}개\n"
        "관찰됨:\n{observed}\n"
        "관찰되지 않음: {not_observed}\n"
        "주의: {cautions}\n"
        "프로토콜 관찰 여부만으로 단계 성공·실패를 확정하지 않습니다."
    ).format(
        state="전체" if inventory.complete else "일부 또는 판단 불가",
        version=run.bundle_version,
        frames=inventory.frames_observed,
        expected=expected,
        truncated=inventory.truncated_frames,
        observed="\n".join(observed),
        not_observed=_compact(inventory.not_observed_labels, 8),
        cautions=_compact(inventory.cautions, 6),
    )


def _format_correlation(result: CaptureAnalysisResult) -> str:
    run = result.protocol_inventory
    if run is None or run.event_correlation is None:
        return "\n\n[3. 접속 단계 및 Finding]\n접속 단계 상관분석 결과가 없습니다."
    correlation = run.event_correlation
    state_names = {
        "success": "성공 응답 관찰",
        "failure": "실패 응답 관찰",
        "mixed": "성공·실패 혼합",
        "incomplete": "진행 중 또는 불완전",
        "not_observed": "관찰되지 않음",
        "unavailable": "판단 불가",
    }
    stages = [
        "- [{0}] {1}: {2} · 근거 {3}".format(
            state_names.get(item.state, item.state),
            item.label_ko,
            item.summary_ko,
            _frames(item.evidence_frames),
        )
        for item in correlation.stages
    ]
    findings = []
    for index, finding in enumerate(correlation.findings, start=1):
        checks = " / ".join(
            "{0}) {1}".format(number, value)
            for number, value in enumerate(finding.next_checks, start=1)
        )
        findings.append(
            "{index}. [{classification}] {title}\n"
            "   단계: {stage}\n"
            "   설명: {summary}\n"
            "   근거 프레임: {frames}\n"
            "   Wireshark 필터: {display_filter}\n"
            "   다음 확인: {checks}".format(
                index=index,
                classification=finding.classification,
                title=finding.title_ko,
                stage=finding.stage_id,
                summary=finding.summary_ko,
                frames=_frames(finding.evidence_frames),
                display_filter=finding.display_filter,
                checks=checks,
            )
        )
    if not findings:
        findings.append(
            "명시적인 실패 Finding은 관찰되지 않았습니다. "
            "캡처 누락 가능성이 있으므로 전체 정상으로 확정하지 않습니다."
        )
    return (
        "\n\n[3. 접속 단계 요약]\n{stages}\n"
        "\n[4. 근거 기반 Finding]\n{findings}\n"
        "\n분석 주의: {cautions}"
    ).format(
        stages="\n".join(stages),
        findings="\n\n".join(findings),
        cautions=_compact(correlation.cautions, 8),
    )


def _format_timeline(result: CaptureAnalysisResult, limit: int = 120) -> str:
    run = result.protocol_inventory
    if run is None or run.event_timeline is None:
        return "\n\n[5. 비식별 이벤트 타임라인]\n이벤트 타임라인 결과가 없습니다."
    timeline = run.event_timeline
    state_names = {
        "success-observed": "성공 결과 관찰",
        "failure-observed": "실패 결과 관찰",
        "mixed": "성공·실패 혼재",
        "sequence-observed": "순서 요소 관찰",
        "activity-observed": "관련 트래픽 관찰",
        "not-observed": "관찰되지 않음",
        "unavailable": "판단 불가",
    }
    stages = [
        "- [{0}] {1}: {2} · 근거 {3}".format(
            state_names.get(item.state, item.state),
            item.label_ko,
            item.summary_ko,
            _frames(item.evidence_frames),
        )
        for item in timeline.stages
    ]
    events = []
    for item in timeline.events[:limit]:
        alias = (
            ""
            if item.correlation_alias is None
            else " · 상관 별칭 " + item.correlation_alias
        )
        code = "" if item.code is None else " · 코드 " + str(item.code)
        events.append(
            "- +{0:,}ms · 프레임 #{1:,} · {2}{3}{4}\n"
            "  Wireshark 필터: {5}".format(
                item.relative_time_ms,
                item.frame_number,
                item.label_ko,
                alias,
                code,
                item.evidence_filter,
            )
        )
    if not events:
        events.append("- 승인된 필드에서 표시할 이벤트를 관찰하지 못했습니다.")
    hidden = max(0, timeline.events_total - min(len(timeline.events), limit))
    if hidden:
        events.append(
            "- 반복 이벤트 {0:,}건은 상세 화면에서 생략했습니다.".format(hidden)
        )
    return (
        "\n\n[5. 비식별 이벤트 타임라인]\n"
        "처리 프레임 {frames:,}개 · 전체 이벤트 {total:,}건 · 상세 보관 {retained:,}건\n"
        "단계별 관찰 결과:\n{stages}\n\n"
        "주요 이벤트:\n{events}\n"
        "주의: {cautions}\n"
        "상관 별칭은 원본 거래 ID·스트림 번호가 아닌 캡처 내부 순번입니다."
    ).format(
        frames=timeline.frames_observed,
        total=timeline.events_total,
        retained=timeline.events_retained,
        stages="\n".join(stages),
        events="\n".join(events),
        cautions=_compact(timeline.cautions, 8),
    )


def _format_transactions(result: CaptureAnalysisResult, limit: int = 80) -> str:
    run = result.protocol_inventory
    if run is None or run.transaction_sessions is None:
        return "\n\n[6. 비식별 거래 시도]\n거래 시도 요약 결과가 없습니다."
    report = run.transaction_sessions
    state_names = {
        "complete": "필요 순서 완료 관찰",
        "success-observed": "성공 결과만 관찰",
        "failure-observed": "실패 결과 관찰",
        "mixed": "성공·실패 혼재",
        "incomplete": "최종 결과 미확인",
    }
    attempts = []
    for index, item in enumerate(report.attempts[:limit], start=1):
        checks = " / ".join(
            "{0}) {1}".format(number, value)
            for number, value in enumerate(item.next_checks_ko, start=1)
        )
        attempts.append(
            "{index}. [{state}] {attempt_id} · {label}\n"
            "   설명: {summary}\n"
            "   관찰 이벤트: {observed}\n"
            "   미확인 순서 요소: {missing}\n"
            "   프레임: #{first:,}~#{last:,} · 상대 지속시간 {duration:,}ms · "
            "이벤트 {count:,}건\n"
            "   근거 프레임: {frames}\n"
            "   Wireshark 필터: {display_filter}\n"
            "   다음 확인: {checks}".format(
                index=index,
                state=state_names.get(item.state, item.state),
                attempt_id=item.attempt_id,
                label=item.label_ko,
                summary=item.summary_ko,
                observed=_event_labels(item.observed_event_types),
                missing=_event_labels(item.missing_event_types),
                first=item.first_frame,
                last=item.last_frame,
                duration=item.duration_ms,
                count=item.event_count,
                frames=_frames(item.evidence_frames),
                display_filter=item.display_filter,
                checks=checks,
            )
        )
    if not attempts:
        attempts.append("거래 별칭이 있는 프로토콜 이벤트를 관찰하지 못했습니다.")
    hidden = max(0, len(report.attempts) - limit)
    if hidden:
        attempts.append(
            "거래 시도 {0:,}건은 GUI 상세 표시에서 생략했습니다.".format(hidden)
        )
    return (
        "\n\n[6. 비식별 거래 시도 요약]\n"
        "요약 범위: {complete} · 거래 시도 {total:,}건 · 미할당 이벤트 {unassigned:,}건\n"
        "거래 시도:\n{attempts}\n"
        "주의: {cautions}\n"
        "서로 다른 프로토콜 거래를 동일 단말 접속으로 자동 결합하지 않습니다."
    ).format(
        complete="전체" if report.complete else "일부",
        total=len(report.attempts),
        unassigned=report.unassigned_event_count,
        attempts="\n\n".join(attempts),
        cautions=_compact(report.cautions, 8),
    )


def _format_devices(result: CaptureAnalysisResult, limit: int = 60) -> str:
    run = result.protocol_inventory
    if run is None or run.device_sessions is None:
        return "\n\n[7. 분석 실행별 단말·AP 가명]\n단말 가명화 결과가 없습니다."
    report = run.device_sessions
    devices = []
    for index, item in enumerate(report.devices[:limit], start=1):
        protocols = _compact(item.protocols_observed, 12)
        evidence = _compact(
            tuple(_EVIDENCE_LABELS.get(value, value) for value in item.evidence_types),
            10,
        )
        aps = _compact(item.ap_aliases, 10)
        attempts = _compact(item.linked_attempt_ids, 15)
        devices.append(
            "{index}. {alias}\n"
            "   프레임: #{first:,}~#{last:,} · 상대 지속시간 {duration:,}ms · "
            "할당 프레임 {count:,}개\n"
            "   확인 근거: {evidence}\n"
            "   관찰 프로토콜: {protocols}\n"
            "   관찰 AP 가명: {aps}\n"
            "   연결된 거래 시도: {attempts}\n"
            "   Wireshark 필터: {display_filter}".format(
                index=index,
                alias=item.alias,
                first=item.first_frame,
                last=item.last_frame,
                duration=item.duration_ms,
                count=item.frame_count,
                evidence=evidence,
                protocols=protocols,
                aps=aps,
                attempts=attempts,
                display_filter=_display_filter(item.evidence_frames),
            )
        )
    if not devices:
        devices.append(
            "802.11 관리·EAP·DHCP 클라이언트 근거에서 단말 가명을 만들지 못했습니다."
        )
    hidden = max(0, len(report.devices) - limit)
    if hidden:
        devices.append(
            "단말 가명 {0:,}개는 GUI 상세 표시에서 생략했습니다.".format(hidden)
        )
    links = {
        "linked": "단일 단말 연결",
        "ambiguous": "모호함",
        "unassigned": "미할당",
    }
    link_counts = {key: 0 for key in links}
    for item in report.attempt_links:
        link_counts[item.state] = link_counts.get(item.state, 0) + 1
    link_summary = " · ".join(
        "{0} {1:,}건".format(label, link_counts.get(state, 0))
        for state, label in links.items()
    )
    return (
        "\n\n[7. 분석 실행별 단말·AP 가명]\n"
        "처리 범위: {complete} · 단말 가명 {total:,}개 · "
        "미할당 프레임 {unassigned:,}개 · 모호 프레임 {ambiguous:,}개\n"
        "거래 연결: {link_summary}\n\n"
        "단말 가명:\n{devices}\n"
        "주의: {cautions}\n"
        "개인정보 경계: 원문 주소 직렬화 {raw} · HMAC 키 저장 {secret} · "
        "실행 간 별칭 고정 {stable}\n"
        "중요: DEVICE-N/AP-N은 현재 분석 실행에서만 유효하며 "
        "사용자 신원이나 완전한 접속 세션을 확정하지 않습니다."
    ).format(
        complete="전체 처리" if report.complete else "일부 처리",
        total=len(report.devices),
        unassigned=report.frames_unassigned,
        ambiguous=report.frames_ambiguous,
        link_summary=link_summary,
        devices="\n\n".join(devices),
        cautions=_compact(report.cautions, 8),
        raw="예" if report.raw_identifiers_serialized else "아니오",
        secret="예" if report.alias_secret_persisted else "아니오",
        stable="예" if report.aliases_stable_across_runs else "아니오",
    )


def format_analysis_detail(result: CaptureAnalysisResult) -> str:
    detail = _format_preflight(
        result.capture_format,
        result.size_bytes,
        result.sha256_prefix,
        result.structure,
        result.capabilities,
    )
    if result.inventory_state == "completed":
        return (
            detail
            + _format_inventory(result)
            + _format_correlation(result)
            + _format_timeline(result)
            + _format_transactions(result)
            + _format_devices(result)
        )
    return (
        detail
        + "\n\n[2. 프로토콜·접속 단계·이벤트·거래·단말 가명 분석]\n"
        + ("실행 안 함" if result.inventory_state == "unavailable" else "실패")
        + ": "
        + result.inventory_message
        + "\n사전 점검 결과는 유지되지만 상세 분석 결과는 확정하지 않습니다."
    )


class CaptureViewModel:
    """Tk 루트 없이 테스트 가능한 전체 캡처 분석 상태 모델."""

    def __init__(
        self,
        vendor_root: Optional[Path] = None,
        profile_path: Optional[Path] = None,
    ) -> None:
        package_root = Path(__file__).resolve().parents[1]
        self.vendor_root = (
            Path(__file__).resolve().parents[3] / "vendor" / "wireshark"
            if vendor_root is None
            else vendor_root
        )
        self.profile_path = (
            package_root / "resources" / "tshark" / "field-profiles.v1.json"
            if profile_path is None
            else profile_path
        )
        self.state = CaptureViewState(
            status="파일을 선택해 주세요.",
            detail="PCAP 또는 PCAPNG 파일을 외부 전송 없이 로컬에서만 분석합니다.",
            valid=False,
        )
        self.capture: Optional[CaptureInfo] = None
        self.structure: Optional[CaptureStructure] = None
        self.capabilities: Optional[CaptureCapabilityReport] = None
        self.analysis_result: Optional[CaptureAnalysisResult] = None

    def select_capture(
        self,
        path: str,
        cancel_event: Optional[threading.Event] = None,
    ) -> CaptureViewState:
        try:
            result = analyze_capture(
                path,
                self.vendor_root,
                self.profile_path,
                cancel_event=cancel_event,
            )
        except CaptureAnalysisError as exc:
            self.capture = None
            self.structure = None
            self.capabilities = None
            self.analysis_result = None
            self.state = CaptureViewState(
                "파일을 사용할 수 없습니다.",
                str(exc),
                False,
            )
            return self.state
        except Exception:
            self.capture = None
            self.structure = None
            self.capabilities = None
            self.analysis_result = None
            self.state = CaptureViewState(
                "파일을 사용할 수 없습니다.",
                "파일을 안전하게 분석하지 못했습니다.",
                False,
            )
            return self.state

        self.capture = None
        self.structure = result.structure
        self.capabilities = result.capabilities
        self.analysis_result = result
        if result.inventory_state == "completed":
            status = "캡처·Finding·거래 시도·단말 가명 분석을 완료했습니다."
        elif result.inventory_state == "failed":
            status = "캡처 사전 점검은 완료했지만 상세 분석에 실패했습니다."
        else:
            status = "캡처 사전 점검을 완료했습니다."
        self.state = CaptureViewState(
            status=status,
            detail=format_analysis_detail(result),
            valid=True,
        )
        return self.state


class MainWindow:
    def __init__(self, root: tk.Tk) -> None:
        self._root = root
        self._vendor_root = (
            Path(__file__).resolve().parents[3] / "vendor" / "wireshark"
        )
        self._profile_path = (
            Path(__file__).resolve().parents[1]
            / "resources"
            / "tshark"
            / "field-profiles.v1.json"
        )
        self._view_model = CaptureViewModel(
            self._vendor_root,
            self._profile_path,
        )
        self._status = tk.StringVar(value=self._view_model.state.status)
        bundle_status = inspect_bundle(self._vendor_root)
        self._tshark_status = tk.StringVar(value=bundle_status.message)
        self._portable_status = tk.StringVar(
            value=_portable_status(bundle_status)
        )
        self._selection_generation = 0
        self._validation_cancel = threading.Event()
        self._closed = False
        self._root.protocol("WM_DELETE_WINDOW", self._close)
        self._build()

    def _build(self) -> None:
        self._root.title("WLAN 장애 분석기 KO")
        self._root.minsize(940, 760)

        frame = ttk.Frame(self._root, padding=24)
        frame.pack(fill="both", expand=True)

        ttk.Label(
            frame,
            text="완전 오프라인",
            style="Accent.TLabel",
        ).pack(anchor="w")
        ttk.Label(
            frame,
            text="무선 네트워크 패킷 장애 분석",
            font=("TkDefaultFont", 18, "bold"),
        ).pack(anchor="w", pady=(12, 4))
        ttk.Label(
            frame,
            text=(
                "접속 단계 · 근거 Finding · 거래 시도 · "
                "분석 실행별 DEVICE-N/AP-N"
            ),
        ).pack(anchor="w")

        ttk.Separator(frame).pack(fill="x", pady=16)
        controls = ttk.Frame(frame)
        controls.pack(fill="x")
        self._select_button = ttk.Button(
            controls,
            text="PCAP 또는 PCAPNG 파일 선택",
            command=self._choose_file,
        )
        self._select_button.pack(side="left")
        self._cancel_button = ttk.Button(
            controls,
            text="분석 취소",
            command=self._cancel_analysis,
            state="disabled",
        )
        self._cancel_button.pack(side="left", padx=(8, 0))
        self._progress = ttk.Progressbar(
            controls,
            mode="indeterminate",
            length=180,
        )
        self._progress.pack(side="right")

        ttk.Label(
            frame,
            textvariable=self._status,
            font=("TkDefaultFont", 12, "bold"),
        ).pack(anchor="w", pady=(16, 6))

        result_frame = ttk.Frame(frame)
        result_frame.pack(fill="both", expand=True)
        self._detail_text = tk.Text(
            result_frame,
            wrap="word",
            height=26,
            padx=12,
            pady=10,
            state="disabled",
        )
        result_scroll = ttk.Scrollbar(
            result_frame,
            orient="vertical",
            command=self._detail_text.yview,
        )
        self._detail_text.configure(yscrollcommand=result_scroll.set)
        self._detail_text.pack(side="left", fill="both", expand=True)
        result_scroll.pack(side="right", fill="y")
        self._set_detail(self._view_model.state.detail)

        ttk.Separator(frame).pack(fill="x", pady=16)
        ttk.Label(
            frame,
            text="AI·외부 API·실시간 캡처·장비 접속을 사용하지 않습니다.",
        ).pack(anchor="w")
        ttk.Label(
            frame,
            textvariable=self._tshark_status,
        ).pack(anchor="w", pady=(5, 0))
        ttk.Label(
            frame,
            textvariable=self._portable_status,
            wraplength=880,
        ).pack(anchor="w", pady=(3, 0))
        ttk.Label(
            frame,
            text=(
                "원문 L2 주소와 가명화 키는 결과·로그·파일에 저장하지 않습니다. "
                "DEVICE-N/AP-N은 실행할 때마다 새로 만들어집니다."
            ),
            wraplength=880,
        ).pack(anchor="w", pady=(3, 0))
        ttk.Button(
            frame,
            text="종료",
            command=self._close,
        ).pack(anchor="e", pady=(12, 0))

    def _set_detail(self, value: str) -> None:
        self._detail_text.configure(state="normal")
        self._detail_text.delete("1.0", "end")
        self._detail_text.insert("1.0", value)
        self._detail_text.configure(state="disabled")
        self._detail_text.yview_moveto(0.0)

    def _set_busy(self, busy: bool) -> None:
        self._select_button.configure(
            state="disabled" if busy else "normal"
        )
        self._cancel_button.configure(
            state="normal" if busy else "disabled"
        )
        if busy:
            self._progress.start(12)
        else:
            self._progress.stop()

    def _choose_file(self) -> None:
        selected = filedialog.askopenfilename(
            title="로컬 패킷 캡처 선택",
            filetypes=(
                ("패킷 캡처", "*.pcap *.pcapng"),
                ("모든 파일", "*.*"),
            ),
        )
        if not selected:
            return

        self._selection_generation += 1
        generation = self._selection_generation
        self._validation_cancel.set()
        cancel_event = threading.Event()
        self._validation_cancel = cancel_event
        self._status.set(
            "캡처 구조·접속 단계·거래 시도·단말 가명을 분석하고 있습니다."
        )
        self._set_detail(
            "파일명과 패킷 원문은 화면과 로그에 표시하지 않습니다. "
            "단말 가명은 현재 실행에서만 유효하며 분석 취소가 가능합니다."
        )
        self._set_busy(True)

        def analyze_in_background() -> None:
            worker_view_model = CaptureViewModel(
                self._vendor_root,
                self._profile_path,
            )
            state = worker_view_model.select_capture(
                selected,
                cancel_event=cancel_event,
            )

            def apply_result() -> None:
                if (
                    generation != self._selection_generation
                    or self._closed
                ):
                    return
                self._view_model = worker_view_model
                self._status.set(state.status)
                self._set_detail(state.detail)
                self._set_busy(False)

            if generation != self._selection_generation or self._closed:
                return
            try:
                self._root.after(0, apply_result)
            except (RuntimeError, tk.TclError):
                return

        threading.Thread(
            target=analyze_in_background,
            daemon=True,
        ).start()

    def _cancel_analysis(self) -> None:
        self._validation_cancel.set()
        self._status.set("분석 취소를 요청했습니다.")
        self._cancel_button.configure(state="disabled")

    def _close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._selection_generation += 1
        self._validation_cancel.set()
        self._root.destroy()


def launch() -> None:
    root = tk.Tk()
    style = ttk.Style(root)
    style.configure("Accent.TLabel", foreground="#146c43")
    MainWindow(root)
    root.mainloop()
