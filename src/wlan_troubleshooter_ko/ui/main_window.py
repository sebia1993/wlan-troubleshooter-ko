"""캡처 구조, Finding, 타임라인과 비식별 거래 시도를 보여 주는 GUI."""

from __future__ import annotations

import threading
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Iterable, Optional, Tuple

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


def _compact(items: Tuple[str, ...], limit: int = 5) -> str:
    if not items:
        return "없음"
    visible = list(items[:limit])
    if len(items) > limit:
        visible.append("외 {0}개".format(len(items) - limit))
    return " · ".join(visible)


def _frames(values: Iterable[int]) -> str:
    items = tuple(values)
    if not items:
        return "없음"
    return ", ".join("#{0:,}".format(value) for value in items)


def _event_labels(values: Iterable[str]) -> str:
    items = tuple(values)
    if not items:
        return "없음"
    return " → ".join(_EVENT_LABELS.get(value, value) for value in items)


def _portable_status(bundle_status: BundleStatus) -> str:
    resources = Path(__file__).resolve().parents[1] / "resources"
    try:
        registry = load_field_profiles(resources / "tshark" / "field-profiles.v1.json")
        profile = registry.get_profile("connection-events")
    except FieldProfileError:
        return "접속 단계 프로파일 오류 · 배포본을 다시 받아야 합니다."
    base = "필드 프로파일 {0} · 접속 필드 {1}개 · 프로토콜 그룹 {2}개".format(
        registry.profile_version,
        len(profile.fields),
        len(registry.protocol_groups),
    )
    if bundle_status.code == "integrity_verified":
        return base + " · 내장 TShark 무결성 확인됨 · 거래 시도 요약 사용 가능"
    return base + " · 소스 실행 모드 · Portable 배포본에서는 내장 TShark가 사용됩니다."


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
    """기존 호출자와 테스트를 위한 사전 점검 문장 호환 함수."""

    return _format_preflight(
        capture.capture_format,
        capture.size_bytes,
        capture.sha256[:12],
        structure,
        report,
    )


def _format_observations(result: CaptureAnalysisResult) -> str:
    run = result.protocol_inventory
    if run is None:
        return ""
    inventory = run.inventory
    observed = []
    for item in inventory.observations:
        observed.append(
            "- {label}: {count:,}프레임 · 처음 #{first:,} · 마지막 #{last:,}".format(
                label=item.label_ko,
                count=item.frame_count,
                first=item.first_frame,
                last=item.last_frame,
            )
        )
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
        "프로토콜이 보였다는 사실은 성공을 뜻하지 않고, 보이지 않았다는 사실도 장애 증거가 아닙니다."
    ).format(
        state="전체" if inventory.complete else "일부 또는 판단 불가",
        version=run.bundle_version,
        frames=inventory.frames_observed,
        expected=expected,
        truncated=inventory.truncated_frames,
        observed="\n".join(observed),
        not_observed=_compact(inventory.not_observed_labels, limit=8),
        cautions=_compact(inventory.cautions, limit=6),
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
    stage_lines = []
    for stage in correlation.stages:
        stage_lines.append(
            "- [{state}] {label}: {summary} · 근거 {frames}".format(
                state=state_names.get(stage.state, stage.state),
                label=stage.label_ko,
                summary=stage.summary_ko,
                frames=_frames(stage.evidence_frames),
            )
        )

    finding_lines = []
    for index, finding in enumerate(correlation.findings, start=1):
        checks = " / ".join(
            "{0}) {1}".format(number, value)
            for number, value in enumerate(finding.next_checks, start=1)
        )
        finding_lines.append(
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
    if not finding_lines:
        finding_lines.append(
            "명시적인 실패 응답 Finding은 관찰되지 않았습니다. "
            "캡처 누락 가능성이 있으므로 전체 정상으로 확정하지 않습니다."
        )

    return (
        "\n\n[3. 접속 단계 요약]\n{stages}\n"
        "\n[4. 근거 기반 Finding]\n{findings}\n"
        "\n분석 주의: {cautions}"
    ).format(
        stages="\n".join(stage_lines),
        findings="\n\n".join(finding_lines),
        cautions=_compact(correlation.cautions, limit=8),
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
    stage_lines = []
    for stage in timeline.stages:
        stage_lines.append(
            "- [{state}] {label}: {summary} · 근거 {frames}".format(
                state=state_names.get(stage.state, stage.state),
                label=stage.label_ko,
                summary=stage.summary_ko,
                frames=_frames(stage.evidence_frames),
            )
        )

    visible = timeline.events[:limit]
    event_lines = []
    for item in visible:
        alias = "" if item.correlation_alias is None else " · 상관 별칭 " + item.correlation_alias
        code = "" if item.code is None else " · 코드 " + str(item.code)
        event_lines.append(
            "- +{time:,}ms · 프레임 #{frame:,} · {label}{alias}{code}\n"
            "  Wireshark 필터: {display_filter}".format(
                time=item.relative_time_ms,
                frame=item.frame_number,
                label=item.label_ko,
                alias=alias,
                code=code,
                display_filter=item.evidence_filter,
            )
        )
    if not event_lines:
        event_lines.append("- 승인된 이벤트 필드에서 표시할 이벤트를 관찰하지 못했습니다.")
    hidden = max(0, timeline.events_total - len(visible))
    if hidden:
        event_lines.append(
            "- 반복 이벤트 {0:,}건은 상세 화면에서 생략했으며 유형별 집계에는 포함했습니다.".format(
                hidden
            )
        )

    return (
        "\n\n[5. 비식별 이벤트 타임라인]\n"
        "처리 프레임 {frames:,}개 · 전체 이벤트 {total:,}건 · 상세 보관 {retained:,}건\n"
        "단계별 관찰 결과:\n{stages}\n\n"
        "주요 이벤트:\n{events}\n"
        "주의: {cautions}\n"
        "상관 별칭은 캡처 내부 순번이며 원본 거래 ID·스트림 번호를 표시하지 않습니다."
    ).format(
        frames=timeline.frames_observed,
        total=timeline.events_total,
        retained=timeline.events_retained,
        stages="\n".join(stage_lines),
        events="\n".join(event_lines),
        cautions=_compact(timeline.cautions, limit=8),
    )


def _format_transaction_sessions(
    result: CaptureAnalysisResult,
    limit: int = 80,
) -> str:
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
    lines = []
    for index, attempt in enumerate(report.attempts[:limit], start=1):
        checks = " / ".join(
            "{0}) {1}".format(number, value)
            for number, value in enumerate(attempt.next_checks_ko, start=1)
        )
        lines.append(
            "{index}. [{state}] {attempt_id} · {label}\n"
            "   설명: {summary}\n"
            "   관찰 이벤트: {observed}\n"
            "   미확인 순서 요소: {missing}\n"
            "   프레임: #{first:,}~#{last:,} · 상대 지속시간 {duration:,}ms · 이벤트 {count:,}건\n"
            "   근거 프레임: {frames}\n"
            "   Wireshark 필터: {display_filter}\n"
            "   다음 확인: {checks}".format(
                index=index,
                state=state_names.get(attempt.state, attempt.state),
                attempt_id=attempt.attempt_id,
                label=attempt.label_ko,
                summary=attempt.summary_ko,
                observed=_event_labels(attempt.observed_event_types),
                missing=_event_labels(attempt.missing_event_types),
                first=attempt.first_frame,
                last=attempt.last_frame,
                duration=attempt.duration_ms,
                count=attempt.event_count,
                frames=_frames(attempt.evidence_frames),
                display_filter=attempt.display_filter,
                checks=checks,
            )
        )
    if not lines:
        lines.append(
            "거래 별칭이 있는 EAP·RADIUS·DHCP·DNS·TCP 이벤트를 관찰하지 못했습니다."
        )
    hidden = max(0, len(report.attempts) - limit)
    if hidden:
        lines.append("거래 시도 {0:,}건은 GUI 상세 표시에서 생략했습니다.".format(hidden))

    protocol_counts = " · ".join(
        "{0} {1:,}건".format(protocol.upper(), count)
        for protocol, count in report.attempts_by_protocol
    ) or "없음"
    state_counts = " · ".join(
        "{0} {1:,}건".format(state_names.get(state, state), count)
        for state, count in report.attempts_by_state
    ) or "없음"
    return (
        "\n\n[6. 비식별 거래 시도 요약]\n"
        "요약 범위: {complete} · 거래 시도 {total:,}건 · 거래 미할당 이벤트 {unassigned:,}건\n"
        "프로토콜별: {protocol_counts}\n"
        "상태별: {state_counts}\n\n"
        "거래 시도:\n{attempts}\n"
        "주의: {cautions}\n"
        "중요: 서로 다른 프로토콜 별칭을 동일 단말의 한 접속으로 자동 결합하지 않습니다."
    ).format(
        complete="전체" if report.complete else "일부",
        total=len(report.attempts),
        unassigned=report.unassigned_event_count,
        protocol_counts=protocol_counts,
        state_counts=state_counts,
        attempts="\n\n".join(lines),
        cautions=_compact(report.cautions, limit=8),
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
            + _format_observations(result)
            + _format_correlation(result)
            + _format_timeline(result)
            + _format_transaction_sessions(result)
        )
    return (
        detail
        + "\n\n[2. 프로토콜·접속 단계·이벤트·거래 시도 분석]\n"
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
            self.state = CaptureViewState("파일을 사용할 수 없습니다.", str(exc), False)
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
            status = "캡처·Finding·이벤트 타임라인·거래 시도 분석을 완료했습니다."
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
        self._vendor_root = Path(__file__).resolve().parents[3] / "vendor" / "wireshark"
        self._profile_path = (
            Path(__file__).resolve().parents[1]
            / "resources"
            / "tshark"
            / "field-profiles.v1.json"
        )
        self._view_model = CaptureViewModel(self._vendor_root, self._profile_path)
        self._status = tk.StringVar(value=self._view_model.state.status)
        bundle_status = inspect_bundle(self._vendor_root)
        self._tshark_status = tk.StringVar(value=bundle_status.message)
        self._portable_status = tk.StringVar(value=_portable_status(bundle_status))
        self._selection_generation = 0
        self._validation_cancel = threading.Event()
        self._closed = False
        self._root.protocol("WM_DELETE_WINDOW", self._close)
        self._build()

    def _build(self) -> None:
        self._root.title("WLAN 장애 분석기 KO")
        self._root.minsize(920, 740)

        frame = ttk.Frame(self._root, padding=24)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="완전 오프라인", style="Accent.TLabel").pack(anchor="w")
        ttk.Label(
            frame,
            text="무선 네트워크 패킷 장애 분석",
            font=("TkDefaultFont", 18, "bold"),
        ).pack(anchor="w", pady=(12, 4))
        ttk.Label(
            frame,
            text="접속 단계 · 근거 Finding · 이벤트 타임라인 · 비식별 거래 시도",
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
        self._progress = ttk.Progressbar(controls, mode="indeterminate", length=180)
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
            height=25,
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
        ttk.Label(frame, textvariable=self._tshark_status).pack(anchor="w", pady=(5, 0))
        ttk.Label(
            frame,
            textvariable=self._portable_status,
            wraplength=860,
        ).pack(anchor="w", pady=(3, 0))
        ttk.Label(
            frame,
            text=(
                "거래 완료·실패는 패킷 이벤트 관찰 결과이며 근본 원인 확정을 뜻하지 않습니다. "
                "서로 다른 프로토콜 거래를 동일 단말 접속으로 자동 결합하지 않습니다."
            ),
            wraplength=860,
        ).pack(anchor="w", pady=(3, 0))
        ttk.Button(frame, text="종료", command=self._close).pack(anchor="e", pady=(12, 0))

    def _set_detail(self, value: str) -> None:
        self._detail_text.configure(state="normal")
        self._detail_text.delete("1.0", "end")
        self._detail_text.insert("1.0", value)
        self._detail_text.configure(state="disabled")
        self._detail_text.yview_moveto(0.0)

    def _set_busy(self, busy: bool) -> None:
        self._select_button.configure(state="disabled" if busy else "normal")
        self._cancel_button.configure(state="normal" if busy else "disabled")
        if busy:
            self._progress.start(12)
        else:
            self._progress.stop()

    def _choose_file(self) -> None:
        selected = filedialog.askopenfilename(
            title="로컬 패킷 캡처 선택",
            filetypes=(("패킷 캡처", "*.pcap *.pcapng"), ("모든 파일", "*.*")),
        )
        if not selected:
            return

        self._selection_generation += 1
        generation = self._selection_generation
        self._validation_cancel.set()
        cancel_event = threading.Event()
        self._validation_cancel = cancel_event
        self._status.set("캡처 구조·접속 단계·이벤트·거래 시도를 분석하고 있습니다.")
        self._set_detail(
            "파일명과 패킷 원문은 화면과 로그에 표시하지 않습니다. "
            "큰 캡처는 시간이 걸릴 수 있으며 언제든 분석 취소를 누를 수 있습니다."
        )
        self._set_busy(True)

        def analyze_in_background() -> None:
            worker_view_model = CaptureViewModel(self._vendor_root, self._profile_path)
            state = worker_view_model.select_capture(selected, cancel_event=cancel_event)

            def apply_result() -> None:
                if generation != self._selection_generation or self._closed:
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

        threading.Thread(target=analyze_in_background, daemon=True).start()

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
