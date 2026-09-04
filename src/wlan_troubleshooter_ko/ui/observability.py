"""Install the Phase 4G capture-observability formatter into the Tkinter UI.

The extension is kept separate from the large Phase 4F window module so the
existing GUI behavior remains stable. Only identifier-free observability
results are rendered.
"""

from __future__ import annotations

from typing import Iterable, Sequence


_ASSESSMENT_LABELS = {
    "response-not-observed": "응답 미관찰",
    "capture-boundary-risk": "캡처 경계 위험",
    "packet-truncation-risk": "잘림 영향 가능",
    "insufficient-analysis-input": "분석 입력 불완전",
}

_RISK_LABELS = {
    "analysis-input-incomplete": "분석 입력 일부",
    "packet-truncation-observed": "잘린 패킷 관찰",
    "event-detail-omitted": "상세 이벤트 생략",
    "attempt-evidence-omitted": "거래 근거 생략",
    "capture-start-boundary-risk": "캡처 시작 경계",
    "capture-end-boundary-risk": "캡처 종료 경계",
}

_PROTOCOL_LABELS = {
    "eap": "EAP",
    "radius": "RADIUS",
    "dhcp": "DHCP",
    "dns": "DNS",
    "tcp": "TCP",
}


def _yes_no(value: bool) -> str:
    return "예" if value else "아니오"


def _compact(values: Sequence[str], limit: int = 8) -> str:
    items = tuple(values)
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


def format_observability(result: object, limit: int = 80) -> str:
    """Render a Korean, identifier-free observability section."""

    report = getattr(result, "capture_observability", None)
    if report is None:
        return (
            "\n\n[9. 캡처 관찰 가능성과 미응답 해석]\n"
            "상세 TShark 분석이 실행되지 않아 관찰 가능성 결과가 없습니다.\n"
            "응답이 보이지 않는다는 사실만으로 장애를 확정하지 않습니다."
        )

    visibility_lines = []
    for item in report.protocol_visibility:
        visibility_lines.append(
            "- {protocol}: 요청 계열 {request} · 응답 계열 {reply} · "
            "양쪽 이벤트 계열 관찰 {both} · 양방향 수집 증명 {direction}".format(
                protocol=_PROTOCOL_LABELS.get(item.protocol, item.protocol),
                request=_yes_no(item.request_event_observed),
                reply=_yes_no(item.reply_event_observed),
                both=_yes_no(item.bidirectional_event_classes_observed),
                direction=_yes_no(item.directionality_proven),
            )
        )
    if not visibility_lines:
        visibility_lines.append("- 표시할 프로토콜 관찰 범위가 없습니다.")

    attempt_lines = []
    for index, item in enumerate(report.incomplete_attempts[:limit], start=1):
        risk_labels = tuple(
            _RISK_LABELS.get(value, value) for value in item.risk_flags
        )
        attempt_lines.append(
            "{index}. [{assessment}] {attempt_id} · {protocol}\n"
            "   설명: {summary}\n"
            "   프레임: #{first:,}~#{last:,} · 근거 {frames}\n"
            "   요청 계열 관찰: {request} · 응답 계열 관찰: {reply}\n"
            "   위험 요소: {risks}\n"
            "   응답 부재를 장애로 확정: {failure}\n"
            "   Wireshark 필터: {display_filter}".format(
                index=index,
                assessment=_ASSESSMENT_LABELS.get(
                    item.assessment,
                    item.assessment,
                ),
                attempt_id=item.attempt_id,
                protocol=_PROTOCOL_LABELS.get(item.protocol, item.protocol),
                summary=item.summary_ko,
                first=item.first_frame,
                last=item.last_frame,
                frames=_frames(item.evidence_frames),
                request=_yes_no(item.request_event_observed),
                reply=_yes_no(item.reply_event_observed),
                risks=_compact(risk_labels),
                failure=_yes_no(item.absence_is_failure),
                display_filter=item.display_filter or "없음",
            )
        )
    if not attempt_lines:
        attempt_lines.append(
            "- 최종 결과 미확인 상태로 분류된 거래 시도가 없습니다."
        )
    hidden = max(0, len(report.incomplete_attempts) - limit)
    if hidden:
        attempt_lines.append(
            "- 미완료 거래 {0:,}건은 GUI 상세 표시에서 생략했습니다.".format(
                hidden
            )
        )

    return (
        "\n\n[9. 캡처 관찰 가능성과 미응답 해석]\n"
        "분석 입력 완전성: {input_complete}\n"
        "구조 점검 전체 처리: {container} · 이벤트 타임라인 전체 처리: {timeline} · "
        "거래 보고서 전체 처리: {transactions}\n"
        "점검 패킷 {packets:,}개 · 이벤트 분석 프레임 {frames:,}개 · "
        "잘린 패킷 {truncated:,}개 · 상세 이벤트 생략 {omitted:,}건\n"
        "캡처 시작 시점 증명: {start} · 캡처 종료 시점 증명: {end}\n"
        "캡처 손실 배제: {loss} · 양방향 수집 증명: {direction}\n"
        "응답 미관찰만으로 실패 확정 가능: {absence}\n\n"
        "프로토콜별 관찰 범위:\n{visibility}\n\n"
        "최종 결과 미확인 거래:\n{attempts}\n"
        "주의: {cautions}\n"
        "중요: 파일을 끝까지 읽었더라도 장애 전부터 캡처했는지, 장애 이후까지 "
        "캡처했는지, 패킷 손실이 없었는지와 양방향을 모두 봤는지는 증명되지 "
        "않습니다. 응답 미관찰만으로 서버·방화벽·ClearPass·DHCP·DNS 장애를 "
        "확정하지 않습니다."
    ).format(
        input_complete=_yes_no(report.analysis_input_complete),
        container=_yes_no(report.container_scan_complete),
        timeline=_yes_no(report.event_timeline_complete),
        transactions=_yes_no(report.transaction_report_complete),
        packets=report.packets_scanned,
        frames=report.frames_observed,
        truncated=report.truncated_packets_observed,
        omitted=report.event_details_omitted,
        start=_yes_no(report.capture_start_proven),
        end=_yes_no(report.capture_end_proven),
        loss=_yes_no(report.capture_loss_excluded),
        direction=_yes_no(report.directionality_proven),
        absence=_yes_no(report.absence_can_confirm_failure),
        visibility="\n".join(visibility_lines),
        attempts="\n\n".join(attempt_lines),
        cautions=_compact(report.cautions, 10),
    )


def install(main_window_module: object) -> None:
    """Idempotently extend ``main_window.format_analysis_detail``."""

    if getattr(main_window_module, "_OBSERVABILITY_FORMAT_INSTALLED", False):
        return
    original = main_window_module.format_analysis_detail

    def format_analysis_detail(result: object) -> str:
        return original(result) + format_observability(result)

    main_window_module.format_analysis_detail = format_analysis_detail
    main_window_module._OBSERVABILITY_FORMAT_INSTALLED = True
