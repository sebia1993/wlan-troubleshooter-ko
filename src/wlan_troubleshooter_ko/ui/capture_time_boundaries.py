"""Korean formatter for relative capture time and transaction boundaries."""

from __future__ import annotations

from typing import Iterable, Optional, Sequence


_BOUNDARY_LABELS = {
    "timestamp-order-risk": "타임스탬프 순서 위험 — 경계 위치 미확정",
    "spans-analysis-window": "첫·마지막 분석 프레임에 걸침",
    "at-analysis-start": "첫 분석 프레임에서 시작",
    "at-analysis-end": "마지막 분석 프레임에서 끝남",
    "near-both-boundaries": "시작·종료 경계 모두 가까움",
    "near-analysis-start": "분석 시작 경계와 가까움",
    "near-analysis-end": "분석 종료 경계와 가까움",
    "analysis-window-interior": "분석 상대 시간 내부",
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


def _milliseconds(value: Optional[int]) -> str:
    if value is None:
        return "확인 불가"
    prefix = "+" if value > 0 else ""
    return "{0}{1:,}ms".format(prefix, value)


def _frame(value: Optional[int]) -> str:
    return "없음" if value is None else "#{0:,}".format(value)


def _frames(values: Iterable[int]) -> str:
    items = tuple(values)
    if not items:
        return "없음"
    return ", ".join("#{0:,}".format(value) for value in items)


def _compact(values: Sequence[str], limit: int = 8) -> str:
    items = tuple(values)
    if not items:
        return "없음"
    visible = list(items[:limit])
    if len(items) > limit:
        visible.append("외 {0}개".format(len(items) - limit))
    return " · ".join(visible)


def format_capture_time_boundaries(result: object, limit: int = 100) -> str:
    report = getattr(result, "capture_time_boundaries", None)
    if report is None:
        return (
            "\n\n[13. 캡처 상대 시간과 거래 경계]\n"
            "내장 TShark 상대 시간 결과가 없습니다. 절대 시각, 캡처 구간 포함 여부, "
            "응답 대기 충분성과 실제 미응답을 추정하지 않습니다."
        )

    boundaries = []
    for index, item in enumerate(report.transaction_boundaries[:limit], start=1):
        boundaries.append(
            "{index}. [{boundary}] {attempt} · {protocol} · 거래 상태 {state}\n"
            "   근거 프레임: #{first:,}~#{last:,}\n"
            "   분석 시작에서 첫 프레임까지: {start}\n"
            "   마지막 거래 프레임 뒤 관찰 시간: {end}\n"
            "   거래 프레임의 관찰 지속시간: {duration}\n"
            "   시작 경계와 가까움: {near_start} · 종료 경계와 가까움: {near_end}\n"
            "   응답 대기 충분성 평가: {wait} · 실제 응답 부재 확정: {absence}\n"
            "   근본 원인 확정: {root}\n"
            "   Wireshark 필터: {display_filter}".format(
                index=index,
                boundary=_BOUNDARY_LABELS.get(
                    item.boundary_state,
                    item.boundary_state,
                ),
                attempt=item.attempt_id,
                protocol=_PROTOCOL_LABELS.get(item.protocol, item.protocol),
                state=item.attempt_state,
                first=item.first_frame,
                last=item.last_frame,
                start=_milliseconds(item.start_distance_ms),
                end=_milliseconds(item.end_observation_window_ms),
                duration=_milliseconds(item.observed_attempt_duration_ms),
                near_start=_yes_no(item.start_near_boundary),
                near_end=_yes_no(item.end_near_boundary),
                wait=_yes_no(item.response_wait_sufficiency_assessed),
                absence=_yes_no(item.response_absence_confirmed),
                root=_yes_no(item.root_cause_confirmed),
                display_filter=item.display_filter,
            )
        )

    if not boundaries:
        boundaries.append("- 표시할 EAP·RADIUS·DHCP·DNS·TCP 거래 시도가 없습니다.")
    hidden = max(0, len(report.transaction_boundaries) - limit)
    if hidden:
        boundaries.append(
            "- 거래 경계 {0:,}건은 GUI 상세 표시에서 생략했습니다.".format(
                hidden
            )
        )

    return (
        "\n\n[13. 캡처 상대 시간과 거래 경계]\n"
        "상태: {complete} · 상대 시간 프로파일 {profile}\n"
        "분석 프레임: {observed:,}/{expected} · 첫 프레임 {first} · 마지막 프레임 {last}\n"
        "첫→마지막 상대 시간: {file_order}\n"
        "관찰 최소 상대 시간: {minimum} · 최대 상대 시간: {maximum} · 전체 span: {span}\n"
        "타임스탬프 역행: {regressions:,}회 · 근거 {regression_frames}"
        "{regression_omitted}\n"
        "거래 경계 표시 기준: {threshold:,}ms · 거래 시도 {attempts:,}개 · "
        "거래 입력 완전성: {transaction_complete}\n\n"
        "거래별 상대 경계:\n{boundaries}\n"
        "주의: {cautions}\n"
        "보호 경계: 절대 시각 출력 {absolute} · 캡처 시작 증명 {start} · "
        "캡처 종료 증명 {end} · 장애 구간 전체 포함 증명 {incident} · "
        "응답 대기 충분성 평가 {wait} · 실제 응답 부재 확정 {absence} · "
        "캡처 무손실 증명 {loss} · 근본 원인 확정 {root}\n"
        "중요: 마지막 거래 프레임 뒤에 시간이 많이 남아도 프로토콜별 응답 대기 "
        "시간이 충분했다거나 서버·방화벽·ClearPass가 실제로 응답하지 않았다고 "
        "확정하지 않습니다."
    ).format(
        complete="완료" if report.complete else "부분 분석",
        profile=report.profile_version,
        observed=report.frames_observed,
        expected=(
            "확정 불가"
            if report.expected_frames is None
            else "{0:,}".format(report.expected_frames)
        ),
        first=_frame(report.first_frame),
        last=_frame(report.last_frame),
        file_order=_milliseconds(report.first_to_last_relative_ms),
        minimum=_milliseconds(report.minimum_relative_ms),
        maximum=_milliseconds(report.maximum_relative_ms),
        span=_milliseconds(report.observed_span_ms),
        regressions=report.timestamp_regressions,
        regression_frames=_frames(report.regression_evidence_frames),
        regression_omitted=(
            " · 생략 {0:,}개".format(
                report.regression_evidence_frames_omitted
            )
            if report.regression_evidence_frames_omitted
            else ""
        ),
        threshold=report.boundary_threshold_ms,
        attempts=report.transaction_attempts_total,
        transaction_complete=_yes_no(report.transaction_source_complete),
        boundaries="\n\n".join(boundaries),
        cautions=_compact(report.cautions, 10),
        absolute=_yes_no(report.absolute_timestamps_serialized),
        start=_yes_no(report.capture_start_proven),
        end=_yes_no(report.capture_end_proven),
        incident=_yes_no(report.incident_window_fully_covered),
        wait=_yes_no(report.response_wait_sufficiency_assessed),
        absence=_yes_no(report.response_absence_confirmed),
        loss=_yes_no(report.capture_loss_excluded),
        root=_yes_no(report.root_cause_confirmed),
    )


def install(main_window_module: object) -> None:
    """Idempotently append relative-time boundaries to the main formatter."""

    if getattr(main_window_module, "_CAPTURE_TIME_BOUNDARIES_INSTALLED", False):
        return
    original = main_window_module.format_analysis_detail

    def format_analysis_detail(result: object) -> str:
        return original(result) + format_capture_time_boundaries(result)

    main_window_module.format_analysis_detail = format_analysis_detail
    main_window_module._CAPTURE_TIME_BOUNDARIES_INSTALLED = True
