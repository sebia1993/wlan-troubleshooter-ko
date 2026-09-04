"""Identifier-free Korean formatter for EAPOL-Key observations."""

from __future__ import annotations

from typing import Iterable, Sequence


_STATE_LABELS = {
    "sequence-observed": "M1→M2→M3→M4 순서 관찰",
    "message-repetition-observed": "메시지 번호 반복 관찰",
    "out-of-order": "메시지 번호 역순 관찰",
    "incomplete": "메시지 일부 관찰",
}


def _yes_no(value: bool) -> str:
    return "예" if value else "아니오"


def _numbers(values: Iterable[int]) -> str:
    items = tuple(values)
    if not items:
        return "없음"
    return " → ".join("M" + str(value) for value in items)


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


def format_eapol_handshakes(result: object, limit: int = 60) -> str:
    report = getattr(result, "eapol_handshakes", None)
    if report is None:
        return (
            "\n\n[10. EAPOL 4-Way Handshake 메시지 순서]\n"
            "상세 TShark 분석이 실행되지 않아 EAPOL-Key 관찰 결과가 없습니다."
        )

    lines = []
    for index, item in enumerate(report.observations[:limit], start=1):
        lines.append(
            "{index}. [{state}] {observation} · {device} ↔ {ap}\n"
            "   설명: {summary}\n"
            "   관찰 메시지: {messages}\n"
            "   첫 관찰 순서: {first_order}\n"
            "   미관찰 메시지: {missing}\n"
            "   반복 메시지 번호: {repeated}\n"
            "   Retry 비트 관찰 프레임: {retry_frames}\n"
            "   프레임: #{first:,}~#{last:,} · 상대 지속시간 {duration:,}ms\n"
            "   근거 프레임: {frames}\n"
            "   Wireshark 필터: {display_filter}".format(
                index=index,
                state=_STATE_LABELS.get(item.state, item.state),
                observation=item.observation_id,
                device=item.device_alias,
                ap=item.ap_alias,
                summary=item.summary_ko,
                messages=_numbers(item.observed_message_numbers),
                first_order=_numbers(item.first_observed_order),
                missing=_numbers(item.missing_message_numbers),
                repeated=_numbers(item.repeated_message_numbers),
                retry_frames=_frames(item.retry_flag_frames),
                first=item.first_frame,
                last=item.last_frame,
                duration=item.duration_ms,
                frames=_frames(item.evidence_frames),
                display_filter=item.display_filter or "없음",
            )
        )
    if not lines:
        if report.field_available:
            lines.append("- EAPOL-Key 메시지 1~4 이벤트를 관찰하지 못했습니다.")
        else:
            lines.append("- 내장 TShark에서 EAPOL-Key 메시지 번호 필드를 사용할 수 없습니다.")
    hidden = max(0, len(report.observations) - limit)
    if hidden:
        lines.append(
            "- EAPOL 관찰 {0:,}건은 GUI 상세 표시에서 생략했습니다.".format(
                hidden
            )
        )

    return (
        "\n\n[10. EAPOL 4-Way Handshake 메시지 순서]\n"
        "메시지 번호 필드 사용 가능: {field}\n"
        "처리 범위: {complete} · Key 이벤트 {source:,}건 · 연결 {linked:,}건 · "
        "미할당 {unassigned:,}건 · 모호 {ambiguous:,}건\n"
        "타임라인 전체 처리: {timeline} · 단말 보고서 전체 처리: {device} · "
        "단말 근거 전체 보관: {evidence}\n\n"
        "관찰 결과:\n{observations}\n"
        "주의: {cautions}\n"
        "확정 경계: Replay Counter 관계 사용 {replay} · 키 원문 직렬화 {raw_key} · "
        "원본 식별자 직렬화 {raw_id} · 동일 Handshake 확정 {same} · "
        "키 설치 확정 {install} · 암호학적 성공 확정 {crypto} · 근본 원인 확정 {root}\n"
        "중요: M1~M4 번호가 모두 보이더라도 동일한 한 번의 Handshake, 키 설치, "
        "암호학적 성공 또는 전체 무선 접속 성공을 뜻하지 않습니다."
    ).format(
        field=_yes_no(report.field_available),
        complete="전체" if report.complete else "일부 또는 판단 불가",
        source=report.source_key_events_total,
        linked=report.linked_key_events,
        unassigned=report.unassigned_key_events,
        ambiguous=report.ambiguous_key_events,
        timeline=_yes_no(report.source_timeline_complete),
        device=_yes_no(report.device_report_complete),
        evidence=_yes_no(report.device_evidence_complete),
        observations="\n\n".join(lines),
        cautions=_compact(report.cautions, 10),
        replay=_yes_no(report.replay_counter_correlation_available),
        raw_key=_yes_no(report.raw_key_material_serialized),
        raw_id=_yes_no(report.raw_identifiers_serialized),
        same=_yes_no(report.same_handshake_confirmed),
        install=_yes_no(report.key_installation_confirmed),
        crypto=_yes_no(report.cryptographic_success_confirmed),
        root=_yes_no(report.root_cause_confirmed),
    )


def install(main_window_module: object) -> None:
    """Idempotently append the EAPOL formatter to the main result text."""

    if getattr(main_window_module, "_EAPOL_HANDSHAKE_FORMAT_INSTALLED", False):
        return
    original = main_window_module.format_analysis_detail

    def format_analysis_detail(result: object) -> str:
        return original(result) + format_eapol_handshakes(result)

    main_window_module.format_analysis_detail = format_analysis_detail
    main_window_module._EAPOL_HANDSHAKE_FORMAT_INSTALLED = True
