"""Render EAPOL Replay Counter relationships without exposing values."""

from __future__ import annotations

from typing import Iterable, Sequence


_STATE_LABELS = {
    "expected-relations-observed": "일반적인 Counter 관계 관찰",
    "relation-mismatch-observed": "Counter 관계 불일치 관찰",
    "multiple-values-observed": "여러 Counter 관계 관찰",
    "partial": "일부 관계만 확인",
    "insufficient-events": "비교 메시지 부족",
    "unavailable": "필드 또는 값 확인 불가",
}

_PAIR_LABELS = {
    "equal-observed": "같은 Counter 관계 관찰",
    "mismatch-observed": "서로 다른 Counter 관계 관찰",
    "multiple-values-observed": "여러 Counter 관계 관찰",
    "unavailable": "Counter 값 확인 불가",
    "not-observed": "비교 메시지 미관찰",
}

_PROGRESS_LABELS = {
    "increased-observed": "후반 Counter 증가 관계 관찰",
    "equal-observed": "같은 Counter 관계 관찰",
    "decreased-observed": "후반 Counter 감소 관계 관찰",
    "multiple-values-observed": "여러 Counter 관계 관찰",
    "unavailable": "Counter 값 확인 불가",
    "not-observed": "비교 메시지 미관찰",
}

_REPEAT_LABELS = {
    "same-counter-observed": "반복 메시지에서 같은 Counter 관계 관찰",
    "different-counters-observed": "반복 메시지에서 다른 Counter 관계 관찰",
    "unavailable": "반복 메시지 Counter 확인 불가",
}


def _yes_no(value: bool) -> str:
    return "예" if value else "아니오"


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


def format_eapol_replay_relations(result: object, limit: int = 60) -> str:
    """Return a Korean relationship-only section for the main text view."""

    report = getattr(result, "eapol_replay_relations", None)
    if report is None:
        return (
            "\n\n[11. EAPOL Replay Counter 관계]\n"
            "Replay Counter 관계 분석 결과가 없습니다.\n"
            "원문 Counter 값을 표시하거나 동일 Handshake를 추정하지 않습니다."
        )

    observations = []
    for index, item in enumerate(report.observations[:limit], start=1):
        repeated = []
        for relation in item.repeated_message_relations:
            repeated.append(
                "M{message}: {state} · 근거 {frames}".format(
                    message=relation.message_number,
                    state=_REPEAT_LABELS.get(relation.state, relation.state),
                    frames=_frames(relation.evidence_frames),
                )
            )
        observations.append(
            "{index}. [{state}] {observation} · {device} ↔ {ap}\n"
            "   설명: {summary}\n"
            "   M1/M2 관계: {m12}\n"
            "   M3/M4 관계: {m34}\n"
            "   M1→M3 진행 관계: {progress}\n"
            "   반복 메시지 관계: {repeated}\n"
            "   Counter 확인 프레임: {with_counter}\n"
            "   Counter 미확인 프레임: {missing}\n"
            "   근거 프레임: {evidence}\n"
            "   Wireshark 필터: {display_filter}\n"
            "   동일 Handshake 확정: {same} · 실제 재전송 확정: {retry}\n"
            "   키 설치 확정: {install} · 암호학적 성공 확정: {crypto} · "
            "근본 원인 확정: {root}".format(
                index=index,
                state=_STATE_LABELS.get(item.state, item.state),
                observation=item.observation_id,
                device=item.device_alias,
                ap=item.ap_alias,
                summary=item.summary_ko,
                m12=_PAIR_LABELS.get(item.m1_m2_relation, item.m1_m2_relation),
                m34=_PAIR_LABELS.get(item.m3_m4_relation, item.m3_m4_relation),
                progress=_PROGRESS_LABELS.get(
                    item.m1_m3_progression,
                    item.m1_m3_progression,
                ),
                repeated=" / ".join(repeated) if repeated else "없음",
                with_counter=_frames(item.frames_with_counter),
                missing=_frames(item.missing_counter_frames),
                evidence=_frames(item.evidence_frames),
                display_filter=item.display_filter or "없음",
                same=_yes_no(item.same_handshake_confirmed),
                retry=_yes_no(item.retransmission_confirmed),
                install=_yes_no(item.key_installation_confirmed),
                crypto=_yes_no(item.cryptographic_success_confirmed),
                root=_yes_no(item.root_cause_confirmed),
            )
        )
    if not observations:
        observations.append(
            "- DEVICE-N·AP-N에 안전하게 연결된 EAPOL-Key 관찰이 없습니다."
        )
    hidden = max(0, len(report.observations) - limit)
    if hidden:
        observations.append(
            "- Counter 관계 관찰 {0:,}건은 GUI 상세 표시에서 생략했습니다.".format(
                hidden
            )
        )

    return (
        "\n\n[11. EAPOL Replay Counter 관계]\n"
        "전용 필드 사용 가능: {field} · 처리 행 {rows:,}개 · Key 행 {key_rows:,}개\n"
        "원본 메시지 관찰 {source:,}개 · 관계 평가 {evaluated:,}개 · "
        "전체 관계 처리 {complete}\n\n"
        "관계 결과:\n{observations}\n"
        "주의: {cautions}\n"
        "보호 경계: Counter 원문 직렬화 {raw} · Counter 값 저장 {persisted} · "
        "동일 Handshake 확정 {same} · 실제 재전송 확정 {retry} · "
        "키 설치 확정 {install} · 암호학적 성공 확정 {crypto} · "
        "근본 원인 확정 {root}\n"
        "중요: 이 화면에는 Replay Counter 숫자가 표시되지 않습니다. "
        "같음·증가·감소·불일치 관계는 패킷 관찰 결과일 뿐 하나의 실제 "
        "Handshake, 재전송, 키 설치 또는 장애 원인을 확정하지 않습니다."
    ).format(
        field=_yes_no(report.field_available),
        rows=report.rows_observed,
        key_rows=report.key_rows_observed,
        source=report.observations_source_total,
        evaluated=report.observations_evaluated,
        complete=_yes_no(report.complete),
        observations="\n\n".join(observations),
        cautions=_compact(report.cautions, 10),
        raw=_yes_no(report.raw_replay_counters_serialized),
        persisted=_yes_no(report.replay_counter_values_persisted),
        same=_yes_no(report.same_handshake_confirmed),
        retry=_yes_no(report.retransmission_confirmed),
        install=_yes_no(report.key_installation_confirmed),
        crypto=_yes_no(report.cryptographic_success_confirmed),
        root=_yes_no(report.root_cause_confirmed),
    )


def install(main_window_module: object) -> None:
    """Idempotently append the relationship section to the main formatter."""

    if getattr(main_window_module, "_EAPOL_REPLAY_RELATIONS_INSTALLED", False):
        return
    original = main_window_module.format_analysis_detail

    def format_analysis_detail(result: object) -> str:
        return original(result) + format_eapol_replay_relations(result)

    main_window_module.format_analysis_detail = format_analysis_detail
    main_window_module._EAPOL_REPLAY_RELATIONS_INSTALLED = True
