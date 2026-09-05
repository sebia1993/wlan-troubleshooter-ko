"""PCAPNG Interface Statistics Block을 초급자용 한국어로 표시한다."""

from __future__ import annotations

from typing import Optional


_STATE_LABELS = {
    "reported-drop-observed": "0보다 큰 드롭 카운터 관찰",
    "zero-reported-drop-counters": "제공된 드롭 카운터가 모두 0",
    "statistics-without-drop-counters": "통계 블록에 드롭 카운터 없음",
}


def _value(value: Optional[int]) -> str:
    return "미제공" if value is None else "{0:,}".format(value)


def _yes_no(value: bool) -> str:
    return "예" if value else "아니오"


def format_pcapng_statistics(result: object, limit: int = 80) -> str:
    structure = getattr(result, "structure", None)
    if structure is None:
        return (
            "\n\n[12. PCAPNG 인터페이스 통계]\n"
            "캡처 구조 결과가 없어 Interface Statistics Block을 확인하지 못했습니다."
        )
    if getattr(structure, "capture_format", None) != "pcapng":
        return (
            "\n\n[12. PCAPNG 인터페이스 통계]\n"
            "선택한 파일은 PCAPNG가 아니어서 Interface Statistics Block이 없습니다.\n"
            "이는 캡처 손실이 없었다는 뜻이 아닙니다."
        )

    observations = tuple(getattr(structure, "interface_statistics", ()))
    if not observations:
        return (
            "\n\n[12. PCAPNG 인터페이스 통계]\n"
            "Interface Statistics Block을 관찰하지 못했습니다.\n"
            "캡처 도구가 드롭 통계를 기록하지 않았거나 현재 점검 범위에 통계 "
            "블록이 없을 수 있습니다. 통계 부재는 캡처 무손실 증명이 아닙니다."
        )

    lines = []
    for index, item in enumerate(observations[:limit], start=1):
        lines.append(
            "{index}. [{state}] {alias} · 관찰 #{observation}\n"
            "   Section/Interface: {section}/{interface}\n"
            "   수신 보고(ifrecv): {ifrecv}\n"
            "   인터페이스 드롭(ifdrop): {ifdrop}\n"
            "   필터 수락(filteraccept): {filteraccept}\n"
            "   OS 드롭(osdrop): {osdrop}\n"
            "   사용자 전달(usrdeliv): {usrdeliv}\n"
            "   블록 Timestamp 필드 존재: {block_time} · 시작/종료 옵션: {start}/{end}\n"
            "   절대 Timestamp 출력: {absolute}\n"
            "   캡처 손실 배제: {loss} · 근본 원인 확정: {root}".format(
                index=index,
                state=_STATE_LABELS.get(item.counter_state, item.counter_state),
                alias=item.interface_alias,
                observation=item.observation_index,
                section=item.section_index,
                interface=item.interface_id,
                ifrecv=_value(item.ifrecv),
                ifdrop=_value(item.ifdrop),
                filteraccept=_value(item.filteraccept),
                osdrop=_value(item.osdrop),
                usrdeliv=_value(item.usrdeliv),
                block_time=_yes_no(item.block_timestamp_present),
                start=_yes_no(item.start_time_present),
                end=_yes_no(item.end_time_present),
                absolute=_yes_no(item.absolute_timestamps_serialized),
                loss=_yes_no(item.capture_loss_excluded),
                root=_yes_no(item.root_cause_confirmed),
            )
        )
    hidden = max(0, len(observations) - limit)
    if hidden:
        lines.append(
            "- 인터페이스 통계 관찰 {0:,}건은 GUI 상세 표시에서 생략했습니다.".format(
                hidden
            )
        )

    return (
        "\n\n[12. PCAPNG 인터페이스 통계]\n"
        "상태: {state} · 통계 블록 {count:,}개\n\n"
        "{observations}\n"
        "중요: 드롭 카운터 0은 캡처 무손실 증명이 아닙니다. 0보다 큰 드롭이 "
        "있어도 특정 EAPOL·DHCP·DNS 패킷 누락이나 AP·단말·RF 근본 원인을 "
        "확정하지 않습니다. 같은 인터페이스의 여러 블록은 누적값일 수 있어 "
        "서로 합산하지 않습니다."
    ).format(
        state=getattr(structure, "interface_statistics_state", "unknown"),
        count=len(observations),
        observations="\n\n".join(lines),
    )


def install(main_window_module: object) -> None:
    """메인 결과 포맷터에 PCAPNG 통계 영역을 한 번만 연결한다."""

    if getattr(main_window_module, "_PCAPNG_STATISTICS_INSTALLED", False):
        return
    original = main_window_module.format_analysis_detail

    def format_analysis_detail(result: object) -> str:
        return original(result) + format_pcapng_statistics(result)

    main_window_module.format_analysis_detail = format_analysis_detail
    main_window_module._PCAPNG_STATISTICS_INSTALLED = True
