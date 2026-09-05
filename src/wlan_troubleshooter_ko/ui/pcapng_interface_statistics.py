"""Korean formatter for identifier-free PCAPNG interface statistics."""

from __future__ import annotations

from typing import Iterable, Sequence


_STATE_LABELS = {
    "reported-drop-observed": "양의 드롭 Counter 관찰",
    "zero-reported-drop-counters": "보고된 드롭 Counter 0",
    "statistics-without-drop-counters": "통계 블록 있으나 드롭 Counter 없음",
    "no-interface-statistics": "Interface Statistics Block 없음",
    "unsupported-capture-format": "일반 PCAP — PCAPNG 통계 구조 없음",
    "partial": "일부 통계만 처리",
}

_COUNTER_LABELS = {
    "ifrecv": "인터페이스 수신 패킷",
    "ifdrop": "인터페이스 보고 드롭",
    "filteraccept": "필터 수락 패킷",
    "osdrop": "운영체제 보고 드롭",
    "usrdeliv": "사용자 공간 전달 패킷",
}

_PROGRESSION_LABELS = {
    "counter-increase-observed": "증가 관찰",
    "counter-unchanged-observed": "변화 없음",
    "counter-decrease-observed": "감소·Reset 가능성 관찰",
    "single-value-observed": "단일 값 관찰",
    "not-reported": "미보고",
}


def _yes_no(value: bool) -> str:
    return "예" if value else "아니오"


def _value(value: object) -> str:
    return "미보고" if value is None else "{0:,}".format(int(value))


def _compact(values: Sequence[str], limit: int = 8) -> str:
    items = tuple(values)
    if not items:
        return "없음"
    visible = list(items[:limit])
    if len(items) > limit:
        visible.append("외 {0}개".format(len(items) - limit))
    return " · ".join(visible)


def format_pcapng_interface_statistics(
    result: object,
    limit: int = 100,
) -> str:
    report = getattr(result, "pcapng_interface_statistics", None)
    if report is None:
        return (
            "\n\n[12. PCAPNG 인터페이스 통계]\n"
            "PCAPNG Interface Statistics Block 분석 결과가 없습니다.\n"
            "통계가 없다는 사실은 캡처 손실이 없다는 뜻이 아닙니다."
        )

    interfaces = []
    for index, item in enumerate(report.interfaces[:limit], start=1):
        counter_lines = []
        for counter in item.counters:
            counter_lines.append(
                "      {label}: 최초 {first} · 마지막 {last} · 관찰 {count:,}회 · {progression}".format(
                    label=_COUNTER_LABELS.get(counter.name, counter.name),
                    first=_value(counter.first_value),
                    last=_value(counter.last_value),
                    count=counter.observations,
                    progression=_PROGRESSION_LABELS.get(
                        counter.progression,
                        counter.progression,
                    ),
                )
            )
        interfaces.append(
            "{index}. [{state}] {alias}\n"
            "   섹션 {section:,} · 섹션 내부 Interface ID {interface_id:,} · "
            "ISB {isb_count:,}개\n"
            "   Counter:\n{counters}\n"
            "   실제 인터페이스 식별정보 직렬화: {raw}\n"
            "   절대 ISB timestamp 직렬화: {timestamp}\n"
            "   특정 패킷 손실 확정: {specific} · 근본 원인 확정: {root}".format(
                index=index,
                state=_STATE_LABELS.get(item.state, item.state),
                alias=item.interface_alias,
                section=item.section_index + 1,
                interface_id=item.interface_id,
                isb_count=item.statistics_blocks,
                counters="\n".join(counter_lines) if counter_lines else "      없음",
                raw=_yes_no(item.raw_interface_identifiers_serialized),
                timestamp=_yes_no(item.absolute_timestamps_serialized),
                specific=_yes_no(item.specific_packet_loss_confirmed),
                root=_yes_no(item.root_cause_confirmed),
            )
        )
    if not interfaces:
        interfaces.append("- 표시할 PCAPNG 인터페이스가 없습니다.")
    hidden = max(0, len(report.interfaces) - limit)
    if hidden:
        interfaces.append(
            "- 인터페이스 {0:,}개는 GUI 상세 표시에서 생략했습니다.".format(
                hidden
            )
        )

    return (
        "\n\n[12. PCAPNG 인터페이스 통계]\n"
        "상태: {state}\n"
        "PCAPNG 통계 지원 형식: {supported} · 전체 처리: {complete}\n"
        "섹션 {sections:,}개 · 정의 인터페이스 {defined:,}개 · "
        "ISB {isb:,}개 · 통계가 있는 인터페이스 {with_stats:,}개\n"
        "실제 인터페이스 식별정보 직렬화: {raw}\n"
        "절대 ISB timestamp 직렬화: {timestamp}\n"
        "캡처 손실 배제: {loss}\n"
        "특정 패킷 손실 확정: {specific} · 근본 원인 확정: {root}\n\n"
        "인터페이스별 통계:\n{interfaces}\n"
        "주의: {cautions}\n"
        "중요: ifdrop·osdrop이 0이어도 전체 캡처 경로의 무손실을 증명하지 "
        "않습니다. 양의 Counter가 있어도 특정 EAPOL·DHCP·DNS·TCP 패킷이 "
        "누락됐거나 RF·SPAN·운영체제·드라이버 중 어느 위치가 원인인지 "
        "확정하지 않습니다."
    ).format(
        state=_STATE_LABELS.get(report.state, report.state),
        supported=_yes_no(report.supported_capture_format),
        complete=_yes_no(report.complete),
        sections=report.sections_observed,
        defined=report.interfaces_defined,
        isb=report.statistics_blocks_observed,
        with_stats=report.interfaces_with_statistics,
        raw=_yes_no(report.raw_interface_identifiers_serialized),
        timestamp=_yes_no(report.absolute_timestamps_serialized),
        loss=_yes_no(report.capture_loss_excluded),
        specific=_yes_no(report.specific_packet_loss_confirmed),
        root=_yes_no(report.root_cause_confirmed),
        interfaces="\n\n".join(interfaces),
        cautions=_compact(report.cautions, 10),
    )


def install(main_window_module: object) -> None:
    """Idempotently append the PCAPNG statistics section."""

    if getattr(
        main_window_module,
        "_PCAPNG_INTERFACE_STATISTICS_INSTALLED",
        False,
    ):
        return
    original = main_window_module.format_analysis_detail

    def format_analysis_detail(result: object) -> str:
        return original(result) + format_pcapng_interface_statistics(result)

    main_window_module.format_analysis_detail = format_analysis_detail
    main_window_module._PCAPNG_INTERFACE_STATISTICS_INSTALLED = True
