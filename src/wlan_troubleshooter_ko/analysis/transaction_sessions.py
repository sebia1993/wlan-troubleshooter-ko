"""Phase 4C의 비식별 이벤트를 프로토콜 거래 시도별로 묶는다.

이 모듈은 원본 주소, 포트, 사용자명, SSID, 거래 ID 또는 TCP Stream을
입력받거나 직렬화하지 않는다. 이벤트 타임라인이 만든 로컬 순번 별칭과
프레임 근거만 사용한다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Mapping, Optional, Sequence, Tuple


_ALIAS_PATTERN = re.compile(r"^(EAP|RADIUS|DHCP|DNS|TCP)-([1-9][0-9]{0,5})$")
_EVENT_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_MAX_SESSIONS = 50_000
_MAX_EVENTS_PER_SESSION = 200_000
_MAX_EVIDENCE_FRAMES = 64


class TransactionSessionError(ValueError):
    """비식별 거래 시도 입력이 안전 조건과 다른 경우."""


@dataclass(frozen=True)
class _ProtocolDefinition:
    label_ko: str
    required_sequence: Tuple[str, ...]
    success_events: Tuple[str, ...]
    failure_events: Tuple[str, ...]
    terminal_events: Tuple[str, ...]
    accepted_prefixes: Tuple[str, ...]
    complete_supported: bool
    next_checks_ko: Tuple[str, ...]


_DEFINITIONS: Mapping[str, _ProtocolDefinition] = {
    "EAP": _ProtocolDefinition(
        label_ko="EAP 단말 인증",
        required_sequence=("eap_request", "eap_response", "eap_success"),
        success_events=("eap_success",),
        failure_events=("eap_failure",),
        terminal_events=("eap_success", "eap_failure"),
        accepted_prefixes=("eap_",),
        complete_supported=True,
        next_checks_ko=(
            "EAP Request·Response·Success 또는 Failure의 순서와 근거 프레임을 확인합니다.",
            "단말 Supplicant와 인증 서버 로그를 같은 시간 범위로 확인합니다.",
        ),
    ),
    "RADIUS": _ProtocolDefinition(
        label_ko="RADIUS 인증 서버",
        required_sequence=("radius_access_request", "radius_access_accept"),
        success_events=("radius_access_accept",),
        failure_events=("radius_access_reject",),
        terminal_events=("radius_access_accept", "radius_access_reject"),
        accepted_prefixes=("radius_",),
        complete_supported=True,
        next_checks_ko=(
            "Access-Request·Challenge·Accept·Reject의 순서와 근거 프레임을 확인합니다.",
            "ClearPass Access Tracker에서 같은 시간의 계정·인증서·정책 결과를 확인합니다.",
        ),
    ),
    "DHCP": _ProtocolDefinition(
        label_ko="DHCP 주소 할당",
        required_sequence=("dhcp_discover", "dhcp_offer", "dhcp_request", "dhcp_ack"),
        success_events=("dhcp_ack",),
        failure_events=("dhcp_nak",),
        terminal_events=("dhcp_ack", "dhcp_nak"),
        accepted_prefixes=("dhcp_",),
        complete_supported=True,
        next_checks_ko=(
            "Discover·Offer·Request·ACK 또는 NAK 순서와 근거 프레임을 확인합니다.",
            "VLAN·DHCP Relay·Scope 여유와 DHCP 서버 로그를 확인합니다.",
        ),
    ),
    "DNS": _ProtocolDefinition(
        label_ko="DNS 이름 조회",
        required_sequence=("dns_query", "dns_response_success"),
        success_events=("dns_response_success",),
        failure_events=("dns_response_error",),
        terminal_events=("dns_response_success", "dns_response_error"),
        accepted_prefixes=("dns_",),
        complete_supported=True,
        next_checks_ko=(
            "DNS Query와 Response의 프레임 간격 및 응답 코드를 확인합니다.",
            "같은 시간의 DNS 서버 로그와 방화벽 UDP·TCP 53 정책을 확인합니다.",
        ),
    ),
    "TCP": _ProtocolDefinition(
        label_ko="TCP 연결",
        required_sequence=("tcp_syn", "tcp_syn_ack"),
        success_events=("tcp_syn_ack",),
        failure_events=("tcp_reset",),
        terminal_events=("tcp_reset",),
        accepted_prefixes=("tcp_", "tls_"),
        complete_supported=False,
        next_checks_ko=(
            "SYN·SYN/ACK·RST와 재전송 표시의 순서 및 근거 프레임을 확인합니다.",
            "최종 ACK를 구분하지 않으므로 서버 수신 포트·방화벽·응용프로그램 로그를 추가 확인합니다.",
        ),
    ),
}


@dataclass(frozen=True)
class TransactionAttempt:
    attempt_id: str
    correlation_alias: str
    protocol: str
    label_ko: str
    state: str
    summary_ko: str
    event_count: int
    first_frame: int
    last_frame: int
    duration_ms: int
    evidence_frames: Tuple[int, ...]
    evidence_frames_omitted: int
    display_filter: str
    observed_event_types: Tuple[str, ...]
    missing_event_types: Tuple[str, ...]
    next_checks_ko: Tuple[str, ...]
    root_cause_confirmed: bool = False
    device_session_confirmed: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "attempt_id": self.attempt_id,
            "correlation_alias": self.correlation_alias,
            "protocol": self.protocol,
            "label_ko": self.label_ko,
            "state": self.state,
            "summary_ko": self.summary_ko,
            "event_count": self.event_count,
            "first_frame": self.first_frame,
            "last_frame": self.last_frame,
            "duration_ms": self.duration_ms,
            "evidence_frames": list(self.evidence_frames),
            "evidence_frames_omitted": self.evidence_frames_omitted,
            "display_filter": self.display_filter,
            "observed_event_types": list(self.observed_event_types),
            "missing_event_types": list(self.missing_event_types),
            "next_checks_ko": list(self.next_checks_ko),
            "root_cause_confirmed": self.root_cause_confirmed,
            "device_session_confirmed": self.device_session_confirmed,
        }


@dataclass(frozen=True)
class TransactionSessionReport:
    attempts: Tuple[TransactionAttempt, ...]
    attempts_by_protocol: Tuple[Tuple[str, int], ...]
    attempts_by_state: Tuple[Tuple[str, int], ...]
    unassigned_event_count: int
    source_events_total: int
    source_events_retained: int
    source_events_omitted: int
    complete: bool
    cautions: Tuple[str, ...]

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema_version": 1,
            "attempts_total": len(self.attempts),
            "attempts_by_protocol": {
                key: value for key, value in self.attempts_by_protocol
            },
            "attempts_by_state": {
                key: value for key, value in self.attempts_by_state
            },
            "unassigned_event_count": self.unassigned_event_count,
            "source_events_total": self.source_events_total,
            "source_events_retained": self.source_events_retained,
            "source_events_omitted": self.source_events_omitted,
            "complete": self.complete,
            "attempts": [item.to_dict() for item in self.attempts],
            "cautions": list(self.cautions),
        }


@dataclass(frozen=True)
class _EventView:
    event_type: str
    frame_number: int
    relative_time_ms: int


def _attribute(value: object, name: str) -> object:
    try:
        return getattr(value, name)
    except (AttributeError, TypeError) as exc:
        raise TransactionSessionError("이벤트 타임라인 구조가 올바르지 않습니다.") from exc


def _nonnegative_integer(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise TransactionSessionError(label + " 값이 올바르지 않습니다.")
    return value


def _normalize_event(value: object) -> Tuple[Optional[str], _EventView]:
    alias = _attribute(value, "correlation_alias")
    event_type = _attribute(value, "event_type")
    frame_number = _attribute(value, "frame_number")
    relative_time_ms = _attribute(value, "relative_time_ms")

    if alias is not None and (
        not isinstance(alias, str) or _ALIAS_PATTERN.fullmatch(alias) is None
    ):
        raise TransactionSessionError("승인되지 않은 거래 별칭입니다.")
    if not isinstance(event_type, str) or _EVENT_PATTERN.fullmatch(event_type) is None:
        raise TransactionSessionError("이벤트 종류 형식이 올바르지 않습니다.")
    if type(frame_number) is not int or frame_number <= 0:
        raise TransactionSessionError("이벤트 프레임 번호가 올바르지 않습니다.")
    if type(relative_time_ms) is not int or relative_time_ms < 0:
        raise TransactionSessionError("이벤트 상대 시간이 올바르지 않습니다.")

    if alias is not None:
        match = _ALIAS_PATTERN.fullmatch(alias)
        if match is None:
            raise TransactionSessionError("승인되지 않은 거래 별칭입니다.")
        definition = _DEFINITIONS[match.group(1)]
        if not event_type.startswith(definition.accepted_prefixes):
            raise TransactionSessionError(
                "거래 별칭과 이벤트 프로토콜이 일치하지 않습니다."
            )
    return alias, _EventView(event_type, frame_number, relative_time_ms)


def _alias_key(alias: str) -> Tuple[int, int]:
    match = _ALIAS_PATTERN.fullmatch(alias)
    if match is None:
        raise TransactionSessionError("승인되지 않은 거래 별칭입니다.")
    protocol_order = tuple(_DEFINITIONS).index(match.group(1))
    return protocol_order, int(match.group(2), 10)


def _sequence_progress(
    events: Sequence[_EventView],
    required: Sequence[str],
) -> Tuple[str, ...]:
    position = 0
    for event in events:
        if position < len(required) and event.event_type == required[position]:
            position += 1
    return tuple(required[position:])


def _state(
    definition: _ProtocolDefinition,
    events: Sequence[_EventView],
) -> Tuple[str, str, Tuple[str, ...]]:
    observed = {item.event_type for item in events}
    has_success = bool(observed.intersection(definition.success_events))
    has_failure = bool(observed.intersection(definition.failure_events))
    missing = _sequence_progress(events, definition.required_sequence)

    if has_success and has_failure:
        return (
            "mixed",
            "같은 비식별 거래 시도에서 성공과 실패 결과가 함께 관찰됐습니다. 재시도 또는 캡처 결합 가능성을 확인해야 합니다.",
            missing,
        )
    if has_failure:
        return (
            "failure-observed",
            "명시적인 실패·거부·오류 또는 Reset 이벤트가 관찰됐습니다. 해당 이벤트는 확정이지만 근본 원인은 추가 확인이 필요합니다.",
            missing,
        )
    if definition.complete_supported and not missing:
        return (
            "complete",
            "요청부터 명시적인 성공 결과까지 필요한 순서 요소가 관찰됐습니다.",
            (),
        )
    if has_success:
        return (
            "success-observed",
            "명시적인 성공 응답은 관찰됐지만 시작부터의 모든 순서 요소는 확인되지 않았습니다.",
            missing,
        )
    return (
        "incomplete",
        "관련 요청 또는 중간 이벤트는 관찰됐지만 최종 결과를 확인하지 못했습니다. 패킷 누락만으로 장애를 확정하지 않습니다.",
        missing,
    )


def _display_filter(frames: Sequence[int]) -> str:
    return " || ".join("frame.number == {0}".format(value) for value in frames)


def _freeze_attempt(
    alias: str,
    attempt_number: int,
    events: Sequence[_EventView],
) -> TransactionAttempt:
    match = _ALIAS_PATTERN.fullmatch(alias)
    if match is None:
        raise TransactionSessionError("승인되지 않은 거래 별칭입니다.")
    protocol = match.group(1)
    definition = _DEFINITIONS[protocol]
    if not events or len(events) > _MAX_EVENTS_PER_SESSION:
        raise TransactionSessionError("한 거래 시도의 이벤트 수가 안전 제한을 벗어났습니다.")

    ordered = tuple(
        sorted(
            events,
            key=lambda item: (
                item.frame_number,
                item.relative_time_ms,
                item.event_type,
            ),
        )
    )
    frames = tuple(sorted({item.frame_number for item in ordered}))
    evidence = frames[:_MAX_EVIDENCE_FRAMES]
    state, summary, missing = _state(definition, ordered)
    return TransactionAttempt(
        attempt_id=alias + "-A" + str(attempt_number),
        correlation_alias=alias,
        protocol=protocol.casefold(),
        label_ko=definition.label_ko,
        state=state,
        summary_ko=summary,
        event_count=len(ordered),
        first_frame=frames[0],
        last_frame=frames[-1],
        duration_ms=max(item.relative_time_ms for item in ordered)
        - min(item.relative_time_ms for item in ordered),
        evidence_frames=evidence,
        evidence_frames_omitted=max(0, len(frames) - len(evidence)),
        display_filter=_display_filter(evidence),
        observed_event_types=tuple(sorted({item.event_type for item in ordered})),
        missing_event_types=missing,
        next_checks_ko=definition.next_checks_ko,
    )


def _split_attempts(alias: str, events: Sequence[_EventView]) -> Tuple[TransactionAttempt, ...]:
    match = _ALIAS_PATTERN.fullmatch(alias)
    if match is None:
        raise TransactionSessionError("승인되지 않은 거래 별칭입니다.")
    definition = _DEFINITIONS[match.group(1)]
    ordered = tuple(
        sorted(
            events,
            key=lambda item: (
                item.frame_number,
                item.relative_time_ms,
                item.event_type,
            ),
        )
    )
    attempts: List[TransactionAttempt] = []
    current: List[_EventView] = []
    attempt_number = 1
    for event in ordered:
        current.append(event)
        if event.event_type in definition.terminal_events:
            attempts.append(_freeze_attempt(alias, attempt_number, current))
            current = []
            attempt_number += 1
    if current:
        attempts.append(_freeze_attempt(alias, attempt_number, current))
    return tuple(attempts)


def build_transaction_sessions(timeline: object) -> TransactionSessionReport:
    """비식별 타임라인을 거래 시도별 요약으로 변환한다."""

    events_value = _attribute(timeline, "events")
    complete_value = _attribute(timeline, "complete")
    total = _nonnegative_integer(_attribute(timeline, "events_total"), "전체 이벤트 수")
    retained = _nonnegative_integer(
        _attribute(timeline, "events_retained"),
        "보관 이벤트 수",
    )
    omitted = _nonnegative_integer(
        _attribute(timeline, "events_omitted"),
        "생략 이벤트 수",
    )
    if not isinstance(events_value, (tuple, list)):
        raise TransactionSessionError("이벤트 타임라인 목록이 올바르지 않습니다.")
    if type(complete_value) is not bool:
        raise TransactionSessionError("캡처 완료 상태가 올바르지 않습니다.")
    if retained != len(events_value) or total != retained + omitted:
        raise TransactionSessionError("이벤트 보관 수와 전체 수가 일치하지 않습니다.")

    grouped: Dict[str, List[_EventView]] = {}
    unassigned = 0
    previous_order: Optional[Tuple[int, int]] = None
    for raw_event in events_value:
        alias, event = _normalize_event(raw_event)
        order = (event.frame_number, event.relative_time_ms)
        if previous_order is not None and order < previous_order:
            raise TransactionSessionError("이벤트 타임라인 순서가 올바르지 않습니다.")
        previous_order = order
        if alias is None:
            unassigned += 1
            continue
        if alias not in grouped and len(grouped) >= _MAX_SESSIONS:
            raise TransactionSessionError("거래 별칭 수가 안전 제한을 초과했습니다.")
        grouped.setdefault(alias, []).append(event)

    attempts: List[TransactionAttempt] = []
    for alias in sorted(grouped, key=_alias_key):
        attempts.extend(_split_attempts(alias, grouped[alias]))

    protocol_counts: Dict[str, int] = {}
    state_counts: Dict[str, int] = {}
    for item in attempts:
        protocol_counts[item.protocol] = protocol_counts.get(item.protocol, 0) + 1
        state_counts[item.state] = state_counts.get(item.state, 0) + 1

    result_complete = complete_value and omitted == 0
    cautions = [
        "거래 별칭은 캡처 내부 상관용 순번이며 단말·사용자 신원을 의미하지 않습니다.",
        "프로토콜별 거래를 서로 연결하지 않으므로 EAP-1·RADIUS-1·DHCP-1이 같은 단말이라고 단정할 수 없습니다.",
        "거래 완료 또는 실패 이벤트가 관찰돼도 무선 접속 전체의 근본 원인은 확정되지 않습니다.",
        "TCP는 최종 ACK를 식별하지 않으므로 SYN/ACK가 보여도 3-Way Handshake 완료로 표시하지 않습니다.",
    ]
    if omitted:
        cautions.insert(
            0,
            "상세 이벤트 보관 상한으로 일부 이벤트가 생략되어 거래 시도 요약은 부분 결과입니다.",
        )
    if not complete_value:
        cautions.insert(
            0,
            "일부 프레임만 처리되어 미완료 거래를 장애로 해석할 수 없습니다.",
        )

    return TransactionSessionReport(
        attempts=tuple(attempts),
        attempts_by_protocol=tuple(sorted(protocol_counts.items())),
        attempts_by_state=tuple(sorted(state_counts.items())),
        unassigned_event_count=unassigned,
        source_events_total=total,
        source_events_retained=retained,
        source_events_omitted=omitted,
        complete=result_complete,
        cautions=tuple(cautions),
    )
