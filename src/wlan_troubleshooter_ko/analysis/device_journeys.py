"""Build conservative per-device journeys from already pseudonymized results.

The module accepts only ``DEVICE-N`` aliases, transaction-attempt metadata and
packet evidence produced by earlier analysis stages. It never receives raw
addresses, SSIDs, user identities, host names, ports or original transaction
identifiers. A journey is an observation grouping, not a confirmed user session
or root-cause conclusion.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple


_DEVICE_PATTERN = re.compile(r"^DEVICE-[1-9][0-9]{0,5}$")
_AP_PATTERN = re.compile(r"^AP-[1-9][0-9]{0,5}$")
_ATTEMPT_PATTERN = re.compile(
    r"^(EAP|RADIUS|DHCP|DNS|TCP)-[1-9][0-9]{0,5}-A[1-9][0-9]{0,5}$"
)
_MAX_DEVICES = 20_000
_MAX_ATTEMPTS = 50_000
_MAX_EVIDENCE_FRAMES = 96

_STAGE_ORDER = ("eap", "radius", "dhcp", "dns", "tcp")
_STAGE_LABELS = {
    "eap": "EAP 단말 인증",
    "radius": "RADIUS 인증 서버",
    "dhcp": "DHCP 주소 할당",
    "dns": "DNS 이름 조회",
    "tcp": "TCP 연결",
}
_ALLOWED_ATTEMPT_STATES = {
    "complete",
    "success-observed",
    "failure-observed",
    "mixed",
    "incomplete",
}
_ALLOWED_LINK_STATES = {"linked", "unassigned", "ambiguous"}
_POSITIVE_STATES = {"complete", "success-observed"}
_FAILURE_STATES = {"failure-observed", "mixed"}


class DeviceJourneyError(ValueError):
    """Pseudonymized device/transaction results violate journey invariants."""


@dataclass(frozen=True)
class DeviceJourneyStage:
    protocol: str
    label_ko: str
    state: str
    summary_ko: str
    attempt_ids: Tuple[str, ...]
    attempt_count: int
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

    def to_dict(self) -> Dict[str, object]:
        return {
            "protocol": self.protocol,
            "label_ko": self.label_ko,
            "state": self.state,
            "summary_ko": self.summary_ko,
            "attempt_ids": list(self.attempt_ids),
            "attempt_count": self.attempt_count,
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
        }


@dataclass(frozen=True)
class DeviceJourney:
    device_alias: str
    ap_aliases: Tuple[str, ...]
    state: str
    summary_ko: str
    first_frame: int
    last_frame: int
    duration_ms: int
    linked_attempt_ids: Tuple[str, ...]
    observed_stage_order: Tuple[str, ...]
    stages: Tuple[DeviceJourneyStage, ...]
    first_failure_stage: Optional[str]
    last_positive_stage: Optional[str]
    evidence_frames: Tuple[int, ...]
    evidence_frames_omitted: int
    display_filter: str
    device_identity_confirmed: bool = False
    cross_protocol_session_confirmed: bool = False
    root_cause_confirmed: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "device_alias": self.device_alias,
            "ap_aliases": list(self.ap_aliases),
            "state": self.state,
            "summary_ko": self.summary_ko,
            "first_frame": self.first_frame,
            "last_frame": self.last_frame,
            "duration_ms": self.duration_ms,
            "linked_attempt_ids": list(self.linked_attempt_ids),
            "observed_stage_order": list(self.observed_stage_order),
            "stages": [item.to_dict() for item in self.stages],
            "first_failure_stage": self.first_failure_stage,
            "last_positive_stage": self.last_positive_stage,
            "evidence_frames": list(self.evidence_frames),
            "evidence_frames_omitted": self.evidence_frames_omitted,
            "display_filter": self.display_filter,
            "device_identity_confirmed": self.device_identity_confirmed,
            "cross_protocol_session_confirmed": self.cross_protocol_session_confirmed,
            "root_cause_confirmed": self.root_cause_confirmed,
        }


@dataclass(frozen=True)
class DeviceJourneyReport:
    journeys: Tuple[DeviceJourney, ...]
    journeys_by_state: Tuple[Tuple[str, int], ...]
    linked_attempts_total: int
    unassigned_attempts: int
    ambiguous_attempts: int
    devices_without_linked_attempts: int
    source_complete: bool
    linkage_complete: bool
    complete: bool
    raw_identifiers_serialized: bool
    aliases_stable_across_runs: bool
    device_identity_confirmed: bool
    cross_protocol_session_confirmed: bool
    root_cause_confirmed: bool
    cautions: Tuple[str, ...]

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema_version": 1,
            "journeys_total": len(self.journeys),
            "journeys_by_state": {
                key: value for key, value in self.journeys_by_state
            },
            "linked_attempts_total": self.linked_attempts_total,
            "unassigned_attempts": self.unassigned_attempts,
            "ambiguous_attempts": self.ambiguous_attempts,
            "devices_without_linked_attempts": self.devices_without_linked_attempts,
            "source_complete": self.source_complete,
            "linkage_complete": self.linkage_complete,
            "complete": self.complete,
            "raw_identifiers_serialized": self.raw_identifiers_serialized,
            "aliases_stable_across_runs": self.aliases_stable_across_runs,
            "device_identity_confirmed": self.device_identity_confirmed,
            "cross_protocol_session_confirmed": self.cross_protocol_session_confirmed,
            "root_cause_confirmed": self.root_cause_confirmed,
            "journeys": [item.to_dict() for item in self.journeys],
            "cautions": list(self.cautions),
        }


def _attribute(value: object, name: str, label: str) -> object:
    try:
        return getattr(value, name)
    except (AttributeError, TypeError) as exc:
        raise DeviceJourneyError(label + " 구조가 올바르지 않습니다.") from exc


def _collection(value: object, name: str, label: str) -> Tuple[object, ...]:
    result = _attribute(value, name, label)
    if not isinstance(result, (tuple, list)):
        raise DeviceJourneyError(label + " 목록이 올바르지 않습니다.")
    return tuple(result)


def _boolean(value: object, name: str, label: str) -> bool:
    result = _attribute(value, name, label)
    if type(result) is not bool:
        raise DeviceJourneyError(label + " 완료 상태가 올바르지 않습니다.")
    return result


def _positive_integer(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise DeviceJourneyError(label + " 값이 올바르지 않습니다.")
    return value


def _nonnegative_integer(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise DeviceJourneyError(label + " 값이 올바르지 않습니다.")
    return value


def _string_tuple(value: object, label: str) -> Tuple[str, ...]:
    if not isinstance(value, (tuple, list)) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise DeviceJourneyError(label + " 목록이 올바르지 않습니다.")
    result = tuple(value)
    if len(result) != len(set(result)):
        raise DeviceJourneyError(label + " 목록에 중복 값이 있습니다.")
    return result


def _integer_tuple(value: object, label: str) -> Tuple[int, ...]:
    if not isinstance(value, (tuple, list)):
        raise DeviceJourneyError(label + " 목록이 올바르지 않습니다.")
    result = tuple(value)
    if any(type(item) is not int or item <= 0 for item in result):
        raise DeviceJourneyError(label + " 프레임 번호가 올바르지 않습니다.")
    if result != tuple(sorted(set(result))):
        raise DeviceJourneyError(label + " 프레임은 중복 없이 오름차순이어야 합니다.")
    return result


def _display_filter(frames: Sequence[int]) -> str:
    return " || ".join("frame.number == {0}".format(value) for value in frames)


def _alias_sort(value: str) -> Tuple[str, int]:
    prefix, separator, number = value.rpartition("-")
    if not separator or not number.isascii() or not number.isdecimal():
        raise DeviceJourneyError("가명 형식이 올바르지 않습니다.")
    return prefix, int(number, 10)


def _attempt_protocol(attempt_id: str) -> str:
    match = _ATTEMPT_PATTERN.fullmatch(attempt_id)
    if match is None:
        raise DeviceJourneyError("거래 시도 ID가 올바르지 않습니다.")
    return match.group(1).casefold()


def _validated_attempts(transaction_sessions: object) -> Dict[str, object]:
    values = _collection(transaction_sessions, "attempts", "거래 시도 보고서")
    if len(values) > _MAX_ATTEMPTS:
        raise DeviceJourneyError("거래 시도 수가 안전 제한을 초과했습니다.")
    result: Dict[str, object] = {}
    for value in values:
        attempt_id = _attribute(value, "attempt_id", "거래 시도")
        protocol = _attribute(value, "protocol", "거래 시도")
        state = _attribute(value, "state", "거래 시도")
        if not isinstance(attempt_id, str) or _ATTEMPT_PATTERN.fullmatch(attempt_id) is None:
            raise DeviceJourneyError("거래 시도 ID가 올바르지 않습니다.")
        expected_protocol = _attempt_protocol(attempt_id)
        if protocol != expected_protocol or protocol not in _STAGE_ORDER:
            raise DeviceJourneyError("거래 시도 ID와 프로토콜이 일치하지 않습니다.")
        if state not in _ALLOWED_ATTEMPT_STATES:
            raise DeviceJourneyError("거래 시도 상태가 올바르지 않습니다.")
        if attempt_id in result:
            raise DeviceJourneyError("거래 시도 ID가 중복됐습니다.")

        first_frame = _positive_integer(
            _attribute(value, "first_frame", "거래 시도"),
            "거래 시작 프레임",
        )
        last_frame = _positive_integer(
            _attribute(value, "last_frame", "거래 시도"),
            "거래 마지막 프레임",
        )
        if last_frame < first_frame:
            raise DeviceJourneyError("거래 시도 프레임 범위가 올바르지 않습니다.")
        _nonnegative_integer(
            _attribute(value, "duration_ms", "거래 시도"),
            "거래 상대 지속시간",
        )
        evidence = _integer_tuple(
            _attribute(value, "evidence_frames", "거래 시도"),
            "거래 근거",
        )
        omitted = _nonnegative_integer(
            _attribute(value, "evidence_frames_omitted", "거래 시도"),
            "거래 근거 생략 수",
        )
        if omitted and evidence:
            # Phase 4E removes truncated evidence before it can be linked.
            pass
        if any(frame < first_frame or frame > last_frame for frame in evidence):
            raise DeviceJourneyError("거래 근거 프레임이 거래 범위를 벗어났습니다.")
        if _attribute(value, "root_cause_confirmed", "거래 시도") is not False:
            raise DeviceJourneyError("거래 시도 근본 원인 확정 값은 false여야 합니다.")
        if _attribute(value, "device_session_confirmed", "거래 시도") is not False:
            raise DeviceJourneyError("거래 시도 단말 세션 확정 값은 false여야 합니다.")
        result[attempt_id] = value
    return result


def _validated_devices(device_sessions: object) -> Dict[str, object]:
    values = _collection(device_sessions, "devices", "단말 가명 보고서")
    if len(values) > _MAX_DEVICES:
        raise DeviceJourneyError("단말 가명 수가 안전 제한을 초과했습니다.")
    result: Dict[str, object] = {}
    for value in values:
        alias = _attribute(value, "alias", "단말 가명")
        if not isinstance(alias, str) or _DEVICE_PATTERN.fullmatch(alias) is None:
            raise DeviceJourneyError("단말 가명 형식이 올바르지 않습니다.")
        if alias in result:
            raise DeviceJourneyError("단말 가명이 중복됐습니다.")
        if _attribute(value, "device_identity_confirmed", "단말 가명") is not False:
            raise DeviceJourneyError("단말 신원 확정 값은 false여야 합니다.")
        if _attribute(value, "cross_protocol_session_confirmed", "단말 가명") is not False:
            raise DeviceJourneyError("교차 프로토콜 세션 확정 값은 false여야 합니다.")
        first_frame = _positive_integer(
            _attribute(value, "first_frame", "단말 가명"),
            "단말 첫 프레임",
        )
        last_frame = _positive_integer(
            _attribute(value, "last_frame", "단말 가명"),
            "단말 마지막 프레임",
        )
        if last_frame < first_frame:
            raise DeviceJourneyError("단말 가명 프레임 범위가 올바르지 않습니다.")
        _nonnegative_integer(
            _attribute(value, "duration_ms", "단말 가명"),
            "단말 상대 지속시간",
        )
        ap_aliases = _string_tuple(
            _attribute(value, "ap_aliases", "단말 가명"),
            "AP 가명",
        )
        if any(_AP_PATTERN.fullmatch(item) is None for item in ap_aliases):
            raise DeviceJourneyError("AP 가명 형식이 올바르지 않습니다.")
        _string_tuple(
            _attribute(value, "linked_attempt_ids", "단말 가명"),
            "단말 연결 거래",
        )
        result[alias] = value
    return result


def _validated_links(
    device_sessions: object,
    attempts: Mapping[str, object],
    devices: Mapping[str, object],
) -> Tuple[Dict[str, str], int, int]:
    values = _collection(device_sessions, "attempt_links", "단말 거래 연결")
    if len(values) != len(attempts):
        raise DeviceJourneyError("거래 시도와 단말 연결 결과 수가 일치하지 않습니다.")
    linked: Dict[str, str] = {}
    unassigned = 0
    ambiguous = 0
    seen: Set[str] = set()
    for value in values:
        attempt_id = _attribute(value, "attempt_id", "단말 거래 연결")
        state = _attribute(value, "state", "단말 거래 연결")
        device_alias = _attribute(value, "device_alias", "단말 거래 연결")
        if attempt_id not in attempts or attempt_id in seen:
            raise DeviceJourneyError("단말 거래 연결 ID가 없거나 중복됐습니다.")
        seen.add(attempt_id)
        if state not in _ALLOWED_LINK_STATES:
            raise DeviceJourneyError("단말 거래 연결 상태가 올바르지 않습니다.")
        if state == "linked":
            if not isinstance(device_alias, str) or device_alias not in devices:
                raise DeviceJourneyError("연결된 거래의 단말 가명이 올바르지 않습니다.")
            attempt = attempts[attempt_id]
            if _nonnegative_integer(
                _attribute(attempt, "evidence_frames_omitted", "거래 시도"),
                "거래 근거 생략 수",
            ):
                raise DeviceJourneyError(
                    "근거 프레임이 생략된 거래는 단말 여정에 연결할 수 없습니다."
                )
            linked[attempt_id] = device_alias
        else:
            if device_alias is not None:
                raise DeviceJourneyError("미연결 거래에 단말 가명이 설정됐습니다.")
            if state == "unassigned":
                unassigned += 1
            else:
                ambiguous += 1
    if seen != set(attempts):
        raise DeviceJourneyError("일부 거래 시도에 단말 연결 결과가 없습니다.")

    expected_by_device: Dict[str, Set[str]] = {key: set() for key in devices}
    for attempt_id, alias in linked.items():
        expected_by_device[alias].add(attempt_id)
    for alias, device in devices.items():
        declared = set(
            _string_tuple(
                _attribute(device, "linked_attempt_ids", "단말 가명"),
                "단말 연결 거래",
            )
        )
        if declared != expected_by_device[alias]:
            raise DeviceJourneyError("단말의 거래 목록과 연결 결과가 일치하지 않습니다.")
    return linked, unassigned, ambiguous


def _attempt_order(value: object) -> Tuple[int, int, str]:
    return (
        _positive_integer(
            _attribute(value, "first_frame", "거래 시도"),
            "거래 시작 프레임",
        ),
        _positive_integer(
            _attribute(value, "last_frame", "거래 시도"),
            "거래 마지막 프레임",
        ),
        str(_attribute(value, "attempt_id", "거래 시도")),
    )


def _stage_state(attempts: Sequence[object]) -> Tuple[str, str]:
    states = {
        str(_attribute(item, "state", "거래 시도")) for item in attempts
    }
    has_positive = bool(states.intersection(_POSITIVE_STATES))
    has_failure = bool(states.intersection(_FAILURE_STATES))
    has_incomplete = "incomplete" in states
    if "mixed" in states or (has_positive and has_failure):
        return (
            "mixed",
            "이 단계에서 성공 방향 결과와 실패 결과가 함께 관찰됐습니다. 여러 시도 또는 재시도를 개별 근거로 확인해야 합니다.",
        )
    if has_failure:
        return (
            "failure-observed",
            "이 단계의 한 개 이상 거래에서 명시적인 실패·거부·오류 또는 Reset이 관찰됐습니다. 근본 원인은 확정하지 않습니다.",
        )
    if states == {"complete"}:
        return (
            "complete",
            "이 단계의 연결된 거래에서 필요한 성공 순서가 관찰됐습니다.",
        )
    if has_positive and has_incomplete:
        return (
            "partial-progress",
            "성공 방향 결과와 최종 결과를 확인하지 못한 거래가 함께 있습니다. 캡처 범위와 개별 시도를 확인해야 합니다.",
        )
    if has_positive:
        return (
            "success-observed",
            "이 단계에서 성공 결과 또는 성공 방향 응답이 관찰됐습니다. 전체 접속 성공을 뜻하지 않습니다.",
        )
    return (
        "incomplete",
        "이 단계의 요청 또는 중간 이벤트는 보였지만 명시적인 최종 결과를 확인하지 못했습니다.",
    )


def _unique_strings(values: Iterable[str]) -> Tuple[str, ...]:
    return tuple(sorted(set(values)))


def _freeze_stage(protocol: str, attempts: Sequence[object]) -> DeviceJourneyStage:
    ordered = tuple(sorted(attempts, key=_attempt_order))
    if not ordered:
        raise DeviceJourneyError("비어 있는 단말 여정 단계를 만들 수 없습니다.")
    state, summary = _stage_state(ordered)
    first_frame = min(
        _positive_integer(
            _attribute(item, "first_frame", "거래 시도"),
            "거래 시작 프레임",
        )
        for item in ordered
    )
    last_frame = max(
        _positive_integer(
            _attribute(item, "last_frame", "거래 시도"),
            "거래 마지막 프레임",
        )
        for item in ordered
    )
    frames = tuple(
        sorted(
            {
                frame
                for item in ordered
                for frame in _integer_tuple(
                    _attribute(item, "evidence_frames", "거래 시도"),
                    "거래 근거",
                )
            }
        )
    )
    evidence = frames[:_MAX_EVIDENCE_FRAMES]
    observed = _unique_strings(
        event
        for item in ordered
        for event in _string_tuple(
            _attribute(item, "observed_event_types", "거래 시도"),
            "관찰 이벤트",
        )
    )
    missing = _unique_strings(
        event
        for item in ordered
        for event in _string_tuple(
            _attribute(item, "missing_event_types", "거래 시도"),
            "미관찰 이벤트",
        )
    )
    checks = _unique_strings(
        check
        for item in ordered
        for check in _string_tuple(
            _attribute(item, "next_checks_ko", "거래 시도"),
            "다음 점검 항목",
        )
    )
    return DeviceJourneyStage(
        protocol=protocol,
        label_ko=_STAGE_LABELS[protocol],
        state=state,
        summary_ko=summary,
        attempt_ids=tuple(
            str(_attribute(item, "attempt_id", "거래 시도")) for item in ordered
        ),
        attempt_count=len(ordered),
        first_frame=first_frame,
        last_frame=last_frame,
        duration_ms=max(
            _nonnegative_integer(
                _attribute(item, "duration_ms", "거래 시도"),
                "거래 상대 지속시간",
            )
            for item in ordered
        ),
        evidence_frames=evidence,
        evidence_frames_omitted=max(0, len(frames) - len(evidence)),
        display_filter=_display_filter(evidence),
        observed_event_types=observed,
        missing_event_types=missing,
        next_checks_ko=checks,
    )


def _journey_state(stages: Sequence[DeviceJourneyStage]) -> Tuple[str, str]:
    if not stages:
        return (
            "no-linked-transactions",
            "이 단말 가명에 안전하게 연결된 EAP·RADIUS·DHCP·DNS·TCP 거래가 없습니다.",
        )
    states = {item.state for item in stages}
    if "mixed" in states:
        return (
            "mixed",
            "단말 가명에 연결된 거래에서 성공 방향과 실패 결과가 함께 관찰됐습니다. 각 거래를 개별적으로 확인해야 합니다.",
        )
    if states.intersection(_FAILURE_STATES):
        return (
            "failure-observed",
            "단말 가명에 연결된 한 개 이상 단계에서 명시적인 실패 결과가 관찰됐습니다. 실패 지점과 근본 원인은 구분해야 합니다.",
        )
    if "partial-progress" in states or "incomplete" in states:
        if states.intersection(_POSITIVE_STATES) or "partial-progress" in states:
            return (
                "partial-progress",
                "성공 방향으로 진행된 단계와 최종 결과를 확인하지 못한 단계가 함께 관찰됐습니다.",
            )
        return (
            "incomplete",
            "연결된 거래가 있지만 명시적인 최종 결과를 확인하지 못했습니다. 캡처 누락 가능성을 유지합니다.",
        )
    return (
        "progress-observed",
        "연결된 프로토콜 거래에서 성공 방향 진행이 관찰됐습니다. 전체 사용자 접속 성공이나 동일 세션을 확정하지 않습니다.",
    )


def _freeze_journey(device: object, attempts: Sequence[object]) -> DeviceJourney:
    alias = str(_attribute(device, "alias", "단말 가명"))
    first_frame = _positive_integer(
        _attribute(device, "first_frame", "단말 가명"),
        "단말 첫 프레임",
    )
    last_frame = _positive_integer(
        _attribute(device, "last_frame", "단말 가명"),
        "단말 마지막 프레임",
    )
    duration_ms = _nonnegative_integer(
        _attribute(device, "duration_ms", "단말 가명"),
        "단말 상대 지속시간",
    )
    by_protocol: Dict[str, List[object]] = {}
    for attempt in attempts:
        protocol = str(_attribute(attempt, "protocol", "거래 시도"))
        by_protocol.setdefault(protocol, []).append(attempt)
    stages = tuple(
        _freeze_stage(protocol, by_protocol[protocol])
        for protocol in _STAGE_ORDER
        if protocol in by_protocol
    )
    state, summary = _journey_state(stages)
    observed_order = tuple(
        item.protocol
        for item in sorted(
            stages,
            key=lambda item: (
                item.first_frame,
                _STAGE_ORDER.index(item.protocol),
            ),
        )
    )
    failure_stages = [
        item for item in stages if item.state in _FAILURE_STATES
    ]
    positive_stages = [
        item
        for item in stages
        if item.state in _POSITIVE_STATES or item.state == "partial-progress"
    ]
    first_failure = (
        min(failure_stages, key=lambda item: item.first_frame).protocol
        if failure_stages
        else None
    )
    last_positive = (
        max(positive_stages, key=lambda item: item.last_frame).protocol
        if positive_stages
        else None
    )
    all_frames = tuple(
        sorted({frame for item in stages for frame in item.evidence_frames})
    )
    evidence = all_frames[:_MAX_EVIDENCE_FRAMES]
    omitted = sum(item.evidence_frames_omitted for item in stages)
    omitted += max(0, len(all_frames) - len(evidence))
    return DeviceJourney(
        device_alias=alias,
        ap_aliases=tuple(
            sorted(
                _string_tuple(
                    _attribute(device, "ap_aliases", "단말 가명"),
                    "AP 가명",
                ),
                key=_alias_sort,
            )
        ),
        state=state,
        summary_ko=summary,
        first_frame=first_frame,
        last_frame=last_frame,
        duration_ms=duration_ms,
        linked_attempt_ids=tuple(
            str(_attribute(item, "attempt_id", "거래 시도"))
            for item in sorted(attempts, key=_attempt_order)
        ),
        observed_stage_order=observed_order,
        stages=stages,
        first_failure_stage=first_failure,
        last_positive_stage=last_positive,
        evidence_frames=evidence,
        evidence_frames_omitted=omitted,
        display_filter=_display_filter(evidence),
    )


def build_device_journeys(
    device_sessions: object,
    transaction_sessions: object,
) -> DeviceJourneyReport:
    """Create per-device observational journeys without identity inference."""

    attempts = _validated_attempts(transaction_sessions)
    devices = _validated_devices(device_sessions)
    linked, unassigned, ambiguous = _validated_links(
        device_sessions,
        attempts,
        devices,
    )

    attempts_by_device: Dict[str, List[object]] = {
        alias: [] for alias in devices
    }
    for attempt_id, device_alias in linked.items():
        attempts_by_device[device_alias].append(attempts[attempt_id])

    journeys = tuple(
        _freeze_journey(devices[alias], attempts_by_device[alias])
        for alias in sorted(devices, key=_alias_sort)
    )
    state_counts: Dict[str, int] = {}
    for journey in journeys:
        state_counts[journey.state] = state_counts.get(journey.state, 0) + 1

    device_source_complete = _boolean(
        device_sessions,
        "complete",
        "단말 가명 보고서",
    )
    transaction_source_complete = _boolean(
        transaction_sessions,
        "complete",
        "거래 시도 보고서",
    )
    source_complete = device_source_complete and transaction_source_complete
    linkage_complete = unassigned == 0 and ambiguous == 0
    complete = source_complete and linkage_complete
    devices_without = sum(1 for value in attempts_by_device.values() if not value)

    cautions = [
        "DEVICE-N은 현재 분석 실행에서만 유효하며 다른 실행의 같은 번호와 비교할 수 없습니다.",
        "여정은 같은 단말 가명에 안전하게 연결된 거래의 관찰 순서이며 사용자 신원이나 하나의 완전한 접속 세션을 확정하지 않습니다.",
        "RADIUS처럼 단말 L2 근거가 없는 거래는 시간만으로 여정에 추가하지 않습니다.",
        "실패 단계는 명시적 패킷 결과의 위치이며 ClearPass·DHCP·DNS·서버 중 근본 책임 시스템을 확정하지 않습니다.",
        "거래 또는 단계 미관찰은 캡처 시작·종료·방향·잘림 때문에 생길 수 있습니다.",
    ]
    if ambiguous:
        cautions.insert(
            0,
            "둘 이상의 단말 근거가 있는 거래가 있어 해당 거래를 여정에서 제외했습니다.",
        )
    if unassigned:
        cautions.insert(
            0,
            "단말 근거가 없는 거래가 있어 모든 프로토콜 단계를 여정에 포함하지 못했습니다.",
        )
    if not source_complete:
        cautions.insert(
            0,
            "입력 분석이 일부 결과이므로 단말 가명별 여정도 일부 결과입니다.",
        )

    return DeviceJourneyReport(
        journeys=journeys,
        journeys_by_state=tuple(sorted(state_counts.items())),
        linked_attempts_total=len(linked),
        unassigned_attempts=unassigned,
        ambiguous_attempts=ambiguous,
        devices_without_linked_attempts=devices_without,
        source_complete=source_complete,
        linkage_complete=linkage_complete,
        complete=complete,
        raw_identifiers_serialized=False,
        aliases_stable_across_runs=False,
        device_identity_confirmed=False,
        cross_protocol_session_confirmed=False,
        root_cause_confirmed=False,
        cautions=tuple(cautions),
    )
