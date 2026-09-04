"""Conservative EAPOL-Key message sequence observations.

The model consumes only identifier-free timeline events and analysis-scoped
``DEVICE-N`` / ``AP-N`` summaries. It does not consume or serialize raw MAC
addresses, BSSIDs, SSIDs, replay counters, nonces, MICs, key data or payloads.
An M1-M4 sequence is an observation only; it is never proof of one handshake,
key installation, cryptographic success or root cause.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple


_DEVICE_PATTERN = re.compile(r"^DEVICE-[1-9][0-9]{0,5}$")
_AP_PATTERN = re.compile(r"^AP-[1-9][0-9]{0,5}$")
_KEY_EVENT_PATTERN = re.compile(r"^eapol_key_message_([1-4])$")
_MAX_KEY_EVENTS = 20_000
_MAX_OBSERVATIONS = 10_000
_MAX_DEVICE_EVIDENCE = 64
_MAX_OBSERVATION_EVIDENCE = 64


class EapolHandshakeError(ValueError):
    """Identifier-free source reports violate handshake invariants."""


@dataclass(frozen=True)
class EapolHandshakeObservation:
    observation_id: str
    device_alias: str
    ap_alias: str
    state: str
    summary_ko: str
    event_count: int
    first_frame: int
    last_frame: int
    duration_ms: int
    observed_message_numbers: Tuple[int, ...]
    first_observed_order: Tuple[int, ...]
    missing_message_numbers: Tuple[int, ...]
    repeated_message_numbers: Tuple[int, ...]
    retry_flag_frames: Tuple[int, ...]
    evidence_frames: Tuple[int, ...]
    evidence_frames_omitted: int
    display_filter: str
    replay_counter_correlation_available: bool = False
    raw_key_material_serialized: bool = False
    raw_identifiers_serialized: bool = False
    same_handshake_confirmed: bool = False
    key_installation_confirmed: bool = False
    cryptographic_success_confirmed: bool = False
    root_cause_confirmed: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "observation_id": self.observation_id,
            "device_alias": self.device_alias,
            "ap_alias": self.ap_alias,
            "state": self.state,
            "summary_ko": self.summary_ko,
            "event_count": self.event_count,
            "first_frame": self.first_frame,
            "last_frame": self.last_frame,
            "duration_ms": self.duration_ms,
            "observed_message_numbers": list(self.observed_message_numbers),
            "first_observed_order": list(self.first_observed_order),
            "missing_message_numbers": list(self.missing_message_numbers),
            "repeated_message_numbers": list(self.repeated_message_numbers),
            "retry_flag_frames": list(self.retry_flag_frames),
            "evidence_frames": list(self.evidence_frames),
            "evidence_frames_omitted": self.evidence_frames_omitted,
            "display_filter": self.display_filter,
            "replay_counter_correlation_available": self.replay_counter_correlation_available,
            "raw_key_material_serialized": self.raw_key_material_serialized,
            "raw_identifiers_serialized": self.raw_identifiers_serialized,
            "same_handshake_confirmed": self.same_handshake_confirmed,
            "key_installation_confirmed": self.key_installation_confirmed,
            "cryptographic_success_confirmed": self.cryptographic_success_confirmed,
            "root_cause_confirmed": self.root_cause_confirmed,
        }


@dataclass(frozen=True)
class EapolHandshakeReport:
    field_available: bool
    source_timeline_complete: bool
    device_report_complete: bool
    device_evidence_complete: bool
    linkage_complete: bool
    complete: bool
    source_key_events_total: int
    linked_key_events: int
    unassigned_key_events: int
    ambiguous_key_events: int
    timeline_events_omitted: int
    observations: Tuple[EapolHandshakeObservation, ...]
    replay_counter_correlation_available: bool
    raw_key_material_serialized: bool
    raw_identifiers_serialized: bool
    same_handshake_confirmed: bool
    key_installation_confirmed: bool
    cryptographic_success_confirmed: bool
    root_cause_confirmed: bool
    cautions: Tuple[str, ...]

    def to_dict(self) -> Dict[str, object]:
        state_counts: Dict[str, int] = {}
        for item in self.observations:
            state_counts[item.state] = state_counts.get(item.state, 0) + 1
        return {
            "schema_version": 1,
            "field_available": self.field_available,
            "source_timeline_complete": self.source_timeline_complete,
            "device_report_complete": self.device_report_complete,
            "device_evidence_complete": self.device_evidence_complete,
            "linkage_complete": self.linkage_complete,
            "complete": self.complete,
            "source_key_events_total": self.source_key_events_total,
            "linked_key_events": self.linked_key_events,
            "unassigned_key_events": self.unassigned_key_events,
            "ambiguous_key_events": self.ambiguous_key_events,
            "timeline_events_omitted": self.timeline_events_omitted,
            "observations_total": len(self.observations),
            "observations_by_state": dict(sorted(state_counts.items())),
            "observations": [item.to_dict() for item in self.observations],
            "replay_counter_correlation_available": self.replay_counter_correlation_available,
            "raw_key_material_serialized": self.raw_key_material_serialized,
            "raw_identifiers_serialized": self.raw_identifiers_serialized,
            "same_handshake_confirmed": self.same_handshake_confirmed,
            "key_installation_confirmed": self.key_installation_confirmed,
            "cryptographic_success_confirmed": self.cryptographic_success_confirmed,
            "root_cause_confirmed": self.root_cause_confirmed,
            "cautions": list(self.cautions),
        }


@dataclass(frozen=True)
class _KeyEvent:
    frame_number: int
    relative_time_ms: int
    message_number: int
    retry_flag_observed: bool
    device_alias: str
    ap_alias: str


def _attribute(value: object, name: str, label: str) -> object:
    try:
        return getattr(value, name)
    except (AttributeError, TypeError) as exc:
        raise EapolHandshakeError(label + " 구조가 올바르지 않습니다.") from exc


def _boolean(value: object, name: str, label: str) -> bool:
    result = _attribute(value, name, label)
    if type(result) is not bool:
        raise EapolHandshakeError(label + " 상태 값이 올바르지 않습니다.")
    return result


def _must_be_false(value: object, name: str, label: str) -> None:
    if _attribute(value, name, label) is not False:
        raise EapolHandshakeError(label + " 보호 플래그는 false여야 합니다.")


def _nonnegative(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise EapolHandshakeError(label + " 값이 올바르지 않습니다.")
    return value


def _positive(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise EapolHandshakeError(label + " 값이 올바르지 않습니다.")
    return value


def _collection(value: object, name: str, label: str) -> Tuple[object, ...]:
    result = _attribute(value, name, label)
    if not isinstance(result, (tuple, list)):
        raise EapolHandshakeError(label + " 목록이 올바르지 않습니다.")
    return tuple(result)


def _string_tuple(value: object, label: str) -> Tuple[str, ...]:
    if not isinstance(value, (tuple, list)) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise EapolHandshakeError(label + " 목록이 올바르지 않습니다.")
    result = tuple(value)
    if len(result) != len(set(result)):
        raise EapolHandshakeError(label + " 목록에 중복 값이 있습니다.")
    return result


def _frame_tuple(value: object, label: str) -> Tuple[int, ...]:
    if not isinstance(value, (tuple, list)):
        raise EapolHandshakeError(label + " 목록이 올바르지 않습니다.")
    result = tuple(value)
    if any(type(item) is not int or item <= 0 for item in result):
        raise EapolHandshakeError(label + " 프레임 번호가 올바르지 않습니다.")
    if result != tuple(sorted(set(result))):
        raise EapolHandshakeError(label + " 프레임은 중복 없이 오름차순이어야 합니다.")
    if len(result) > _MAX_DEVICE_EVIDENCE:
        raise EapolHandshakeError(label + " 프레임 수가 안전 상한을 초과했습니다.")
    return result


def _details(value: object) -> Mapping[str, str]:
    if not isinstance(value, (tuple, list)):
        raise EapolHandshakeError("이벤트 상세 구조가 올바르지 않습니다.")
    result: Dict[str, str] = {}
    for item in value:
        if (
            not isinstance(item, (tuple, list))
            or len(item) != 2
            or not isinstance(item[0], str)
            or not isinstance(item[1], str)
            or not item[0]
        ):
            raise EapolHandshakeError("이벤트 상세 값이 올바르지 않습니다.")
        if item[0] in result:
            raise EapolHandshakeError("이벤트 상세 키가 중복됐습니다.")
        result[item[0]] = item[1]
    return result


def _display_filter(frames: Sequence[int]) -> str:
    return " || ".join("frame.number == {0}".format(value) for value in frames)


def _alias_sort(value: str) -> Tuple[str, int]:
    prefix, separator, number = value.rpartition("-")
    if not separator or not number.isascii() or not number.isdecimal():
        raise EapolHandshakeError("가명 형식이 올바르지 않습니다.")
    return prefix, int(number, 10)


def _device_evidence(device_report: object) -> Tuple[Dict[int, Set[str]], Dict[str, Tuple[str, ...]], bool]:
    _must_be_false(device_report, "raw_identifiers_serialized", "단말 가명 보고서")
    _must_be_false(device_report, "alias_secret_persisted", "단말 가명 보고서")
    _must_be_false(device_report, "aliases_stable_across_runs", "단말 가명 보고서")

    frame_devices: Dict[int, Set[str]] = {}
    device_aps: Dict[str, Tuple[str, ...]] = {}
    evidence_complete = True
    devices = _collection(device_report, "devices", "단말 가명 보고서")
    for device in devices:
        alias = _attribute(device, "alias", "단말 가명")
        if not isinstance(alias, str) or _DEVICE_PATTERN.fullmatch(alias) is None:
            raise EapolHandshakeError("단말 가명 형식이 올바르지 않습니다.")
        if alias in device_aps:
            raise EapolHandshakeError("단말 가명이 중복됐습니다.")
        _must_be_false(device, "device_identity_confirmed", "단말 가명")
        _must_be_false(device, "cross_protocol_session_confirmed", "단말 가명")
        frames = _frame_tuple(
            _attribute(device, "evidence_frames", "단말 가명"),
            "단말 근거",
        )
        omitted = _nonnegative(
            _attribute(device, "evidence_frames_omitted", "단말 가명"),
            "단말 근거 생략 수",
        )
        if omitted:
            evidence_complete = False
        aps = _string_tuple(
            _attribute(device, "ap_aliases", "단말 가명"),
            "AP 가명",
        )
        if any(_AP_PATTERN.fullmatch(item) is None for item in aps):
            raise EapolHandshakeError("AP 가명 형식이 올바르지 않습니다.")
        device_aps[alias] = tuple(sorted(aps, key=_alias_sort))
        for frame in frames:
            frame_devices.setdefault(frame, set()).add(alias)
    return frame_devices, device_aps, evidence_complete


def _timeline_events(timeline: object) -> Tuple[Tuple[object, ...], Set[int], bool, int]:
    events = _collection(timeline, "events", "이벤트 타임라인")
    timeline_complete = _boolean(timeline, "complete", "이벤트 타임라인")
    omitted = _nonnegative(
        _attribute(timeline, "events_omitted", "이벤트 타임라인"),
        "이벤트 생략 수",
    )
    missing_optional = _string_tuple(
        _attribute(timeline, "missing_optional_fields", "이벤트 타임라인"),
        "누락 선택 필드",
    )
    field_available = "eapol_key_message" not in missing_optional

    previous_frame = 0
    previous_time = 0
    key_frames: Set[int] = set()
    retry_frames: Set[int] = set()
    key_events = []
    for event in events:
        frame = _positive(
            _attribute(event, "frame_number", "이벤트"),
            "이벤트 프레임",
        )
        relative_time = _nonnegative(
            _attribute(event, "relative_time_ms", "이벤트"),
            "이벤트 상대 시간",
        )
        if frame < previous_frame or relative_time < previous_time:
            raise EapolHandshakeError("이벤트 타임라인 순서가 올바르지 않습니다.")
        previous_frame = frame
        previous_time = relative_time
        event_type = _attribute(event, "event_type", "이벤트")
        category = _attribute(event, "category", "이벤트")
        if not isinstance(event_type, str) or not isinstance(category, str):
            raise EapolHandshakeError("이벤트 종류가 올바르지 않습니다.")
        evidence_filter = _attribute(event, "evidence_filter", "이벤트")
        if evidence_filter != "frame.number == " + str(frame):
            raise EapolHandshakeError("이벤트 근거 필터가 프레임 번호와 일치하지 않습니다.")
        if event_type == "wlan_retry_flag":
            if frame in retry_frames:
                raise EapolHandshakeError("Retry 이벤트가 같은 프레임에 중복됐습니다.")
            retry_frames.add(frame)
            continue
        match = _KEY_EVENT_PATTERN.fullmatch(event_type)
        if match is None:
            continue
        if category != "eapol" or frame in key_frames:
            raise EapolHandshakeError("EAPOL-Key 이벤트가 중복되거나 범주가 올바르지 않습니다.")
        message = int(match.group(1), 10)
        details = _details(_attribute(event, "details", "이벤트"))
        if details.get("message_number") != str(message):
            raise EapolHandshakeError("EAPOL-Key 메시지 상세 값이 이벤트 종류와 일치하지 않습니다.")
        key_frames.add(frame)
        key_events.append(event)
    if len(key_events) > _MAX_KEY_EVENTS:
        raise EapolHandshakeError("EAPOL-Key 이벤트 수가 안전 제한을 초과했습니다.")
    return tuple(key_events), retry_frames, field_available, omitted


def _segments(events: Sequence[_KeyEvent]) -> Tuple[Tuple[_KeyEvent, ...], ...]:
    result: List[Tuple[_KeyEvent, ...]] = []
    current: List[_KeyEvent] = []
    for event in events:
        if current:
            last_message = current[-1].message_number
            progressed_beyond_m1 = any(item.message_number != 1 for item in current)
            if last_message == 4 or (event.message_number == 1 and progressed_beyond_m1):
                result.append(tuple(current))
                current = []
        current.append(event)
    if current:
        result.append(tuple(current))
    return tuple(result)


def _first_order(numbers: Sequence[int]) -> Tuple[int, ...]:
    result: List[int] = []
    for number in numbers:
        if number not in result:
            result.append(number)
    return tuple(result)


def _state(numbers: Sequence[int]) -> Tuple[str, str, Tuple[int, ...], Tuple[int, ...], Tuple[int, ...]]:
    first_order = _first_order(numbers)
    missing = tuple(number for number in (1, 2, 3, 4) if number not in first_order)
    repeated = tuple(
        number for number in (1, 2, 3, 4) if numbers.count(number) > 1
    )
    order_violation = any(
        current < previous
        for previous, current in zip(numbers, numbers[1:])
    )
    if order_violation:
        return (
            "out-of-order",
            "EAPOL-Key 메시지 번호가 역순으로 관찰됐습니다. 캡처 누락·여러 교환 혼재 가능성을 확인해야 합니다.",
            first_order,
            missing,
            repeated,
        )
    if first_order == (1, 2, 3, 4):
        if repeated:
            return (
                "message-repetition-observed",
                "M1→M2→M3→M4 순서와 같은 메시지 번호의 반복이 관찰됐습니다. Replay Counter를 사용하지 않아 실제 재전송은 확정하지 않습니다.",
                first_order,
                missing,
                repeated,
            )
        return (
            "sequence-observed",
            "M1→M2→M3→M4 메시지 번호 순서가 관찰됐습니다. 동일 Handshake·키 설치·암호학적 성공은 확정하지 않습니다.",
            first_order,
            missing,
            repeated,
        )
    return (
        "incomplete",
        "EAPOL-Key 메시지 일부만 관찰됐습니다. 캡처 시작·종료·방향·손실 가능성을 유지합니다.",
        first_order,
        missing,
        repeated,
    )


def _freeze_observation(
    observation_id: str,
    events: Sequence[_KeyEvent],
) -> EapolHandshakeObservation:
    if not events:
        raise EapolHandshakeError("비어 있는 EAPOL 관찰을 만들 수 없습니다.")
    device_alias = events[0].device_alias
    ap_alias = events[0].ap_alias
    if any(
        item.device_alias != device_alias or item.ap_alias != ap_alias
        for item in events
    ):
        raise EapolHandshakeError("하나의 관찰에 서로 다른 단말·AP 가명이 섞였습니다.")
    numbers = tuple(item.message_number for item in events)
    state, summary, first_order, missing, repeated = _state(numbers)
    all_frames = tuple(sorted({item.frame_number for item in events}))
    evidence = all_frames[:_MAX_OBSERVATION_EVIDENCE]
    retry_frames = tuple(
        item.frame_number for item in events if item.retry_flag_observed
    )
    return EapolHandshakeObservation(
        observation_id=observation_id,
        device_alias=device_alias,
        ap_alias=ap_alias,
        state=state,
        summary_ko=summary,
        event_count=len(events),
        first_frame=events[0].frame_number,
        last_frame=events[-1].frame_number,
        duration_ms=events[-1].relative_time_ms - events[0].relative_time_ms,
        observed_message_numbers=numbers,
        first_observed_order=first_order,
        missing_message_numbers=missing,
        repeated_message_numbers=repeated,
        retry_flag_frames=retry_frames,
        evidence_frames=evidence,
        evidence_frames_omitted=max(0, len(all_frames) - len(evidence)),
        display_filter=_display_filter(evidence),
    )


def build_eapol_handshakes(
    timeline: object,
    device_report: object,
) -> EapolHandshakeReport:
    """Build identifier-free EAPOL-Key message sequence observations."""

    key_events, retry_frames, field_available, timeline_omitted = _timeline_events(
        timeline
    )
    frame_devices, device_aps, evidence_complete = _device_evidence(device_report)
    source_timeline_complete = _boolean(
        timeline,
        "complete",
        "이벤트 타임라인",
    )
    device_report_complete = _boolean(
        device_report,
        "complete",
        "단말 가명 보고서",
    )

    linked: List[_KeyEvent] = []
    unassigned = 0
    ambiguous = 0
    for event in key_events:
        frame = int(_attribute(event, "frame_number", "이벤트"))
        candidates = frame_devices.get(frame, set())
        if not candidates:
            unassigned += 1
            continue
        if len(candidates) != 1:
            ambiguous += 1
            continue
        device_alias = next(iter(candidates))
        aps = device_aps[device_alias]
        if len(aps) != 1:
            ambiguous += 1
            continue
        match = _KEY_EVENT_PATTERN.fullmatch(
            str(_attribute(event, "event_type", "이벤트"))
        )
        if match is None:
            raise EapolHandshakeError("EAPOL-Key 이벤트 종류가 변경됐습니다.")
        linked.append(
            _KeyEvent(
                frame_number=frame,
                relative_time_ms=int(
                    _attribute(event, "relative_time_ms", "이벤트")
                ),
                message_number=int(match.group(1), 10),
                retry_flag_observed=frame in retry_frames,
                device_alias=device_alias,
                ap_alias=aps[0],
            )
        )

    grouped: Dict[Tuple[str, str], List[_KeyEvent]] = {}
    for event in linked:
        grouped.setdefault((event.device_alias, event.ap_alias), []).append(event)

    raw_segments: List[Tuple[_KeyEvent, ...]] = []
    for key in sorted(
        grouped,
        key=lambda item: (_alias_sort(item[0]), _alias_sort(item[1])),
    ):
        values = sorted(
            grouped[key],
            key=lambda item: (item.frame_number, item.relative_time_ms),
        )
        raw_segments.extend(_segments(values))
    raw_segments.sort(
        key=lambda items: (
            items[0].frame_number,
            _alias_sort(items[0].device_alias),
            _alias_sort(items[0].ap_alias),
        )
    )
    if len(raw_segments) > _MAX_OBSERVATIONS:
        raise EapolHandshakeError("EAPOL 관찰 수가 안전 제한을 초과했습니다.")

    observations = tuple(
        _freeze_observation("EAPOL-HS-" + str(index), segment)
        for index, segment in enumerate(raw_segments, start=1)
    )
    observation_evidence_complete = all(
        item.evidence_frames_omitted == 0 for item in observations
    )
    linkage_complete = unassigned == 0 and ambiguous == 0
    complete = (
        field_available
        and source_timeline_complete
        and device_report_complete
        and evidence_complete
        and observation_evidence_complete
        and timeline_omitted == 0
        and linkage_complete
    )

    cautions = [
        "M1~M4 번호 순서는 패킷 관찰 결과이며 동일한 한 번의 Handshake를 확정하지 않습니다.",
        "Replay Counter를 사용하지 않으므로 같은 메시지 번호 반복을 실제 재전송으로 확정하지 않습니다.",
        "Nonce·MIC·Key Data와 암호화 키를 읽거나 결과에 기록하지 않습니다.",
        "키 설치·암호학적 성공·전체 무선 접속 성공과 근본 원인은 확정하지 않습니다.",
        "DEVICE-N과 AP-N은 현재 분석 실행에서만 유효합니다.",
    ]
    if not field_available:
        cautions.insert(0, "내장 TShark에서 EAPOL-Key 메시지 번호 필드를 사용할 수 없습니다.")
    if timeline_omitted:
        cautions.insert(0, "상세 이벤트가 일부 생략되어 Key 메시지 순서가 부분 결과일 수 있습니다.")
    if not evidence_complete:
        cautions.insert(0, "단말 근거 프레임이 일부 생략되어 Key 이벤트 연결이 부분 결과입니다.")
    if unassigned:
        cautions.insert(0, "단말 근거가 없는 EAPOL-Key 이벤트는 관찰에 포함하지 않았습니다.")
    if ambiguous:
        cautions.insert(0, "단말 또는 AP 후보가 하나가 아닌 EAPOL-Key 이벤트는 관찰에 포함하지 않았습니다.")

    return EapolHandshakeReport(
        field_available=field_available,
        source_timeline_complete=source_timeline_complete,
        device_report_complete=device_report_complete,
        device_evidence_complete=evidence_complete,
        linkage_complete=linkage_complete,
        complete=complete,
        source_key_events_total=len(key_events),
        linked_key_events=len(linked),
        unassigned_key_events=unassigned,
        ambiguous_key_events=ambiguous,
        timeline_events_omitted=timeline_omitted,
        observations=observations,
        replay_counter_correlation_available=False,
        raw_key_material_serialized=False,
        raw_identifiers_serialized=False,
        same_handshake_confirmed=False,
        key_installation_confirmed=False,
        cryptographic_success_confirmed=False,
        root_cause_confirmed=False,
        cautions=tuple(cautions),
    )
