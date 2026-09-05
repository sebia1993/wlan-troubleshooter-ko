"""Compare EAPOL Replay Counter relationships without serializing values.

The dedicated TShark profile may expose ``eapol.keydes.replay_counter`` only to
this transient parser. Raw counters are converted immediately into equality or
ordering relationships for existing ``EAPOL-HS-N`` observations. Counter
values, key material and raw identifiers are never stored in the returned
models.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Mapping, Optional, Sequence, Set, Tuple

from wlan_troubleshooter_ko.tshark.fields_output import iter_fields_rows
from wlan_troubleshooter_ko.tshark.profiles import ResolvedProfile


_OBSERVATION_PATTERN = re.compile(r"^EAPOL-HS-[1-9][0-9]{0,5}$")
_DEVICE_PATTERN = re.compile(r"^DEVICE-[1-9][0-9]{0,5}$")
_AP_PATTERN = re.compile(r"^AP-[1-9][0-9]{0,5}$")
_MAX_UINT64 = (1 << 64) - 1
_MAX_ROWS = 100_000
_MAX_OBSERVATIONS = 10_000
_MAX_EVIDENCE_FRAMES = 64

_PAIR_RELATIONS = {
    "equal-observed",
    "mismatch-observed",
    "multiple-values-observed",
    "unavailable",
    "not-observed",
}
_PROGRESS_RELATIONS = {
    "increased-observed",
    "equal-observed",
    "decreased-observed",
    "multiple-values-observed",
    "unavailable",
    "not-observed",
}
_REPEATED_RELATIONS = {
    "same-counter-observed",
    "different-counters-observed",
    "unavailable",
}


class EapolReplayRelationError(ValueError):
    """Replay metadata or handshake observations violate safety invariants."""


@dataclass(frozen=True)
class RepeatedCounterRelation:
    message_number: int
    state: str
    evidence_frames: Tuple[int, ...]

    def to_dict(self) -> Dict[str, object]:
        return {
            "message_number": self.message_number,
            "state": self.state,
            "evidence_frames": list(self.evidence_frames),
        }


@dataclass(frozen=True)
class EapolReplayRelationObservation:
    observation_id: str
    device_alias: str
    ap_alias: str
    state: str
    summary_ko: str
    evidence_frames: Tuple[int, ...]
    frames_with_counter: Tuple[int, ...]
    missing_counter_frames: Tuple[int, ...]
    m1_m2_relation: str
    m3_m4_relation: str
    m1_m3_progression: str
    repeated_message_relations: Tuple[RepeatedCounterRelation, ...]
    display_filter: str
    raw_replay_counters_serialized: bool = False
    replay_counter_values_persisted: bool = False
    same_handshake_confirmed: bool = False
    retransmission_confirmed: bool = False
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
            "evidence_frames": list(self.evidence_frames),
            "frames_with_counter": list(self.frames_with_counter),
            "missing_counter_frames": list(self.missing_counter_frames),
            "m1_m2_relation": self.m1_m2_relation,
            "m3_m4_relation": self.m3_m4_relation,
            "m1_m3_progression": self.m1_m3_progression,
            "repeated_message_relations": [
                item.to_dict() for item in self.repeated_message_relations
            ],
            "display_filter": self.display_filter,
            "raw_replay_counters_serialized": self.raw_replay_counters_serialized,
            "replay_counter_values_persisted": self.replay_counter_values_persisted,
            "same_handshake_confirmed": self.same_handshake_confirmed,
            "retransmission_confirmed": self.retransmission_confirmed,
            "key_installation_confirmed": self.key_installation_confirmed,
            "cryptographic_success_confirmed": self.cryptographic_success_confirmed,
            "root_cause_confirmed": self.root_cause_confirmed,
        }


@dataclass(frozen=True)
class EapolReplayRelationReport:
    profile_id: str
    profile_version: str
    field_available: bool
    rows_observed: int
    key_rows_observed: int
    observations_source_total: int
    observations_evaluated: int
    observations: Tuple[EapolReplayRelationObservation, ...]
    complete: bool
    raw_replay_counters_serialized: bool
    replay_counter_values_persisted: bool
    same_handshake_confirmed: bool
    retransmission_confirmed: bool
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
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "field_available": self.field_available,
            "rows_observed": self.rows_observed,
            "key_rows_observed": self.key_rows_observed,
            "observations_source_total": self.observations_source_total,
            "observations_evaluated": self.observations_evaluated,
            "observations_by_state": dict(sorted(state_counts.items())),
            "observations": [item.to_dict() for item in self.observations],
            "complete": self.complete,
            "raw_replay_counters_serialized": self.raw_replay_counters_serialized,
            "replay_counter_values_persisted": self.replay_counter_values_persisted,
            "same_handshake_confirmed": self.same_handshake_confirmed,
            "retransmission_confirmed": self.retransmission_confirmed,
            "key_installation_confirmed": self.key_installation_confirmed,
            "cryptographic_success_confirmed": self.cryptographic_success_confirmed,
            "root_cause_confirmed": self.root_cause_confirmed,
            "cautions": list(self.cautions),
        }


@dataclass(frozen=True)
class _CounterRow:
    frame_number: int
    message_number: int
    counter: Optional[int]


def _attribute(value: object, name: str, label: str) -> object:
    try:
        return getattr(value, name)
    except (AttributeError, TypeError) as exc:
        raise EapolReplayRelationError(label + " 구조가 올바르지 않습니다.") from exc


def _must_be_false(value: object, name: str, label: str) -> None:
    if _attribute(value, name, label) is not False:
        raise EapolReplayRelationError(label + " 보호 플래그는 false여야 합니다.")


def _boolean(value: object, name: str, label: str) -> bool:
    result = _attribute(value, name, label)
    if type(result) is not bool:
        raise EapolReplayRelationError(label + " 상태가 올바르지 않습니다.")
    return result


def _nonnegative(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise EapolReplayRelationError(label + " 값이 올바르지 않습니다.")
    return value


def _positive(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise EapolReplayRelationError(label + " 값이 올바르지 않습니다.")
    return value


def _collection(value: object, name: str, label: str) -> Tuple[object, ...]:
    result = _attribute(value, name, label)
    if not isinstance(result, (tuple, list)):
        raise EapolReplayRelationError(label + " 목록이 올바르지 않습니다.")
    return tuple(result)


def _integer_tuple(
    value: object,
    label: str,
    *,
    minimum: int,
    maximum: int,
    unique_sorted: bool,
) -> Tuple[int, ...]:
    if not isinstance(value, (tuple, list)):
        raise EapolReplayRelationError(label + " 목록이 올바르지 않습니다.")
    result = tuple(value)
    if any(
        type(item) is not int or item < minimum or item > maximum
        for item in result
    ):
        raise EapolReplayRelationError(label + " 값이 허용 범위를 벗어났습니다.")
    if unique_sorted and result != tuple(sorted(set(result))):
        raise EapolReplayRelationError(label + " 목록은 중복 없이 오름차순이어야 합니다.")
    return result


def _parse_uint(value: str, label: str, maximum: int) -> Optional[int]:
    raw = value.strip()
    if not raw:
        return None
    try:
        if raw.casefold().startswith("0x"):
            parsed = int(raw[2:], 16)
        elif raw.isascii() and raw.isdecimal():
            parsed = int(raw, 10)
        else:
            raise ValueError
    except ValueError:
        raise EapolReplayRelationError(label + " 값이 정수 형식이 아닙니다.") from None
    if parsed < 0 or parsed > maximum:
        raise EapolReplayRelationError(label + " 값이 허용 범위를 벗어났습니다.")
    return parsed


def _display_filter(frames: Sequence[int]) -> str:
    return " || ".join("frame.number == {0}".format(value) for value in frames)


def _parse_rows(text: str, profile: ResolvedProfile) -> Tuple[Dict[int, _CounterRow], int]:
    if profile.profile_id != "eapol-replay-relations":
        raise EapolReplayRelationError("Replay Counter 전용 추출 프로파일이 필요합니다.")
    positions = {key: index for index, key in enumerate(profile.output_keys())}
    if "frame_number" not in positions:
        raise EapolReplayRelationError("Replay Counter 프레임 필드가 누락됐습니다.")
    rows: Dict[int, _CounterRow] = {}
    rows_observed = 0
    previous_frame = 0
    for raw_row in iter_fields_rows(text, profile):
        rows_observed += 1
        if rows_observed > _MAX_ROWS:
            raise EapolReplayRelationError("Replay Counter 행 수가 안전 제한을 초과했습니다.")
        frame = _parse_uint(
            raw_row[positions["frame_number"]],
            "Replay Counter 프레임",
            _MAX_UINT64,
        )
        if frame is None or frame <= previous_frame:
            raise EapolReplayRelationError("Replay Counter 프레임 순서가 올바르지 않습니다.")
        previous_frame = frame
        message_value = (
            ""
            if "eapol_key_message" not in positions
            else raw_row[positions["eapol_key_message"]]
        )
        counter_value = (
            ""
            if "eapol_replay_counter" not in positions
            else raw_row[positions["eapol_replay_counter"]]
        )
        message = _parse_uint(message_value, "EAPOL-Key 메시지 번호", 4)
        counter = _parse_uint(counter_value, "EAPOL Replay Counter", _MAX_UINT64)
        if message is None and counter is None:
            continue
        if message is None:
            raise EapolReplayRelationError(
                "메시지 번호 없이 Replay Counter만 관찰됐습니다."
            )
        if message < 1:
            raise EapolReplayRelationError("EAPOL-Key 메시지 번호가 1~4가 아닙니다.")
        if frame in rows:
            raise EapolReplayRelationError("Replay Counter 프레임이 중복됐습니다.")
        rows[frame] = _CounterRow(frame, message, counter)
    return rows, rows_observed


def _pair_relation(
    left_values: Sequence[Optional[int]],
    right_values: Sequence[Optional[int]],
) -> str:
    if not left_values or not right_values:
        return "not-observed"
    if any(value is None for value in (*left_values, *right_values)):
        return "unavailable"
    left_unique = set(left_values)
    right_unique = set(right_values)
    if len(left_unique) != 1 or len(right_unique) != 1:
        return "multiple-values-observed"
    return (
        "equal-observed"
        if next(iter(left_unique)) == next(iter(right_unique))
        else "mismatch-observed"
    )


def _progress_relation(
    first_values: Sequence[Optional[int]],
    later_values: Sequence[Optional[int]],
) -> str:
    if not first_values or not later_values:
        return "not-observed"
    if any(value is None for value in (*first_values, *later_values)):
        return "unavailable"
    first_unique = set(first_values)
    later_unique = set(later_values)
    if len(first_unique) != 1 or len(later_unique) != 1:
        return "multiple-values-observed"
    first = next(iter(first_unique))
    later = next(iter(later_unique))
    if later > first:
        return "increased-observed"
    if later == first:
        return "equal-observed"
    return "decreased-observed"


def _repeated_relations(
    frames: Sequence[int],
    messages: Sequence[int],
    counters: Sequence[Optional[int]],
) -> Tuple[RepeatedCounterRelation, ...]:
    result = []
    for message in (1, 2, 3, 4):
        indexes = [index for index, value in enumerate(messages) if value == message]
        if len(indexes) < 2:
            continue
        values = [counters[index] for index in indexes]
        if any(value is None for value in values):
            state = "unavailable"
        elif len(set(values)) == 1:
            state = "same-counter-observed"
        else:
            state = "different-counters-observed"
        if state not in _REPEATED_RELATIONS:
            raise EapolReplayRelationError("반복 메시지 관계 상태가 올바르지 않습니다.")
        result.append(
            RepeatedCounterRelation(
                message_number=message,
                state=state,
                evidence_frames=tuple(frames[index] for index in indexes),
            )
        )
    return tuple(result)


def _observation_state(
    *,
    field_available: bool,
    omitted: int,
    missing_frames: Sequence[int],
    m1_m2: str,
    m3_m4: str,
    progression: str,
    repeated: Sequence[RepeatedCounterRelation],
) -> Tuple[str, str]:
    if not field_available:
        return (
            "unavailable",
            "내장 TShark에서 Replay Counter 필드를 사용할 수 없어 관계를 평가하지 않았습니다.",
        )
    if omitted or missing_frames:
        return (
            "partial",
            "일부 Key 프레임의 Replay Counter 관계를 확인할 수 없어 부분 결과로 제한합니다.",
        )
    pair_values = (m1_m2, m3_m4)
    if (
        "mismatch-observed" in pair_values
        or progression in {"equal-observed", "decreased-observed"}
        or any(item.state == "different-counters-observed" for item in repeated)
    ):
        return (
            "relation-mismatch-observed",
            "일반적인 M1/M2·M3/M4 동일 관계 또는 후반 Counter 증가와 다른 관계가 관찰됐습니다. 동일 Handshake나 근본 원인은 확정하지 않습니다.",
        )
    if (
        "multiple-values-observed" in pair_values
        or progression == "multiple-values-observed"
    ):
        return (
            "multiple-values-observed",
            "같은 메시지 번호에서 여러 Replay Counter 관계가 관찰돼 하나의 교환으로 단정할 수 없습니다.",
        )
    comparable = [
        value
        for value in (*pair_values, progression)
        if value not in {"not-observed", "unavailable"}
    ]
    if not comparable:
        return (
            "insufficient-events",
            "비교 가능한 M1/M2·M3/M4 또는 M1/M3 메시지 조합이 없습니다.",
        )
    expected = (
        m1_m2 in {"equal-observed", "not-observed"}
        and m3_m4 in {"equal-observed", "not-observed"}
        and progression in {"increased-observed", "not-observed"}
        and all(
            item.state in {"same-counter-observed", "unavailable"}
            for item in repeated
        )
    )
    if expected:
        return (
            "expected-relations-observed",
            "관찰된 메시지에서 M1/M2·M3/M4 동일 관계와 후반 Counter 증가 관계가 확인됐습니다. 동일 Handshake·재전송·키 설치는 확정하지 않습니다.",
        )
    return (
        "partial",
        "일부 Replay Counter 관계만 평가할 수 있습니다.",
    )


def _validate_handshake_report(report: object) -> Tuple[Tuple[object, ...], bool]:
    for name in (
        "raw_key_material_serialized",
        "raw_identifiers_serialized",
        "same_handshake_confirmed",
        "key_installation_confirmed",
        "cryptographic_success_confirmed",
        "root_cause_confirmed",
    ):
        _must_be_false(report, name, "EAPOL 순서 보고서")
    complete = _boolean(report, "complete", "EAPOL 순서 보고서")
    observations = _collection(report, "observations", "EAPOL 순서 보고서")
    if len(observations) > _MAX_OBSERVATIONS:
        raise EapolReplayRelationError("EAPOL 관찰 수가 안전 제한을 초과했습니다.")
    seen = set()
    for observation in observations:
        observation_id = _attribute(observation, "observation_id", "EAPOL 관찰")
        device_alias = _attribute(observation, "device_alias", "EAPOL 관찰")
        ap_alias = _attribute(observation, "ap_alias", "EAPOL 관찰")
        if (
            not isinstance(observation_id, str)
            or _OBSERVATION_PATTERN.fullmatch(observation_id) is None
            or observation_id in seen
        ):
            raise EapolReplayRelationError("EAPOL 관찰 ID가 올바르지 않거나 중복됐습니다.")
        seen.add(observation_id)
        if not isinstance(device_alias, str) or _DEVICE_PATTERN.fullmatch(device_alias) is None:
            raise EapolReplayRelationError("EAPOL 관찰 단말 가명이 올바르지 않습니다.")
        if not isinstance(ap_alias, str) or _AP_PATTERN.fullmatch(ap_alias) is None:
            raise EapolReplayRelationError("EAPOL 관찰 AP 가명이 올바르지 않습니다.")
        for name in (
            "raw_key_material_serialized",
            "raw_identifiers_serialized",
            "same_handshake_confirmed",
            "key_installation_confirmed",
            "cryptographic_success_confirmed",
            "root_cause_confirmed",
        ):
            _must_be_false(observation, name, "EAPOL 관찰")
    return observations, complete


def build_eapol_replay_relations(
    text: str,
    profile: ResolvedProfile,
    handshake_report: object,
) -> EapolReplayRelationReport:
    """Convert transient Replay Counter values into non-secret relationships."""

    counter_rows, rows_observed = _parse_rows(text, profile)
    observations, source_complete = _validate_handshake_report(handshake_report)
    field_available = (
        "eapol_key_message" not in profile.missing_optional_fields
        and "eapol_replay_counter" not in profile.missing_optional_fields
        and "eapol_key_message" in profile.output_keys()
        and "eapol_replay_counter" in profile.output_keys()
    )

    results: List[EapolReplayRelationObservation] = []
    for observation in observations:
        observation_id = str(_attribute(observation, "observation_id", "EAPOL 관찰"))
        device_alias = str(_attribute(observation, "device_alias", "EAPOL 관찰"))
        ap_alias = str(_attribute(observation, "ap_alias", "EAPOL 관찰"))
        frames = _integer_tuple(
            _attribute(observation, "evidence_frames", "EAPOL 관찰"),
            "EAPOL 관찰 근거",
            minimum=1,
            maximum=_MAX_UINT64,
            unique_sorted=True,
        )
        if len(frames) > _MAX_EVIDENCE_FRAMES:
            raise EapolReplayRelationError("EAPOL 관찰 근거 프레임이 안전 상한을 초과했습니다.")
        messages = _integer_tuple(
            _attribute(observation, "observed_message_numbers", "EAPOL 관찰"),
            "EAPOL 관찰 메시지",
            minimum=1,
            maximum=4,
            unique_sorted=False,
        )
        omitted = _nonnegative(
            _attribute(observation, "evidence_frames_omitted", "EAPOL 관찰"),
            "EAPOL 관찰 근거 생략 수",
        )
        event_count = _positive(
            _attribute(observation, "event_count", "EAPOL 관찰"),
            "EAPOL 관찰 이벤트 수",
        )
        if len(messages) != event_count or len(frames) + omitted != event_count:
            raise EapolReplayRelationError("EAPOL 관찰 이벤트·근거 개수가 일치하지 않습니다.")

        if omitted:
            frame_messages = tuple(zip(frames, messages[: len(frames)]))
        else:
            if len(frames) != len(messages):
                raise EapolReplayRelationError("EAPOL 관찰 프레임과 메시지 개수가 일치하지 않습니다.")
            frame_messages = tuple(zip(frames, messages))

        counters: List[Optional[int]] = []
        missing_frames: List[int] = []
        frames_with_counter: List[int] = []
        for frame, expected_message in frame_messages:
            row = counter_rows.get(frame)
            if row is None:
                counters.append(None)
                missing_frames.append(frame)
                continue
            if row.message_number != expected_message:
                raise EapolReplayRelationError(
                    "Replay Counter 메시지 번호가 EAPOL 관찰과 일치하지 않습니다."
                )
            counters.append(row.counter)
            if row.counter is None:
                missing_frames.append(frame)
            else:
                frames_with_counter.append(frame)

        by_message: Dict[int, List[Optional[int]]] = {1: [], 2: [], 3: [], 4: []}
        for (_frame, message), counter in zip(frame_messages, counters):
            by_message[message].append(counter)
        m1_m2 = _pair_relation(by_message[1], by_message[2])
        m3_m4 = _pair_relation(by_message[3], by_message[4])
        progression = _progress_relation(by_message[1], by_message[3])
        if m1_m2 not in _PAIR_RELATIONS or m3_m4 not in _PAIR_RELATIONS:
            raise EapolReplayRelationError("Replay Counter 쌍 관계 상태가 올바르지 않습니다.")
        if progression not in _PROGRESS_RELATIONS:
            raise EapolReplayRelationError("Replay Counter 증가 관계 상태가 올바르지 않습니다.")
        repeated = _repeated_relations(
            tuple(frame for frame, _message in frame_messages),
            tuple(message for _frame, message in frame_messages),
            tuple(counters),
        )
        state, summary = _observation_state(
            field_available=field_available,
            omitted=omitted,
            missing_frames=missing_frames,
            m1_m2=m1_m2,
            m3_m4=m3_m4,
            progression=progression,
            repeated=repeated,
        )
        results.append(
            EapolReplayRelationObservation(
                observation_id=observation_id,
                device_alias=device_alias,
                ap_alias=ap_alias,
                state=state,
                summary_ko=summary,
                evidence_frames=frames,
                frames_with_counter=tuple(frames_with_counter),
                missing_counter_frames=tuple(missing_frames),
                m1_m2_relation=m1_m2,
                m3_m4_relation=m3_m4,
                m1_m3_progression=progression,
                repeated_message_relations=repeated,
                display_filter=_display_filter(frames),
            )
        )

    complete = (
        source_complete
        and field_available
        and len(results) == len(observations)
        and all(item.state not in {"unavailable", "partial"} for item in results)
    )
    cautions = [
        "Replay Counter 원문은 관계 계산 중 메모리에서만 사용하고 결과·로그·파일에 기록하지 않습니다.",
        "M1/M2·M3/M4 동일 관계와 M1→M3 증가가 보여도 동일한 한 번의 Handshake를 확정하지 않습니다.",
        "같은 메시지 번호와 같은 Counter 관계가 반복돼도 실제 재전송을 확정하지 않습니다.",
        "Counter 관계 불일치는 캡처 누락·여러 교환 혼재 가능성을 포함하며 키 설치 실패나 근본 원인을 확정하지 않습니다.",
    ]
    if not field_available:
        cautions.insert(0, "내장 TShark에서 Replay Counter 관계 필드를 사용할 수 없습니다.")
    if not source_complete:
        cautions.insert(0, "EAPOL 메시지 순서 보고서가 일부 결과라 Counter 관계도 일부 결과입니다.")

    return EapolReplayRelationReport(
        profile_id=profile.profile_id,
        profile_version=profile.profile_version,
        field_available=field_available,
        rows_observed=rows_observed,
        key_rows_observed=len(counter_rows),
        observations_source_total=len(observations),
        observations_evaluated=len(results),
        observations=tuple(results),
        complete=complete,
        raw_replay_counters_serialized=False,
        replay_counter_values_persisted=False,
        same_handshake_confirmed=False,
        retransmission_confirmed=False,
        key_installation_confirmed=False,
        cryptographic_success_confirmed=False,
        root_cause_confirmed=False,
        cautions=tuple(cautions),
    )
