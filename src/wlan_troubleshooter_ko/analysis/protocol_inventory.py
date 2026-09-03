"""TShark 프레임 메타데이터에서 프로토콜 존재 인벤토리를 생성한다."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from wlan_troubleshooter_ko.tshark.fields_output import FieldsOutputError, iter_fields_rows
from wlan_troubleshooter_ko.tshark.profiles import ProtocolGroup, ResolvedProfile


class ProtocolInventoryError(ValueError):
    """프레임 메타데이터가 인벤토리 규칙을 충족하지 못한 경우."""


@dataclass(frozen=True)
class ProtocolObservation:
    group_id: str
    label_ko: str
    frame_count: int
    first_frame: int
    last_frame: int

    def to_dict(self) -> Dict[str, object]:
        return {
            "group_id": self.group_id,
            "label_ko": self.label_ko,
            "frame_count": self.frame_count,
            "first_frame": self.first_frame,
            "last_frame": self.last_frame,
        }


@dataclass(frozen=True)
class ProtocolInventory:
    profile_id: str
    profile_version: str
    frames_observed: int
    expected_frames: Optional[int]
    complete: bool
    truncated_frames: int
    observations: Tuple[ProtocolObservation, ...]
    not_observed_labels: Tuple[str, ...]
    missing_optional_fields: Tuple[str, ...]
    cautions: Tuple[str, ...]

    def to_dict(self) -> Dict[str, object]:
        return {
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "frames_observed": self.frames_observed,
            "expected_frames": self.expected_frames,
            "complete": self.complete,
            "truncated_frames": self.truncated_frames,
            "observations": [item.to_dict() for item in self.observations],
            "not_observed_labels": list(self.not_observed_labels),
            "missing_optional_fields": list(self.missing_optional_fields),
            "cautions": list(self.cautions),
        }


def _parse_uint(value: str, label: str, *, allow_empty: bool = False) -> Optional[int]:
    if allow_empty and value == "":
        return None
    if not value or not value.isascii() or not value.isdecimal():
        raise ProtocolInventoryError(label + " 값이 음이 아닌 정수가 아닙니다.")
    parsed = int(value, 10)
    if parsed > 2**63 - 1:
        raise ProtocolInventoryError(label + " 값이 허용 범위를 초과했습니다.")
    return parsed


def build_protocol_inventory(
    text: str,
    profile: ResolvedProfile,
    groups: Tuple[ProtocolGroup, ...],
    *,
    expected_frames: Optional[int],
) -> ProtocolInventory:
    """식별자와 Payload 없이 프로토콜 토큰의 프레임 존재만 집계한다."""

    if expected_frames is not None and (
        type(expected_frames) is not int or expected_frames < 0
    ):
        raise ProtocolInventoryError("예상 프레임 수가 올바르지 않습니다.")
    positions = {item.output_key: index for index, item in enumerate(profile.fields)}
    required_keys = {"frame_number", "captured_length", "frame_length", "protocols"}
    if not required_keys.issubset(positions):
        raise ProtocolInventoryError("프로토콜 인벤토리 필수 열이 누락됐습니다.")

    token_to_group: Dict[str, int] = {}
    for index, group in enumerate(groups):
        for token in group.tokens:
            if token in token_to_group:
                raise ProtocolInventoryError("프로토콜 토큰이 여러 그룹에 중복됐습니다.")
            token_to_group[token] = index
    counters = [0 for _group in groups]
    first_frames: list[Optional[int]] = [None for _group in groups]
    last_frames: list[Optional[int]] = [None for _group in groups]
    frames_observed = 0
    truncated = 0
    previous_frame = 0

    try:
        rows = iter_fields_rows(text, profile)
        for row in rows:
            frame_number_value = _parse_uint(row[positions["frame_number"]], "프레임 번호")
            captured_length_value = _parse_uint(row[positions["captured_length"]], "캡처 길이")
            frame_length_value = _parse_uint(row[positions["frame_length"]], "프레임 길이")
            assert frame_number_value is not None
            assert captured_length_value is not None
            assert frame_length_value is not None
            if frame_number_value <= previous_frame or frame_number_value == 0:
                raise ProtocolInventoryError("프레임 번호가 엄격한 증가 순서가 아닙니다.")
            if captured_length_value > frame_length_value:
                raise ProtocolInventoryError("캡처 길이가 프레임 길이보다 큽니다.")
            previous_frame = frame_number_value
            frames_observed += 1
            truncated += int(captured_length_value < frame_length_value)

            tokens = {
                token.strip().casefold()
                for token in row[positions["protocols"]].split(":")
                if token.strip()
            }
            seen_groups = {token_to_group[token] for token in tokens if token in token_to_group}
            for index in seen_groups:
                counters[index] += 1
                if first_frames[index] is None:
                    first_frames[index] = frame_number_value
                last_frames[index] = frame_number_value
    except FieldsOutputError as exc:
        raise ProtocolInventoryError(str(exc)) from exc

    if expected_frames is not None and frames_observed > expected_frames:
        raise ProtocolInventoryError("관찰 프레임 수가 사전 점검 프레임 수보다 큽니다.")
    observations = []
    not_observed = []
    for index, group in enumerate(groups):
        if counters[index]:
            observations.append(
                ProtocolObservation(
                    group_id=group.group_id,
                    label_ko=group.label_ko,
                    frame_count=counters[index],
                    first_frame=first_frames[index] or 0,
                    last_frame=last_frames[index] or 0,
                )
            )
        else:
            not_observed.append(group.label_ko)

    complete = expected_frames is not None and frames_observed == expected_frames
    cautions = ["프로토콜 존재는 해당 접속 단계의 성공 또는 실패를 의미하지 않습니다."]
    if expected_frames is None:
        cautions.append("Phase 2A 전체 프레임 수가 확정되지 않아 인벤토리 완전성을 판단할 수 없습니다.")
    elif frames_observed < expected_frames:
        cautions.append("프로파일 패킷 상한 또는 TShark 처리 결과 때문에 일부 프레임만 관찰됐습니다.")
    if not_observed:
        cautions.append("관찰되지 않은 프로토콜은 캡처 위치·시간·방향 때문에 누락됐을 수 있습니다.")
    if truncated:
        cautions.append("잘린 프레임이 있어 상위 프로토콜 식별이 불완전할 수 있습니다.")
    if profile.missing_optional_fields:
        cautions.append("선택 필드 일부가 현재 TShark에 없어 해당 정보는 판단할 수 없습니다.")

    return ProtocolInventory(
        profile_id=profile.profile_id,
        profile_version=profile.profile_version,
        frames_observed=frames_observed,
        expected_frames=expected_frames,
        complete=complete,
        truncated_frames=truncated,
        observations=tuple(observations),
        not_observed_labels=tuple(not_observed),
        missing_optional_fields=profile.missing_optional_fields,
        cautions=tuple(cautions),
    )
