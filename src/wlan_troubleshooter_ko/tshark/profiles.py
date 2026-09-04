"""Version-pinned TShark extraction profile loader and compatibility resolver."""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from wlan_troubleshooter_ko.tshark.catalog import FieldCatalog


_ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_FIELD_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
_VERSION_PATTERN = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}(?:-[0-9A-Za-z.-]+)?$")
_MAX_PROFILE_BYTES = 1024 * 1024
_PROFILE_REQUIRED_OUTPUT_KEYS = {
    "protocol-inventory": {
        "frame_number",
        "captured_length",
        "frame_length",
        "protocols",
    },
    "connection-events": {
        "frame_number",
        "time_epoch",
        "captured_length",
        "frame_length",
        "protocols",
    },
    "device-identities": {
        "frame_number",
        "time_epoch",
        "protocols",
    },
    "eapol-replay-relations": {
        "frame_number",
    },
}


class FieldProfileError(ValueError):
    """The extraction profile violates the schema or safety policy."""


class FieldCompatibilityError(RuntimeError):
    """The current TShark does not register a required field."""


@dataclass(frozen=True)
class FieldRequirement:
    output_key: str
    candidates: Tuple[str, ...]
    required: bool


@dataclass(frozen=True)
class ExtractionProfile:
    profile_id: str
    display_filter_name: str
    max_packets: int
    fields: Tuple[FieldRequirement, ...]


@dataclass(frozen=True)
class ProtocolGroup:
    group_id: str
    label_ko: str
    tokens: Tuple[str, ...]


@dataclass(frozen=True)
class FieldProfileRegistry:
    schema_version: int
    profile_version: str
    profiles: Tuple[ExtractionProfile, ...]
    protocol_groups: Tuple[ProtocolGroup, ...]

    def get_profile(self, profile_id: str) -> ExtractionProfile:
        for profile in self.profiles:
            if profile.profile_id == profile_id:
                return profile
        raise FieldProfileError("알 수 없는 추출 프로파일입니다.")


@dataclass(frozen=True)
class ResolvedField:
    output_key: str
    field_name: str


@dataclass(frozen=True)
class ResolvedProfile:
    profile_id: str
    profile_version: str
    display_filter_name: str
    max_packets: int
    fields: Tuple[ResolvedField, ...]
    missing_optional_fields: Tuple[str, ...]

    def headers(self) -> Tuple[str, ...]:
        return tuple(item.field_name for item in self.fields)

    def output_keys(self) -> Tuple[str, ...]:
        return tuple(item.output_key for item in self.fields)


def _reject_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _normalized_text(value: object, label: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or "\x00" in value
    ):
        raise FieldProfileError(label + " 형식이 올바르지 않습니다.")
    normalized = unicodedata.normalize("NFC", value)
    if normalized != value:
        raise FieldProfileError(label + "은 NFC 정규화 문자열이어야 합니다.")
    return value


def _exact_keys(
    value: object,
    expected: Iterable[str],
    label: str,
) -> Dict[str, object]:
    if not isinstance(value, dict) or set(value) != set(expected):
        raise FieldProfileError(label + " 키 구성이 올바르지 않습니다.")
    return value


def _load_json(path: Path) -> Dict[str, object]:
    try:
        if not path.is_file() or path.stat().st_size > _MAX_PROFILE_BYTES:
            raise FieldProfileError("추출 프로파일 파일을 사용할 수 없습니다.")
        raw = path.read_text(encoding="utf-8")
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except FieldProfileError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        raise FieldProfileError(
            "추출 프로파일 JSON을 안전하게 읽을 수 없습니다."
        ) from None
    if not isinstance(value, dict):
        raise FieldProfileError("추출 프로파일 루트는 객체여야 합니다.")
    return value


def load_field_profiles(path: Path) -> FieldProfileRegistry:
    root = _exact_keys(
        _load_json(path),
        ("schema_version", "profile_version", "profiles", "protocol_groups"),
        "추출 프로파일",
    )
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise FieldProfileError("지원하지 않는 추출 프로파일 스키마입니다.")
    profile_version = _normalized_text(root["profile_version"], "프로파일 버전", 64)
    if not _VERSION_PATTERN.fullmatch(profile_version):
        raise FieldProfileError("프로파일 버전 형식이 올바르지 않습니다.")

    raw_profiles = root["profiles"]
    if not isinstance(raw_profiles, list) or not raw_profiles:
        raise FieldProfileError("추출 프로파일 목록이 비어 있습니다.")
    profiles: List[ExtractionProfile] = []
    profile_ids = set()
    for raw_profile in raw_profiles:
        profile_data = _exact_keys(
            raw_profile,
            ("profile_id", "display_filter_name", "max_packets", "fields"),
            "추출 프로파일 항목",
        )
        profile_id = _normalized_text(profile_data["profile_id"], "프로파일 ID", 64)
        filter_name = _normalized_text(
            profile_data["display_filter_name"],
            "필터 이름",
            64,
        )
        if not _ID_PATTERN.fullmatch(profile_id) or not _ID_PATTERN.fullmatch(
            filter_name
        ):
            raise FieldProfileError("프로파일 또는 필터 식별자가 올바르지 않습니다.")
        if profile_id not in _PROFILE_REQUIRED_OUTPUT_KEYS:
            raise FieldProfileError("승인되지 않은 추출 프로파일 ID입니다.")
        if profile_id in profile_ids:
            raise FieldProfileError("추출 프로파일 ID가 중복됐습니다.")
        profile_ids.add(profile_id)
        max_packets = profile_data["max_packets"]
        if type(max_packets) is not int or not 1 <= max_packets <= 500_000:
            raise FieldProfileError("프로파일 패킷 상한이 올바르지 않습니다.")
        raw_fields = profile_data["fields"]
        if not isinstance(raw_fields, list) or not 2 <= len(raw_fields) <= 64:
            raise FieldProfileError("프로파일 필드 목록이 올바르지 않습니다.")
        requirements: List[FieldRequirement] = []
        output_keys = set()
        all_candidates = set()
        for raw_field in raw_fields:
            field_data = _exact_keys(
                raw_field,
                ("output_key", "candidates", "required"),
                "필드 요구사항",
            )
            output_key = _normalized_text(field_data["output_key"], "출력 키", 64)
            if not _KEY_PATTERN.fullmatch(output_key) or output_key in output_keys:
                raise FieldProfileError("출력 키가 올바르지 않거나 중복됐습니다.")
            output_keys.add(output_key)
            candidates_value = field_data["candidates"]
            if (
                not isinstance(candidates_value, list)
                or not 1 <= len(candidates_value) <= 8
            ):
                raise FieldProfileError("필드 후보 목록이 올바르지 않습니다.")
            candidates = []
            for candidate_value in candidates_value:
                candidate = _normalized_text(
                    candidate_value,
                    "TShark 필드명",
                    128,
                )
                if (
                    not _FIELD_PATTERN.fullmatch(candidate)
                    or candidate in candidates
                    or candidate in all_candidates
                ):
                    raise FieldProfileError(
                        "TShark 필드명이 올바르지 않거나 프로파일에서 중복됐습니다."
                    )
                candidates.append(candidate)
                all_candidates.add(candidate)
            required = field_data["required"]
            if type(required) is not bool:
                raise FieldProfileError("필수 필드 표시는 불리언이어야 합니다.")
            requirements.append(
                FieldRequirement(output_key, tuple(candidates), required)
            )
        required_keys = {
            item.output_key for item in requirements if item.required
        }
        expected_required = _PROFILE_REQUIRED_OUTPUT_KEYS[profile_id]
        if not expected_required.issubset(required_keys):
            raise FieldProfileError("추출 프로파일 필수 출력 키가 누락됐습니다.")
        profiles.append(
            ExtractionProfile(
                profile_id,
                filter_name,
                max_packets,
                tuple(requirements),
            )
        )

    if set(profile_ids) != set(_PROFILE_REQUIRED_OUTPUT_KEYS):
        raise FieldProfileError("필수 추출 프로파일 구성이 완전하지 않습니다.")

    raw_groups = root["protocol_groups"]
    if not isinstance(raw_groups, list) or not raw_groups:
        raise FieldProfileError("프로토콜 그룹 목록이 비어 있습니다.")
    groups: List[ProtocolGroup] = []
    group_ids = set()
    claimed_tokens = set()
    for raw_group in raw_groups:
        group_data = _exact_keys(
            raw_group,
            ("group_id", "label_ko", "tokens"),
            "프로토콜 그룹",
        )
        group_id = _normalized_text(
            group_data["group_id"],
            "프로토콜 그룹 ID",
            64,
        )
        label = _normalized_text(
            group_data["label_ko"],
            "프로토콜 그룹 표시명",
            128,
        )
        if not _ID_PATTERN.fullmatch(group_id) or group_id in group_ids:
            raise FieldProfileError(
                "프로토콜 그룹 ID가 올바르지 않거나 중복됐습니다."
            )
        group_ids.add(group_id)
        tokens_value = group_data["tokens"]
        if not isinstance(tokens_value, list) or not 1 <= len(tokens_value) <= 16:
            raise FieldProfileError("프로토콜 토큰 목록이 올바르지 않습니다.")
        tokens = []
        for token_value in tokens_value:
            token = _normalized_text(token_value, "프로토콜 토큰", 128)
            if not _FIELD_PATTERN.fullmatch(token) or token in claimed_tokens:
                raise FieldProfileError(
                    "프로토콜 토큰이 올바르지 않거나 다른 그룹과 중복됐습니다."
                )
            claimed_tokens.add(token)
            tokens.append(token)
        groups.append(ProtocolGroup(group_id, label, tuple(tokens)))

    return FieldProfileRegistry(
        1,
        profile_version,
        tuple(profiles),
        tuple(groups),
    )


def resolve_profile(
    registry: FieldProfileRegistry,
    catalog: FieldCatalog,
    profile_id: str,
) -> ResolvedProfile:
    profile = registry.get_profile(profile_id)
    available = set(catalog.field_names())
    resolved: List[ResolvedField] = []
    missing_required = []
    missing_optional = []
    for requirement in profile.fields:
        selected = next(
            (item for item in requirement.candidates if item in available),
            None,
        )
        if selected is None:
            if requirement.required:
                missing_required.append(requirement.output_key)
            else:
                missing_optional.append(requirement.output_key)
            continue
        resolved.append(ResolvedField(requirement.output_key, selected))
    if missing_required:
        raise FieldCompatibilityError(
            "현재 TShark에 필수 추출 필드가 없습니다: "
            + ", ".join(sorted(missing_required))
        )
    return ResolvedProfile(
        profile_id=profile.profile_id,
        profile_version=registry.profile_version,
        display_filter_name=profile.display_filter_name,
        max_packets=profile.max_packets,
        fields=tuple(resolved),
        missing_optional_fields=tuple(sorted(missing_optional)),
    )
