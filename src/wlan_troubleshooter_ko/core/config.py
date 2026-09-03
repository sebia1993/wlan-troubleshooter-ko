"""규칙·메시지 골격의 실패-폐쇄형 검증."""

import json
import math
import re
from pathlib import Path
from typing import Any, Dict, Set

from wlan_troubleshooter_ko.core.canonical_json import CanonicalJsonError, dumps, normalize


_RULE_ID = re.compile(r"^[A-Z][A-Z0-9-]{2,63}$")
_MESSAGE_ID = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")
_CLASSIFICATION_ORDER = ["확정", "유력", "참고", "판단 불가"]
_CLASSIFICATIONS = set(_CLASSIFICATION_ORDER)


class ConfigurationError(ValueError):
    """리소스가 선언된 스키마를 충족하지 못한 경우."""


def _reject_non_finite(value: str) -> None:
    raise ValueError("non-finite JSON number: " + value)


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("out-of-range JSON number: " + value)
    return parsed


def _reject_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key: " + key)
        value[key] = item
    return value


def _read_object(path: Path) -> Dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
        value = normalize(
            json.loads(
                raw,
                parse_constant=_reject_non_finite,
                parse_float=_parse_finite_float,
                object_pairs_hook=_reject_duplicate_keys,
            )
        )
        dumps(value)
    except (OSError, UnicodeError, ValueError, CanonicalJsonError) as exc:
        raise ConfigurationError("JSON 리소스를 안전하게 읽을 수 없습니다.") from exc
    if not isinstance(value, dict):
        raise ConfigurationError("JSON 리소스의 최상위 값은 객체여야 합니다.")
    return value


def load_ruleset(path: Path) -> Dict[str, Any]:
    value = _read_object(path)
    if set(value) != {"schema_version", "ruleset_version", "classifications", "rules"}:
        raise ConfigurationError("규칙 파일에 알 수 없거나 누락된 최상위 필드가 있습니다.")
    if type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise ConfigurationError("지원하지 않는 규칙 스키마입니다.")
    if not isinstance(value.get("ruleset_version"), str) or not value["ruleset_version"]:
        raise ConfigurationError("규칙 버전이 필요합니다.")
    classifications = value.get("classifications")
    if (
        not isinstance(classifications, list)
        or classifications != _CLASSIFICATION_ORDER
    ):
        raise ConfigurationError("판정 등급 집합이 올바르지 않습니다.")
    rules = value.get("rules")
    if not isinstance(rules, list):
        raise ConfigurationError("rules는 배열이어야 합니다.")

    identifiers: Set[str] = set()
    for rule in rules:
        if not isinstance(rule, dict):
            raise ConfigurationError("각 규칙은 객체여야 합니다.")
        if set(rule) != {"id", "classification", "conditions", "exclusions"}:
            raise ConfigurationError("규칙에 알 수 없거나 누락된 필드가 있습니다.")
        identifier = rule.get("id")
        if not isinstance(identifier, str) or not _RULE_ID.fullmatch(identifier):
            raise ConfigurationError("규칙 ID 형식이 올바르지 않습니다.")
        if identifier in identifiers:
            raise ConfigurationError("중복 규칙 ID가 있습니다.")
        identifiers.add(identifier)
        if rule.get("classification") not in _CLASSIFICATIONS:
            raise ConfigurationError("알 수 없는 판정 등급입니다.")
        conditions = rule.get("conditions", {})
        exclusions = rule.get("exclusions", {})
        if not isinstance(conditions, dict) or not isinstance(exclusions, dict):
            raise ConfigurationError("조건과 제외 조건은 객체여야 합니다.")
        if any(key in exclusions and exclusions[key] == value for key, value in conditions.items()):
            raise ConfigurationError("같은 사실을 요구하고 제외하는 충돌 규칙입니다.")
    return value


def load_messages(path: Path) -> Dict[str, Any]:
    value = _read_object(path)
    if set(value) != {"schema_version", "catalog_version", "locale", "messages"}:
        raise ConfigurationError("메시지 파일에 알 수 없거나 누락된 필드가 있습니다.")
    if (
        type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or not isinstance(value.get("catalog_version"), str)
        or not value["catalog_version"]
        or value.get("locale") != "ko-KR"
    ):
        raise ConfigurationError("지원하지 않는 한국어 메시지 스키마입니다.")
    messages = value.get("messages")
    if not isinstance(messages, dict) or not messages or not all(
        isinstance(key, str)
        and bool(_MESSAGE_ID.fullmatch(key))
        and isinstance(message, str)
        and bool(message.strip())
        and any("가" <= character <= "힣" for character in message)
        for key, message in messages.items()
    ):
        raise ConfigurationError("messages는 문자열 키와 값으로 구성돼야 합니다.")
    return value


def load_example_profile(path: Path) -> Dict[str, Any]:
    value = _read_object(path)
    expected = {
        "schema_version",
        "profile_version",
        "profile_id",
        "display_name",
        "synthetic",
        "radius_servers",
        "dhcp_servers",
        "dns_servers",
        "vlans",
    }
    if (
        set(value) != expected
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or not isinstance(value.get("profile_version"), str)
        or not value["profile_version"]
    ):
        raise ConfigurationError("예시 프로파일 스키마가 올바르지 않습니다.")
    if value.get("synthetic") is not True:
        raise ConfigurationError("커밋 가능한 프로파일은 합성 예시여야 합니다.")
    if not isinstance(value.get("profile_id"), str) or not value["profile_id"].startswith(
        "SYNTHETIC-"
    ):
        raise ConfigurationError("합성 프로파일 ID가 필요합니다.")
    if not isinstance(value.get("display_name"), str) or not value["display_name"]:
        raise ConfigurationError("예시 프로파일 표시 이름이 필요합니다.")
    for key in ("radius_servers", "dhcp_servers", "dns_servers", "vlans"):
        if value.get(key) != []:
            raise ConfigurationError("공개 예시 프로파일에는 사이트 값을 넣을 수 없습니다.")
    return value
