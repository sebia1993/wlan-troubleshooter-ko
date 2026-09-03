"""동일 입력에 동일 바이트를 만드는 JSON 직렬화."""

import json
from pathlib import Path
import unicodedata
from typing import Any, Dict


class CanonicalJsonError(ValueError):
    """결정론적으로 직렬화할 수 없는 값이 포함된 경우."""


def normalize(value: Any) -> Any:
    """문자열을 NFC로 고정하고 JSON 호환 컨테이너를 재귀 정규화한다."""

    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, (list, tuple)):
        return [normalize(item) for item in value]
    if isinstance(value, dict):
        normalized: Dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalJsonError("JSON 객체 키는 문자열이어야 합니다.")
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized:
                raise CanonicalJsonError("유니코드 정규화 후 중복되는 JSON 키가 있습니다.")
            normalized[normalized_key] = normalize(item)
        return normalized
    raise CanonicalJsonError("지원하지 않는 JSON 값 형식입니다.")


def dumps(value: Any) -> str:
    """키 순서와 공백을 고정한 UTF-8 JSON 문자열을 반환한다."""

    try:
        rendered = json.dumps(
            normalize(value),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalJsonError(str(exc)) from exc
    result = rendered + "\n"
    try:
        result.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise CanonicalJsonError("UTF-8로 표현할 수 없는 문자열이 포함돼 있습니다.") from exc
    return result


def dump_file(path: Path, value: Any) -> None:
    """결정론적 JSON을 새 로컬 파일에 기록한다."""

    payload = dumps(value).encode("utf-8", errors="strict")
    path.write_bytes(payload)
