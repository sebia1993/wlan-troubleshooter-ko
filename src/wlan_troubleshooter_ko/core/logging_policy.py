"""민감 필드를 거부하고 마스킹한 구조화 로그 레코드 생성."""

import re
from typing import Any, Dict

from wlan_troubleshooter_ko.core.canonical_json import dumps
from wlan_troubleshooter_ko.core.redaction import redact_text


_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_VERSION_PATTERN = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}(?:-[0-9A-Za-z.-]+)?$")
_ERROR_CODE_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
_ALLOWED_STATUS = {
    "ok",
    "cancelled",
    "rejected",
    "error",
    "integrity_verified",
    "ready",
    "not_provisioned",
    "integrity_error",
}
_ALLOWED_EVENTS = {
    "application.started",
    "application.stopped",
    "analysis.error",
    "analysis.started",
    "capture.cancelled",
    "capture.rejected",
    "capture.validated",
    "capture.validation_started",
    "tshark.probe",
    "tshark.status",
}
_ALLOWED_FIELDS = {
    "status",
    "size_bytes",
    "input_sha256",
    "ruleset_version",
    "tshark_version",
    "error_code",
}


class UnsafeLogRecord(ValueError):
    """허용 목록 밖의 로그 필드가 요청된 경우."""


def build_log_record(event: str, **fields: Any) -> str:
    """허용된 메타데이터만 남긴 결정론적 JSON Lines 레코드를 만든다."""

    if not isinstance(event, str) or event not in _ALLOWED_EVENTS:
        raise UnsafeLogRecord("허용 목록에 등록된 이벤트 식별자만 사용할 수 있습니다.")
    unknown = set(fields) - _ALLOWED_FIELDS
    if unknown:
        raise UnsafeLogRecord("허용되지 않은 로그 필드가 포함됐습니다.")

    record: Dict[str, Any] = {"event": event}
    for key, value in fields.items():
        if key == "size_bytes":
            if type(value) is not int or value < 0:
                raise UnsafeLogRecord("파일 크기는 0 이상의 정수여야 합니다.")
            record[key] = value
            continue
        if key == "input_sha256":
            if not isinstance(value, str) or not _SHA256_PATTERN.fullmatch(value):
                raise UnsafeLogRecord("입력 SHA-256 형식이 올바르지 않습니다.")
            record[key] = value
            continue
        if key == "status":
            if not isinstance(value, str) or value not in _ALLOWED_STATUS:
                raise UnsafeLogRecord("로그 상태 값이 허용 목록에 없습니다.")
        elif key in {"ruleset_version", "tshark_version"}:
            if not isinstance(value, str) or not _VERSION_PATTERN.fullmatch(value):
                raise UnsafeLogRecord("로그 버전 값 형식이 올바르지 않습니다.")
        elif key == "error_code":
            if not isinstance(value, str) or not _ERROR_CODE_PATTERN.fullmatch(value):
                raise UnsafeLogRecord("로그 오류 코드 형식이 올바르지 않습니다.")
        else:
            raise UnsafeLogRecord("로그 필드 정책이 정의되지 않았습니다.")
        record[key] = redact_text(value)
    return dumps(record)
