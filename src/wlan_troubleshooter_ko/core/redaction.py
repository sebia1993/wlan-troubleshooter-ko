"""로컬 로그에 민감정보가 남지 않도록 하는 보수적 마스킹."""

import ipaddress
import re


_SENSITIVE_HEADER = re.compile(
    r"(?is)[\"']?(authorization|proxy-authorization|cookie|set-cookie)[\"']?"
    r"\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\r\n]*)"
)
_SENSITIVE_VALUE = re.compile(
    r"(?is)[\"']?(password|passwd|token|secret|api[_-]?key|"
    r"user(?:name|_?id)?|identity)[\"']?\s*[:=]\s*"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;}]+)"
)
_EMAIL_PATTERN = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_MAC_PATTERN = re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")
_CISCO_MAC_PATTERN = re.compile(r"(?i)\b(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}\b")
_IPV4_PATTERN = re.compile(
    r"(?<![0-9])(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})"
    r"(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}(?![0-9])"
)
_ABSOLUTE_PATH_PATTERN = re.compile(
    r"(?i)(?<![\w:])(?:[A-Z]:[\\/]|\\\\|//|/)[^\r\n\t,;\"'}]+"
)
_IPV6_CANDIDATE_PATTERN = re.compile(
    r"(?i)(?<![0-9a-f:])[0-9a-f:]{2,}(?![0-9a-f:])"
)
_LONG_HEX_PATTERN = re.compile(r"(?i)\b[0-9a-f]{32,}\b")
_LONG_BASE64_PATTERN = re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b")


def _redact_ipv6(match: re.Match) -> str:
    candidate = match.group(0)
    if ":" not in candidate:
        return candidate
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        return candidate
    return "<IP>" if parsed.version == 6 else candidate


def redact_text(value: object) -> str:
    """헤더, 자격증명, 식별자, 사용자 경로와 긴 원시값을 마스킹한다."""

    text = str(value)
    text = _SENSITIVE_HEADER.sub(lambda match: match.group(1) + "=<REDACTED>", text)
    text = _SENSITIVE_VALUE.sub(lambda match: match.group(1) + "=<REDACTED>", text)
    text = _EMAIL_PATTERN.sub("<USER>", text)
    text = _MAC_PATTERN.sub("<MAC>", text)
    text = _CISCO_MAC_PATTERN.sub("<MAC>", text)
    text = _IPV4_PATTERN.sub("<IP>", text)
    text = _IPV6_CANDIDATE_PATTERN.sub(_redact_ipv6, text)
    text = _ABSOLUTE_PATH_PATTERN.sub("<PATH>", text)
    text = _LONG_HEX_PATTERN.sub("<PAYLOAD>", text)
    text = _LONG_BASE64_PATTERN.sub("<PAYLOAD>", text)
    return text
