"""식별정보 없는 프로토콜 이벤트 타임라인과 보수적인 단계 관찰 요약."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from wlan_troubleshooter_ko.tshark.fields_output import FieldsOutputError, iter_fields_rows
from wlan_troubleshooter_ko.tshark.profiles import ResolvedProfile


_MAX_INTEGER = 2**63 - 1
_DEFAULT_MAX_RETAINED_EVENTS = 2000
_MAX_EVIDENCE_FRAMES = 12


class EventTimelineError(ValueError):
    """TShark 메타데이터가 안전한 이벤트 타임라인 형식과 다른 경우."""


@dataclass(frozen=True)
class ProtocolEvent:
    frame_number: int
    relative_time_ms: int
    category: str
    event_type: str
    label_ko: str
    outcome: str
    code: Optional[int]
    correlation_alias: Optional[str]
    evidence_filter: str
    details: Tuple[Tuple[str, str], ...]

    def to_dict(self) -> Dict[str, object]:
        return {
            "frame_number": self.frame_number,
            "relative_time_ms": self.relative_time_ms,
            "category": self.category,
            "event_type": self.event_type,
            "label_ko": self.label_ko,
            "outcome": self.outcome,
            "code": self.code,
            "correlation_alias": self.correlation_alias,
            "evidence_filter": self.evidence_filter,
            "details": {key: value for key, value in self.details},
        }


@dataclass(frozen=True)
class EventTypeSummary:
    event_type: str
    label_ko: str
    count: int
    first_frame: int
    last_frame: int
    outcomes: Tuple[str, ...]
    evidence_frames: Tuple[int, ...]

    def to_dict(self) -> Dict[str, object]:
        return {
            "event_type": self.event_type,
            "label_ko": self.label_ko,
            "count": self.count,
            "first_frame": self.first_frame,
            "last_frame": self.last_frame,
            "outcomes": list(self.outcomes),
            "evidence_frames": list(self.evidence_frames),
        }


@dataclass(frozen=True)
class StageAssessment:
    stage_id: str
    label_ko: str
    state: str
    summary_ko: str
    evidence_frames: Tuple[int, ...]

    def to_dict(self) -> Dict[str, object]:
        return {
            "stage_id": self.stage_id,
            "label_ko": self.label_ko,
            "state": self.state,
            "summary_ko": self.summary_ko,
            "evidence_frames": list(self.evidence_frames),
        }


@dataclass(frozen=True)
class EventTimeline:
    profile_id: str
    profile_version: str
    frames_observed: int
    expected_frames: Optional[int]
    complete: bool
    events_total: int
    events_retained: int
    events_omitted: int
    events: Tuple[ProtocolEvent, ...]
    summaries: Tuple[EventTypeSummary, ...]
    stages: Tuple[StageAssessment, ...]
    missing_optional_fields: Tuple[str, ...]
    cautions: Tuple[str, ...]

    def to_dict(self) -> Dict[str, object]:
        return {
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "frames_observed": self.frames_observed,
            "expected_frames": self.expected_frames,
            "complete": self.complete,
            "events_total": self.events_total,
            "events_retained": self.events_retained,
            "events_omitted": self.events_omitted,
            "events": [item.to_dict() for item in self.events],
            "summaries": [item.to_dict() for item in self.summaries],
            "stages": [item.to_dict() for item in self.stages],
            "missing_optional_fields": list(self.missing_optional_fields),
            "cautions": list(self.cautions),
        }


class _SummaryAccumulator:
    def __init__(self, event_type: str, label_ko: str, frame_number: int, outcome: str) -> None:
        self.event_type = event_type
        self.label_ko = label_ko
        self.count = 1
        self.first_frame = frame_number
        self.last_frame = frame_number
        self.outcomes: Set[str] = {outcome}
        self.evidence_frames: List[int] = [frame_number]

    def add(self, frame_number: int, outcome: str) -> None:
        self.count += 1
        self.last_frame = frame_number
        self.outcomes.add(outcome)
        if len(self.evidence_frames) < _MAX_EVIDENCE_FRAMES:
            self.evidence_frames.append(frame_number)

    def freeze(self) -> EventTypeSummary:
        return EventTypeSummary(
            event_type=self.event_type,
            label_ko=self.label_ko,
            count=self.count,
            first_frame=self.first_frame,
            last_frame=self.last_frame,
            outcomes=tuple(sorted(self.outcomes)),
            evidence_frames=tuple(self.evidence_frames),
        )


class _AliasRegistry:
    """캡처 내부 거래 번호를 원문이 아닌 순번 별칭으로 바꾼다."""

    def __init__(self) -> None:
        self._values: Dict[str, Dict[str, str]] = {}

    def alias(self, category: str, raw_value: str) -> Optional[str]:
        value = raw_value.strip()
        if not value:
            return None
        if len(value) > 256 or any(ord(character) == 0 for character in value):
            raise EventTimelineError("프로토콜 상관 값이 안전 제한을 벗어났습니다.")
        category_values = self._values.setdefault(category, {})
        existing = category_values.get(value)
        if existing is not None:
            return existing
        alias = category.upper() + "-" + str(len(category_values) + 1)
        category_values[value] = alias
        return alias


def _parse_uint(value: str, label: str) -> Optional[int]:
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
        raise EventTimelineError(label + " 값이 지원하는 정수 형식이 아닙니다.") from None
    if parsed < 0 or parsed > _MAX_INTEGER:
        raise EventTimelineError(label + " 값이 허용 범위를 벗어났습니다.")
    return parsed


def _parse_bool(value: str, label: str) -> Optional[bool]:
    raw = value.strip().casefold()
    if not raw:
        return None
    if raw in {"1", "true", "yes", "set"}:
        return True
    if raw in {"0", "false", "no", "unset"}:
        return False
    parsed = _parse_uint(value, label)
    if parsed is not None:
        return parsed != 0
    raise EventTimelineError(label + " 값이 지원하는 불리언 형식이 아닙니다.")


def _parse_epoch_microseconds(value: str) -> int:
    raw = value.strip()
    if not raw or raw.startswith(("+", "-")):
        raise EventTimelineError("프레임 시간이 올바른 양수 epoch 형식이 아닙니다.")
    whole, separator, fraction = raw.partition(".")
    if not whole.isascii() or not whole.isdecimal():
        raise EventTimelineError("프레임 시간이 올바른 epoch 형식이 아닙니다.")
    if separator and (not fraction or not fraction.isascii() or not fraction.isdecimal()):
        raise EventTimelineError("프레임 시간의 소수부가 올바르지 않습니다.")
    if len(whole) > 15 or len(fraction) > 18:
        raise EventTimelineError("프레임 시간이 안전 범위를 벗어났습니다.")
    microseconds = int(whole, 10) * 1_000_000
    microseconds += int((fraction + "000000")[:6] or "0", 10)
    if microseconds > _MAX_INTEGER:
        raise EventTimelineError("프레임 시간이 허용 범위를 벗어났습니다.")
    return microseconds


def _value(row: Tuple[str, ...], positions: Dict[str, int], key: str) -> str:
    position = positions.get(key)
    return "" if position is None else row[position]


def _detail_pairs(**values: Optional[int]) -> Tuple[Tuple[str, str], ...]:
    return tuple(
        (key, str(value))
        for key, value in values.items()
        if value is not None
    )


def _event(
    frame_number: int,
    relative_time_ms: int,
    category: str,
    event_type: str,
    label_ko: str,
    outcome: str = "observed",
    code: Optional[int] = None,
    correlation_alias: Optional[str] = None,
    details: Tuple[Tuple[str, str], ...] = (),
) -> ProtocolEvent:
    return ProtocolEvent(
        frame_number=frame_number,
        relative_time_ms=relative_time_ms,
        category=category,
        event_type=event_type,
        label_ko=label_ko,
        outcome=outcome,
        code=code,
        correlation_alias=correlation_alias,
        evidence_filter="frame.number == " + str(frame_number),
        details=details,
    )


def _wlan_events(
    row: Tuple[str, ...],
    positions: Dict[str, int],
    frame_number: int,
    relative_time_ms: int,
    tokens: Set[str],
) -> List[ProtocolEvent]:
    if not ({"wlan", "wlan_radio"} & tokens):
        return []
    result: List[ProtocolEvent] = []
    subtype = _parse_uint(_value(row, positions, "wlan_type_subtype"), "802.11 프레임 유형")
    status = _parse_uint(_value(row, positions, "wlan_status_code"), "802.11 상태 코드")
    reason = _parse_uint(_value(row, positions, "wlan_reason_code"), "802.11 종료 사유 코드")
    auth_algorithm = _parse_uint(
        _value(row, positions, "wlan_auth_algorithm"),
        "802.11 인증 알고리즘",
    )
    auth_sequence = _parse_uint(
        _value(row, positions, "wlan_auth_sequence"),
        "802.11 인증 순번",
    )

    if subtype == 0:
        result.append(_event(frame_number, relative_time_ms, "wlan", "wlan_assoc_request", "802.11 연결 요청"))
    elif subtype == 1:
        outcome = "success" if status == 0 else "failure" if status is not None else "observed"
        event_type = "wlan_assoc_response_success" if status == 0 else "wlan_assoc_response_rejected" if status is not None else "wlan_assoc_response"
        label = "802.11 연결 응답 성공" if status == 0 else "802.11 연결 응답 거절" if status is not None else "802.11 연결 응답"
        result.append(_event(frame_number, relative_time_ms, "wlan", event_type, label, outcome, status, details=_detail_pairs(status_code=status)))
    elif subtype == 2:
        result.append(_event(frame_number, relative_time_ms, "wlan", "wlan_reassoc_request", "802.11 재연결 요청"))
    elif subtype == 3:
        outcome = "success" if status == 0 else "failure" if status is not None else "observed"
        event_type = "wlan_reassoc_response_success" if status == 0 else "wlan_reassoc_response_rejected" if status is not None else "wlan_reassoc_response"
        label = "802.11 재연결 응답 성공" if status == 0 else "802.11 재연결 응답 거절" if status is not None else "802.11 재연결 응답"
        result.append(_event(frame_number, relative_time_ms, "wlan", event_type, label, outcome, status, details=_detail_pairs(status_code=status)))
    elif subtype == 10:
        result.append(_event(frame_number, relative_time_ms, "wlan", "wlan_disassociation", "802.11 연결 해제 프레임", "warning", reason, details=_detail_pairs(reason_code=reason)))
    elif subtype == 11:
        if auth_sequence == 1:
            event_type = "wlan_auth_request"
            label = "802.11 인증 요청"
            outcome = "observed"
        elif auth_sequence == 2 and status == 0:
            event_type = "wlan_auth_response_success"
            label = "802.11 인증 응답 성공"
            outcome = "success"
        elif auth_sequence == 2 and status is not None:
            event_type = "wlan_auth_response_rejected"
            label = "802.11 인증 응답 거절"
            outcome = "failure"
        else:
            event_type = "wlan_auth_frame"
            label = "802.11 인증 프레임"
            outcome = "observed"
        result.append(
            _event(
                frame_number,
                relative_time_ms,
                "wlan",
                event_type,
                label,
                outcome,
                status,
                details=_detail_pairs(
                    auth_algorithm=auth_algorithm,
                    auth_sequence=auth_sequence,
                    status_code=status,
                ),
            )
        )
    elif subtype == 12:
        result.append(_event(frame_number, relative_time_ms, "wlan", "wlan_deauthentication", "802.11 인증 해제 프레임", "warning", reason, details=_detail_pairs(reason_code=reason)))

    retry = _parse_bool(_value(row, positions, "wlan_retry"), "802.11 Retry 비트")
    if retry:
        result.append(_event(frame_number, relative_time_ms, "wlan", "wlan_retry_flag", "802.11 Retry 비트 설정 프레임", "warning"))
    return result


def _eapol_events(
    row: Tuple[str, ...],
    positions: Dict[str, int],
    frame_number: int,
    relative_time_ms: int,
    tokens: Set[str],
) -> List[ProtocolEvent]:
    if not ({"eapol", "wlan_rsna_eapol"} & tokens):
        return []
    eapol_type = _parse_uint(_value(row, positions, "eapol_type"), "EAPOL 유형")
    message = _parse_uint(_value(row, positions, "eapol_key_message"), "EAPOL-Key 메시지 번호")
    if eapol_type == 1:
        return [_event(frame_number, relative_time_ms, "eapol", "eapol_start", "EAPOL Start")]
    if eapol_type == 2:
        return [_event(frame_number, relative_time_ms, "eapol", "eapol_logoff", "EAPOL Logoff", "warning")]
    if eapol_type == 3 and message in {1, 2, 3, 4}:
        return [
            _event(
                frame_number,
                relative_time_ms,
                "eapol",
                "eapol_key_message_" + str(message),
                "4-Way Handshake 메시지 " + str(message),
                details=_detail_pairs(message_number=message),
            )
        ]
    if eapol_type == 3:
        return [_event(frame_number, relative_time_ms, "eapol", "eapol_key_frame", "EAPOL-Key 프레임")]
    if eapol_type == 0 and "eap" not in tokens:
        return [_event(frame_number, relative_time_ms, "eapol", "eapol_packet", "EAPOL 인증 패킷")]
    return []


def _eap_events(
    row: Tuple[str, ...],
    positions: Dict[str, int],
    frame_number: int,
    relative_time_ms: int,
    tokens: Set[str],
    aliases: _AliasRegistry,
) -> List[ProtocolEvent]:
    if "eap" not in tokens:
        return []
    code = _parse_uint(_value(row, positions, "eap_code"), "EAP 코드")
    eap_type = _parse_uint(_value(row, positions, "eap_type"), "EAP 방식")
    alias = aliases.alias("eap", _value(row, positions, "eap_identifier"))
    mapping = {
        1: ("eap_request", "EAP 요청", "observed"),
        2: ("eap_response", "EAP 응답", "observed"),
        3: ("eap_success", "EAP 성공", "success"),
        4: ("eap_failure", "EAP 실패", "failure"),
    }
    event_type, label, outcome = mapping.get(code, ("eap_message", "EAP 메시지", "observed"))
    return [
        _event(
            frame_number,
            relative_time_ms,
            "eap",
            event_type,
            label,
            outcome,
            code,
            alias,
            _detail_pairs(eap_code=code, eap_type=eap_type),
        )
    ]


def _radius_events(
    row: Tuple[str, ...],
    positions: Dict[str, int],
    frame_number: int,
    relative_time_ms: int,
    tokens: Set[str],
    aliases: _AliasRegistry,
) -> List[ProtocolEvent]:
    if "radius" not in tokens:
        return []
    code = _parse_uint(_value(row, positions, "radius_code"), "RADIUS 코드")
    alias = aliases.alias("radius", _value(row, positions, "radius_identifier"))
    mapping = {
        1: ("radius_access_request", "RADIUS Access-Request", "observed"),
        2: ("radius_access_accept", "RADIUS Access-Accept", "success"),
        3: ("radius_access_reject", "RADIUS Access-Reject", "failure"),
        4: ("radius_accounting_request", "RADIUS Accounting-Request", "observed"),
        5: ("radius_accounting_response", "RADIUS Accounting-Response", "observed"),
        11: ("radius_access_challenge", "RADIUS Access-Challenge", "observed"),
        12: ("radius_status_server", "RADIUS Status-Server", "observed"),
    }
    event_type, label, outcome = mapping.get(code, ("radius_message", "RADIUS 메시지", "observed"))
    return [_event(frame_number, relative_time_ms, "radius", event_type, label, outcome, code, alias, _detail_pairs(radius_code=code))]


def _dhcp_events(
    row: Tuple[str, ...],
    positions: Dict[str, int],
    frame_number: int,
    relative_time_ms: int,
    tokens: Set[str],
    aliases: _AliasRegistry,
) -> List[ProtocolEvent]:
    if not ({"dhcp", "bootp"} & tokens):
        return []
    code = _parse_uint(_value(row, positions, "dhcp_message_type"), "DHCP 메시지 유형")
    alias = aliases.alias("dhcp", _value(row, positions, "dhcp_transaction_id"))
    mapping = {
        1: ("dhcp_discover", "DHCP Discover", "observed"),
        2: ("dhcp_offer", "DHCP Offer", "observed"),
        3: ("dhcp_request", "DHCP Request", "observed"),
        4: ("dhcp_decline", "DHCP Decline", "warning"),
        5: ("dhcp_ack", "DHCP ACK", "success"),
        6: ("dhcp_nak", "DHCP NAK", "failure"),
        7: ("dhcp_release", "DHCP Release", "observed"),
        8: ("dhcp_inform", "DHCP Inform", "observed"),
    }
    event_type, label, outcome = mapping.get(code, ("dhcp_message", "DHCP 메시지", "observed"))
    return [_event(frame_number, relative_time_ms, "dhcp", event_type, label, outcome, code, alias, _detail_pairs(message_type=code))]


def _dns_events(
    row: Tuple[str, ...],
    positions: Dict[str, int],
    frame_number: int,
    relative_time_ms: int,
    tokens: Set[str],
    aliases: _AliasRegistry,
) -> List[ProtocolEvent]:
    if "dns" not in tokens:
        return []
    response = _parse_bool(_value(row, positions, "dns_is_response"), "DNS 응답 플래그")
    rcode = _parse_uint(_value(row, positions, "dns_response_code"), "DNS 응답 코드")
    alias = aliases.alias("dns", _value(row, positions, "dns_identifier"))
    if response is False:
        return [_event(frame_number, relative_time_ms, "dns", "dns_query", "DNS 질의", correlation_alias=alias)]
    if response is True and rcode == 0:
        return [_event(frame_number, relative_time_ms, "dns", "dns_response_success", "DNS 정상 응답", "success", rcode, alias, _detail_pairs(response_code=rcode))]
    if response is True:
        return [_event(frame_number, relative_time_ms, "dns", "dns_response_error", "DNS 오류 응답", "failure", rcode, alias, _detail_pairs(response_code=rcode))]
    return [_event(frame_number, relative_time_ms, "dns", "dns_message", "DNS 메시지", correlation_alias=alias)]


def _arp_events(
    row: Tuple[str, ...],
    positions: Dict[str, int],
    frame_number: int,
    relative_time_ms: int,
    tokens: Set[str],
) -> List[ProtocolEvent]:
    if "arp" not in tokens:
        return []
    opcode = _parse_uint(_value(row, positions, "arp_opcode"), "ARP Opcode")
    if opcode == 1:
        return [_event(frame_number, relative_time_ms, "arp", "arp_request", "ARP 요청", code=opcode)]
    if opcode == 2:
        return [_event(frame_number, relative_time_ms, "arp", "arp_reply", "ARP 응답", "success", opcode)]
    return [_event(frame_number, relative_time_ms, "arp", "arp_message", "ARP 메시지", code=opcode)]


def _tcp_events(
    row: Tuple[str, ...],
    positions: Dict[str, int],
    frame_number: int,
    relative_time_ms: int,
    tokens: Set[str],
    aliases: _AliasRegistry,
) -> List[ProtocolEvent]:
    if "tcp" not in tokens:
        return []
    result: List[ProtocolEvent] = []
    alias = aliases.alias("tcp", _value(row, positions, "tcp_stream"))
    syn = _parse_bool(_value(row, positions, "tcp_syn"), "TCP SYN 플래그")
    ack = _parse_bool(_value(row, positions, "tcp_ack"), "TCP ACK 플래그")
    reset = _parse_bool(_value(row, positions, "tcp_reset"), "TCP RST 플래그")
    retransmission = _parse_bool(
        _value(row, positions, "tcp_retransmission"),
        "TCP 재전송 표시",
    )
    if syn and ack:
        result.append(_event(frame_number, relative_time_ms, "tcp", "tcp_syn_ack", "TCP SYN/ACK 응답", correlation_alias=alias))
    elif syn:
        result.append(_event(frame_number, relative_time_ms, "tcp", "tcp_syn", "TCP 연결 요청(SYN)", correlation_alias=alias))
    if reset:
        result.append(_event(frame_number, relative_time_ms, "tcp", "tcp_reset", "TCP 연결 재설정(RST)", "warning", correlation_alias=alias))
    if retransmission:
        result.append(_event(frame_number, relative_time_ms, "tcp", "tcp_retransmission", "TCP 재전송 표시", "warning", correlation_alias=alias))
    return result


def _tls_events(
    row: Tuple[str, ...],
    positions: Dict[str, int],
    frame_number: int,
    relative_time_ms: int,
    tokens: Set[str],
    aliases: _AliasRegistry,
) -> List[ProtocolEvent]:
    if not ({"tls", "ssl"} & tokens):
        return []
    handshake_type = _parse_uint(
        _value(row, positions, "tls_handshake_type"),
        "TLS Handshake 유형",
    )
    alias = aliases.alias("tcp", _value(row, positions, "tcp_stream"))
    mapping = {
        1: ("tls_client_hello", "TLS ClientHello"),
        2: ("tls_server_hello", "TLS ServerHello"),
        11: ("tls_certificate", "TLS Certificate"),
        20: ("tls_finished", "TLS Finished"),
    }
    event_type, label = mapping.get(handshake_type, ("tls_handshake", "TLS Handshake"))
    return [_event(frame_number, relative_time_ms, "tls", event_type, label, code=handshake_type, correlation_alias=alias, details=_detail_pairs(handshake_type=handshake_type))]


def _evidence(summaries: Dict[str, EventTypeSummary], event_types: Set[str]) -> Tuple[int, ...]:
    frames: Set[int] = set()
    for event_type in event_types:
        summary = summaries.get(event_type)
        if summary is not None:
            frames.update(summary.evidence_frames)
    return tuple(sorted(frames)[:_MAX_EVIDENCE_FRAMES])


def _stage(
    summaries: Dict[str, EventTypeSummary],
    available_keys: Set[str],
    *,
    stage_id: str,
    label: str,
    required_any: Set[str],
    success_types: Set[str],
    failure_types: Set[str],
    activity_types: Set[str],
    success_text: str,
    failure_text: str,
    activity_text: str,
) -> StageAssessment:
    relevant = success_types | failure_types | activity_types
    evidence = _evidence(summaries, relevant)
    if not (required_any & available_keys):
        return StageAssessment(stage_id, label, "unavailable", "현재 TShark에서 필요한 선택 필드를 확인하지 못했습니다.", ())
    has_success = bool(success_types & summaries.keys())
    has_failure = bool(failure_types & summaries.keys())
    has_activity = bool(activity_types & summaries.keys()) or has_success or has_failure
    if has_success and has_failure:
        return StageAssessment(stage_id, label, "mixed", success_text + " 동시에 " + failure_text + " 여러 접속이 섞였을 수 있습니다.", evidence)
    if has_failure:
        return StageAssessment(stage_id, label, "failure-observed", failure_text + " 이것만으로 원인을 확정하지 않습니다.", evidence)
    if has_success:
        return StageAssessment(stage_id, label, "success-observed", success_text + " 전체 서비스 정상 여부를 뜻하지 않습니다.", evidence)
    if has_activity:
        return StageAssessment(stage_id, label, "activity-observed", activity_text, evidence)
    return StageAssessment(stage_id, label, "not-observed", "현재 캡처에서 관련 이벤트를 관찰하지 못했습니다. 패킷 부재는 장애 증거가 아닙니다.", ())


def _build_stages(
    summaries: Tuple[EventTypeSummary, ...],
    available_keys: Set[str],
) -> Tuple[StageAssessment, ...]:
    values = {item.event_type: item for item in summaries}
    stages = [
        _stage(
            values,
            available_keys,
            stage_id="wlan-management",
            label="802.11 연결·로밍",
            required_any={"wlan_type_subtype"},
            success_types={"wlan_auth_response_success", "wlan_assoc_response_success", "wlan_reassoc_response_success"},
            failure_types={"wlan_auth_response_rejected", "wlan_assoc_response_rejected", "wlan_reassoc_response_rejected"},
            activity_types={"wlan_auth_request", "wlan_auth_frame", "wlan_assoc_request", "wlan_reassoc_request", "wlan_deauthentication", "wlan_disassociation", "wlan_retry_flag"},
            success_text="802.11 성공 상태 코드가 포함된 응답을 관찰했습니다.",
            failure_text="802.11 비정상 상태 코드가 포함된 응답을 관찰했습니다.",
            activity_text="802.11 연결·해제 또는 Retry 관련 프레임을 관찰했습니다.",
        ),
        _stage(
            values,
            available_keys,
            stage_id="eap",
            label="EAP 단말 인증",
            required_any={"eap_code"},
            success_types={"eap_success"},
            failure_types={"eap_failure"},
            activity_types={"eap_request", "eap_response", "eap_message"},
            success_text="EAP Success를 관찰했습니다.",
            failure_text="EAP Failure를 관찰했습니다.",
            activity_text="EAP 요청·응답은 보였지만 최종 Success/Failure를 확인하지 못했습니다.",
        ),
        _stage(
            values,
            available_keys,
            stage_id="radius",
            label="RADIUS 인증 서버",
            required_any={"radius_code"},
            success_types={"radius_access_accept"},
            failure_types={"radius_access_reject"},
            activity_types={"radius_access_request", "radius_access_challenge", "radius_message"},
            success_text="RADIUS Access-Accept를 관찰했습니다.",
            failure_text="RADIUS Access-Reject를 관찰했습니다.",
            activity_text="RADIUS 요청·Challenge는 보였지만 Accept/Reject를 확인하지 못했습니다.",
        ),
        _stage(
            values,
            available_keys,
            stage_id="dhcp",
            label="DHCP 주소 할당",
            required_any={"dhcp_message_type"},
            success_types={"dhcp_ack"},
            failure_types={"dhcp_nak", "dhcp_decline"},
            activity_types={"dhcp_discover", "dhcp_offer", "dhcp_request", "dhcp_release", "dhcp_inform", "dhcp_message"},
            success_text="DHCP ACK를 관찰했습니다.",
            failure_text="DHCP NAK 또는 Decline을 관찰했습니다.",
            activity_text="DHCP 교환 일부는 보였지만 최종 ACK를 확인하지 못했습니다.",
        ),
        _stage(
            values,
            available_keys,
            stage_id="dns",
            label="DNS 이름 조회",
            required_any={"dns_is_response"},
            success_types={"dns_response_success"},
            failure_types={"dns_response_error"},
            activity_types={"dns_query", "dns_message"},
            success_text="DNS 정상 응답 코드를 관찰했습니다.",
            failure_text="DNS 오류 응답 코드를 관찰했습니다.",
            activity_text="DNS 질의는 보였지만 응답 결과를 확인하지 못했습니다.",
        ),
        _stage(
            values,
            available_keys,
            stage_id="tcp",
            label="TCP 연결",
            required_any={"tcp_syn", "tcp_reset", "tcp_retransmission"},
            success_types={"tcp_syn_ack"},
            failure_types=set(),
            activity_types={"tcp_syn", "tcp_reset", "tcp_retransmission"},
            success_text="TCP SYN/ACK 응답을 관찰했습니다.",
            failure_text="",
            activity_text="TCP 연결 요청·RST 또는 재전송 표시를 관찰했습니다. 이를 서버 장애나 RF 장애로 단정하지 않습니다.",
        ),
    ]

    key_messages = {
        "eapol_key_message_1",
        "eapol_key_message_2",
        "eapol_key_message_3",
        "eapol_key_message_4",
    }
    key_evidence = _evidence(values, key_messages | {"eapol_start", "eapol_key_frame", "eapol_logoff"})
    if not ({"eapol_type", "eapol_key_message"} & available_keys):
        key_stage = StageAssessment("eapol-key", "EAPOL·4-Way Handshake", "unavailable", "현재 TShark에서 EAPOL 이벤트 필드를 확인하지 못했습니다.", ())
    elif key_messages.issubset(values.keys()):
        key_stage = StageAssessment("eapol-key", "EAPOL·4-Way Handshake", "sequence-observed", "메시지 1~4 번호가 모두 관찰됐습니다. 식별정보를 사용하지 않으므로 동일 단말의 한 번의 교환인지는 확정하지 않습니다.", key_evidence)
    elif key_evidence:
        key_stage = StageAssessment("eapol-key", "EAPOL·4-Way Handshake", "activity-observed", "EAPOL 또는 일부 Key 메시지를 관찰했습니다. 완전한 4-Way Handshake로 단정하지 않습니다.", key_evidence)
    else:
        key_stage = StageAssessment("eapol-key", "EAPOL·4-Way Handshake", "not-observed", "현재 캡처에서 EAPOL 이벤트를 관찰하지 못했습니다. 패킷 부재는 장애 증거가 아닙니다.", ())
    stages.insert(1, key_stage)
    return tuple(stages)


def build_event_timeline(
    text: str,
    profile: ResolvedProfile,
    *,
    expected_frames: Optional[int],
    max_retained_events: int = _DEFAULT_MAX_RETAINED_EVENTS,
) -> EventTimeline:
    """고정 fields 출력에서 비식별 이벤트와 단계 관찰 요약을 생성한다."""

    if profile.profile_id != "event-timeline":
        raise EventTimelineError("이벤트 타임라인 프로파일이 필요합니다.")
    if expected_frames is not None and (
        type(expected_frames) is not int or expected_frames < 0
    ):
        raise EventTimelineError("예상 프레임 수가 올바르지 않습니다.")
    if not 1 <= max_retained_events <= 20_000:
        raise EventTimelineError("보관 이벤트 상한이 올바르지 않습니다.")

    positions = {item.output_key: index for index, item in enumerate(profile.fields)}
    required = {"frame_number", "time_epoch", "captured_length", "frame_length", "protocols"}
    if not required.issubset(positions):
        raise EventTimelineError("이벤트 타임라인 필수 열이 누락됐습니다.")

    retained: List[ProtocolEvent] = []
    summaries: Dict[str, _SummaryAccumulator] = {}
    aliases = _AliasRegistry()
    frames_observed = 0
    events_total = 0
    previous_frame = 0
    first_epoch: Optional[int] = None
    previous_epoch: Optional[int] = None

    try:
        rows = iter_fields_rows(text, profile)
        for row in rows:
            frame_number = _parse_uint(_value(row, positions, "frame_number"), "프레임 번호")
            captured_length = _parse_uint(_value(row, positions, "captured_length"), "캡처 길이")
            frame_length = _parse_uint(_value(row, positions, "frame_length"), "프레임 길이")
            if frame_number is None or frame_number == 0 or frame_number <= previous_frame:
                raise EventTimelineError("프레임 번호가 엄격한 증가 순서가 아닙니다.")
            if captured_length is None or frame_length is None or captured_length > frame_length:
                raise EventTimelineError("프레임 길이 정보가 올바르지 않습니다.")
            epoch = _parse_epoch_microseconds(_value(row, positions, "time_epoch"))
            if previous_epoch is not None and epoch < previous_epoch:
                raise EventTimelineError("프레임 시간이 역순으로 기록되어 타임라인을 만들 수 없습니다.")
            if first_epoch is None:
                first_epoch = epoch
            relative_time_ms = (epoch - first_epoch) // 1000
            previous_epoch = epoch
            previous_frame = frame_number
            frames_observed += 1

            tokens = {
                token.strip().casefold()
                for token in _value(row, positions, "protocols").split(":")
                if token.strip()
            }
            frame_events: List[ProtocolEvent] = []
            frame_events.extend(_wlan_events(row, positions, frame_number, relative_time_ms, tokens))
            frame_events.extend(_eapol_events(row, positions, frame_number, relative_time_ms, tokens))
            frame_events.extend(_eap_events(row, positions, frame_number, relative_time_ms, tokens, aliases))
            frame_events.extend(_radius_events(row, positions, frame_number, relative_time_ms, tokens, aliases))
            frame_events.extend(_dhcp_events(row, positions, frame_number, relative_time_ms, tokens, aliases))
            frame_events.extend(_dns_events(row, positions, frame_number, relative_time_ms, tokens, aliases))
            frame_events.extend(_arp_events(row, positions, frame_number, relative_time_ms, tokens))
            frame_events.extend(_tcp_events(row, positions, frame_number, relative_time_ms, tokens, aliases))
            frame_events.extend(_tls_events(row, positions, frame_number, relative_time_ms, tokens, aliases))

            for item in frame_events:
                events_total += 1
                accumulator = summaries.get(item.event_type)
                if accumulator is None:
                    summaries[item.event_type] = _SummaryAccumulator(
                        item.event_type,
                        item.label_ko,
                        item.frame_number,
                        item.outcome,
                    )
                else:
                    accumulator.add(item.frame_number, item.outcome)
                if len(retained) < max_retained_events:
                    retained.append(item)
    except FieldsOutputError as exc:
        raise EventTimelineError(str(exc)) from exc

    if expected_frames is not None and frames_observed > expected_frames:
        raise EventTimelineError("관찰 프레임 수가 사전 점검 프레임 수보다 큽니다.")
    frozen_summaries = tuple(
        summaries[key].freeze()
        for key in sorted(summaries)
    )
    available_keys = set(positions)
    complete = expected_frames is not None and frames_observed == expected_frames
    events_omitted = events_total - len(retained)
    cautions = [
        "이벤트는 캡처 전체에서 관찰한 사실이며 하나의 단말 세션으로 자동 결합하지 않습니다.",
        "여러 단말과 여러 접속이 섞인 캡처에서는 성공·실패 이벤트가 동시에 보일 수 있습니다.",
        "프로토콜 결과 코드는 관찰 사실이며 최종 장애 원인이나 책임 시스템을 뜻하지 않습니다.",
        "원본 IP·MAC·SSID·사용자명은 추출하거나 결과에 기록하지 않습니다.",
    ]
    if expected_frames is None:
        cautions.append("사전 점검 전체 프레임 수가 확정되지 않아 타임라인 완전성을 판단할 수 없습니다.")
    elif frames_observed < expected_frames:
        cautions.append("패킷 상한 또는 TShark 처리 결과 때문에 일부 프레임만 분석됐습니다.")
    if events_omitted:
        cautions.append("화면·JSON 크기 제한으로 일부 반복 이벤트는 요약에만 집계했습니다.")
    if profile.missing_optional_fields:
        cautions.append("현재 TShark에 없는 선택 필드는 해당 단계만 판단 불가로 표시합니다.")

    return EventTimeline(
        profile_id=profile.profile_id,
        profile_version=profile.profile_version,
        frames_observed=frames_observed,
        expected_frames=expected_frames,
        complete=complete,
        events_total=events_total,
        events_retained=len(retained),
        events_omitted=events_omitted,
        events=tuple(retained),
        summaries=frozen_summaries,
        stages=_build_stages(frozen_summaries, available_keys),
        missing_optional_fields=profile.missing_optional_fields,
        cautions=tuple(cautions),
    )
