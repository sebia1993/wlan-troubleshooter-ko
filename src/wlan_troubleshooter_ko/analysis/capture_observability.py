"""Assess whether an unobserved response can be interpreted safely.

The model uses only container completeness, retained event metadata and
identifier-free transaction attempts. It never upgrades packet absence to a
confirmed failure. A fully parsed file still does not prove that capture began
before the incident, ended after it, saw both directions, or lost no packets.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, Mapping, Optional, Sequence, Tuple


_ATTEMPT_PATTERN = re.compile(
    r"^(EAP|RADIUS|DHCP|DNS|TCP)-[1-9][0-9]{0,5}-A[1-9][0-9]{0,5}$"
)
_ALLOWED_PROTOCOLS = ("eap", "radius", "dhcp", "dns", "tcp")
_ALLOWED_ATTEMPT_STATES = {
    "complete",
    "success-observed",
    "failure-observed",
    "mixed",
    "incomplete",
}
_MAX_ATTEMPTS = 50_000
_MAX_EVIDENCE = 64

_REQUEST_EVENTS: Mapping[str, Tuple[str, ...]] = {
    "eap": ("eap_request",),
    "radius": ("radius_access_request",),
    "dhcp": (
        "dhcp_discover",
        "dhcp_request",
        "dhcp_decline",
        "dhcp_release",
        "dhcp_inform",
    ),
    "dns": ("dns_query",),
    "tcp": ("tcp_syn",),
}
_REPLY_EVENTS: Mapping[str, Tuple[str, ...]] = {
    "eap": ("eap_response", "eap_success", "eap_failure"),
    "radius": (
        "radius_access_challenge",
        "radius_access_accept",
        "radius_access_reject",
    ),
    "dhcp": ("dhcp_offer", "dhcp_ack", "dhcp_nak"),
    "dns": ("dns_response_success", "dns_response_error"),
    "tcp": ("tcp_syn_ack", "tcp_reset"),
}


class CaptureObservabilityError(ValueError):
    """Source reports do not satisfy observability invariants."""


@dataclass(frozen=True)
class ProtocolVisibility:
    protocol: str
    request_event_observed: bool
    reply_event_observed: bool
    request_event_types: Tuple[str, ...]
    reply_event_types: Tuple[str, ...]
    bidirectional_event_classes_observed: bool
    directionality_proven: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "protocol": self.protocol,
            "request_event_observed": self.request_event_observed,
            "reply_event_observed": self.reply_event_observed,
            "request_event_types": list(self.request_event_types),
            "reply_event_types": list(self.reply_event_types),
            "bidirectional_event_classes_observed": self.bidirectional_event_classes_observed,
            "directionality_proven": self.directionality_proven,
        }


@dataclass(frozen=True)
class IncompleteAttemptAssessment:
    attempt_id: str
    protocol: str
    assessment: str
    summary_ko: str
    first_frame: int
    last_frame: int
    evidence_frames: Tuple[int, ...]
    display_filter: str
    risk_flags: Tuple[str, ...]
    request_event_observed: bool
    reply_event_observed: bool
    absence_is_failure: bool = False
    capture_loss_excluded: bool = False
    directionality_proven: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "attempt_id": self.attempt_id,
            "protocol": self.protocol,
            "assessment": self.assessment,
            "summary_ko": self.summary_ko,
            "first_frame": self.first_frame,
            "last_frame": self.last_frame,
            "evidence_frames": list(self.evidence_frames),
            "display_filter": self.display_filter,
            "risk_flags": list(self.risk_flags),
            "request_event_observed": self.request_event_observed,
            "reply_event_observed": self.reply_event_observed,
            "absence_is_failure": self.absence_is_failure,
            "capture_loss_excluded": self.capture_loss_excluded,
            "directionality_proven": self.directionality_proven,
        }


@dataclass(frozen=True)
class CaptureObservabilityReport:
    packets_scanned: int
    frames_observed: int
    analysis_input_complete: bool
    container_scan_complete: bool
    event_timeline_complete: bool
    transaction_report_complete: bool
    truncated_packets_observed: int
    event_details_omitted: int
    protocol_visibility: Tuple[ProtocolVisibility, ...]
    incomplete_attempts: Tuple[IncompleteAttemptAssessment, ...]
    capture_start_proven: bool
    capture_end_proven: bool
    capture_loss_excluded: bool
    directionality_proven: bool
    absence_can_confirm_failure: bool
    cautions: Tuple[str, ...]

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema_version": 1,
            "packets_scanned": self.packets_scanned,
            "frames_observed": self.frames_observed,
            "analysis_input_complete": self.analysis_input_complete,
            "container_scan_complete": self.container_scan_complete,
            "event_timeline_complete": self.event_timeline_complete,
            "transaction_report_complete": self.transaction_report_complete,
            "truncated_packets_observed": self.truncated_packets_observed,
            "event_details_omitted": self.event_details_omitted,
            "protocol_visibility": [item.to_dict() for item in self.protocol_visibility],
            "incomplete_attempts_total": len(self.incomplete_attempts),
            "incomplete_attempts": [item.to_dict() for item in self.incomplete_attempts],
            "capture_start_proven": self.capture_start_proven,
            "capture_end_proven": self.capture_end_proven,
            "capture_loss_excluded": self.capture_loss_excluded,
            "directionality_proven": self.directionality_proven,
            "absence_can_confirm_failure": self.absence_can_confirm_failure,
            "cautions": list(self.cautions),
        }


def _attribute(value: object, name: str, label: str) -> object:
    try:
        return getattr(value, name)
    except (AttributeError, TypeError) as exc:
        raise CaptureObservabilityError(label + " 구조가 올바르지 않습니다.") from exc


def _boolean(value: object, name: str, label: str) -> bool:
    result = _attribute(value, name, label)
    if type(result) is not bool:
        raise CaptureObservabilityError(label + " 완료 상태가 올바르지 않습니다.")
    return result


def _nonnegative(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise CaptureObservabilityError(label + " 값이 올바르지 않습니다.")
    return value


def _positive(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise CaptureObservabilityError(label + " 값이 올바르지 않습니다.")
    return value


def _strings(value: object, label: str) -> Tuple[str, ...]:
    if not isinstance(value, (tuple, list)) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise CaptureObservabilityError(label + " 목록이 올바르지 않습니다.")
    result = tuple(value)
    if len(result) != len(set(result)):
        raise CaptureObservabilityError(label + " 목록에 중복 값이 있습니다.")
    return result


def _frames(value: object, label: str) -> Tuple[int, ...]:
    if not isinstance(value, (tuple, list)):
        raise CaptureObservabilityError(label + " 목록이 올바르지 않습니다.")
    result = tuple(value)
    if any(type(item) is not int or item <= 0 for item in result):
        raise CaptureObservabilityError(label + " 프레임 번호가 올바르지 않습니다.")
    if result != tuple(sorted(set(result))):
        raise CaptureObservabilityError(label + " 프레임은 중복 없이 오름차순이어야 합니다.")
    if len(result) > _MAX_EVIDENCE:
        raise CaptureObservabilityError(label + " 프레임 수가 안전 상한을 초과했습니다.")
    return result


def _display_filter(frames: Sequence[int]) -> str:
    return " || ".join("frame.number == {0}".format(item) for item in frames)


def _attempts(transaction_report: object, frames_observed: int) -> Tuple[object, ...]:
    values = _attribute(transaction_report, "attempts", "거래 시도 보고서")
    if not isinstance(values, (tuple, list)):
        raise CaptureObservabilityError("거래 시도 목록이 올바르지 않습니다.")
    if len(values) > _MAX_ATTEMPTS:
        raise CaptureObservabilityError("거래 시도 수가 안전 제한을 초과했습니다.")
    seen = set()
    result = []
    for attempt in values:
        attempt_id = _attribute(attempt, "attempt_id", "거래 시도")
        protocol = _attribute(attempt, "protocol", "거래 시도")
        state = _attribute(attempt, "state", "거래 시도")
        if not isinstance(attempt_id, str) or _ATTEMPT_PATTERN.fullmatch(attempt_id) is None:
            raise CaptureObservabilityError("거래 시도 ID가 올바르지 않습니다.")
        if attempt_id in seen:
            raise CaptureObservabilityError("거래 시도 ID가 중복됐습니다.")
        seen.add(attempt_id)
        expected_protocol = attempt_id.split("-", 1)[0].casefold()
        if protocol != expected_protocol or protocol not in _ALLOWED_PROTOCOLS:
            raise CaptureObservabilityError("거래 시도 ID와 프로토콜이 일치하지 않습니다.")
        if state not in _ALLOWED_ATTEMPT_STATES:
            raise CaptureObservabilityError("거래 시도 상태가 올바르지 않습니다.")
        first_frame = _positive(_attribute(attempt, "first_frame", "거래 시도"), "첫 프레임")
        last_frame = _positive(_attribute(attempt, "last_frame", "거래 시도"), "마지막 프레임")
        if last_frame < first_frame or (frames_observed and last_frame > frames_observed):
            raise CaptureObservabilityError("거래 시도 프레임 범위가 올바르지 않습니다.")
        evidence = _frames(_attribute(attempt, "evidence_frames", "거래 시도"), "거래 근거")
        if any(item < first_frame or item > last_frame for item in evidence):
            raise CaptureObservabilityError("거래 근거가 거래 프레임 범위를 벗어났습니다.")
        _nonnegative(
            _attribute(attempt, "evidence_frames_omitted", "거래 시도"),
            "거래 근거 생략 수",
        )
        _strings(_attribute(attempt, "observed_event_types", "거래 시도"), "관찰 이벤트")
        if _attribute(attempt, "root_cause_confirmed", "거래 시도") is not False:
            raise CaptureObservabilityError("거래 시도 근본 원인 확정 값은 false여야 합니다.")
        result.append(attempt)
    return tuple(result)


def _event_classes(attempts: Iterable[object], protocol: str) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    observed = {
        event
        for attempt in attempts
        if _attribute(attempt, "protocol", "거래 시도") == protocol
        for event in _strings(
            _attribute(attempt, "observed_event_types", "거래 시도"),
            "관찰 이벤트",
        )
    }
    request = tuple(item for item in _REQUEST_EVENTS[protocol] if item in observed)
    reply = tuple(item for item in _REPLY_EVENTS[protocol] if item in observed)
    return request, reply


def _risk_flags(
    attempt: object,
    *,
    frames_observed: int,
    analysis_input_complete: bool,
    truncated_packets: int,
    event_details_omitted: int,
) -> Tuple[str, ...]:
    flags = []
    if not analysis_input_complete:
        flags.append("analysis-input-incomplete")
    if truncated_packets:
        flags.append("packet-truncation-observed")
    if event_details_omitted:
        flags.append("event-detail-omitted")
    omitted = _nonnegative(
        _attribute(attempt, "evidence_frames_omitted", "거래 시도"),
        "거래 근거 생략 수",
    )
    if omitted:
        flags.append("attempt-evidence-omitted")
    first_frame = _positive(_attribute(attempt, "first_frame", "거래 시도"), "첫 프레임")
    last_frame = _positive(_attribute(attempt, "last_frame", "거래 시도"), "마지막 프레임")
    if first_frame == 1:
        flags.append("capture-start-boundary-risk")
    if frames_observed and last_frame == frames_observed:
        flags.append("capture-end-boundary-risk")
    return tuple(flags)


def _assessment(flags: Sequence[str]) -> Tuple[str, str]:
    if "analysis-input-incomplete" in flags or "event-detail-omitted" in flags or "attempt-evidence-omitted" in flags:
        return (
            "insufficient-analysis-input",
            "분석 입력 또는 상세 근거가 일부여서 응답 미관찰을 해석할 수 없습니다.",
        )
    if "packet-truncation-observed" in flags:
        return (
            "packet-truncation-risk",
            "잘린 패킷이 있어 응답 또는 상위 프로토콜 필드가 누락됐을 가능성을 배제할 수 없습니다.",
        )
    if "capture-start-boundary-risk" in flags or "capture-end-boundary-risk" in flags:
        return (
            "capture-boundary-risk",
            "거래가 캡처 파일 경계에 닿아 캡처 시작 전 요청 또는 종료 후 응답 가능성을 배제할 수 없습니다.",
        )
    return (
        "response-not-observed",
        "현재 보관된 프레임 범위에서 명시적인 최종 응답을 관찰하지 못했습니다. 이는 실패 확정이 아닙니다.",
    )


def build_capture_observability(
    structure: object,
    timeline: object,
    transaction_report: object,
) -> CaptureObservabilityReport:
    """Build a conservative interpretation boundary for packet absence."""

    packets_scanned = _nonnegative(_attribute(structure, "packets_scanned", "캡처 구조"), "점검 패킷 수")
    truncated_packets = _nonnegative(
        _attribute(structure, "truncated_packets_observed", "캡처 구조"),
        "잘린 패킷 수",
    )
    if truncated_packets > packets_scanned:
        raise CaptureObservabilityError("잘린 패킷 수가 점검 패킷 수보다 많습니다.")
    container_complete = _boolean(structure, "scan_complete", "캡처 구조")

    frames_observed = _nonnegative(_attribute(timeline, "frames_observed", "이벤트 타임라인"), "관찰 프레임 수")
    timeline_complete = _boolean(timeline, "complete", "이벤트 타임라인")
    events_total = _nonnegative(_attribute(timeline, "events_total", "이벤트 타임라인"), "전체 이벤트 수")
    events_retained = _nonnegative(_attribute(timeline, "events_retained", "이벤트 타임라인"), "보관 이벤트 수")
    events_omitted = _nonnegative(_attribute(timeline, "events_omitted", "이벤트 타임라인"), "생략 이벤트 수")
    if events_total != events_retained + events_omitted:
        raise CaptureObservabilityError("이벤트 전체·보관·생략 수가 일치하지 않습니다.")
    if container_complete and timeline_complete and frames_observed != packets_scanned:
        raise CaptureObservabilityError("구조 점검과 이벤트 분석의 프레임 수가 일치하지 않습니다.")

    transaction_complete = _boolean(transaction_report, "complete", "거래 시도 보고서")
    source_total = _nonnegative(
        _attribute(transaction_report, "source_events_total", "거래 시도 보고서"),
        "거래 원본 이벤트 수",
    )
    source_retained = _nonnegative(
        _attribute(transaction_report, "source_events_retained", "거래 시도 보고서"),
        "거래 보관 이벤트 수",
    )
    source_omitted = _nonnegative(
        _attribute(transaction_report, "source_events_omitted", "거래 시도 보고서"),
        "거래 생략 이벤트 수",
    )
    if source_total != source_retained + source_omitted:
        raise CaptureObservabilityError("거래 이벤트 전체·보관·생략 수가 일치하지 않습니다.")
    if (source_total, source_retained, source_omitted) != (
        events_total,
        events_retained,
        events_omitted,
    ):
        raise CaptureObservabilityError("이벤트 타임라인과 거래 시도 보고서의 이벤트 수가 일치하지 않습니다.")

    attempts = _attempts(transaction_report, frames_observed)
    analysis_input_complete = (
        container_complete
        and timeline_complete
        and transaction_complete
        and events_omitted == 0
    )

    visibility = []
    for protocol in _ALLOWED_PROTOCOLS:
        request, reply = _event_classes(attempts, protocol)
        visibility.append(
            ProtocolVisibility(
                protocol=protocol,
                request_event_observed=bool(request),
                reply_event_observed=bool(reply),
                request_event_types=request,
                reply_event_types=reply,
                bidirectional_event_classes_observed=bool(request and reply),
                directionality_proven=False,
            )
        )

    incomplete = []
    for attempt in attempts:
        if _attribute(attempt, "state", "거래 시도") != "incomplete":
            continue
        protocol = str(_attribute(attempt, "protocol", "거래 시도"))
        event_types = _strings(
            _attribute(attempt, "observed_event_types", "거래 시도"),
            "관찰 이벤트",
        )
        request_observed = any(item in _REQUEST_EVENTS[protocol] for item in event_types)
        reply_observed = any(item in _REPLY_EVENTS[protocol] for item in event_types)
        flags = _risk_flags(
            attempt,
            frames_observed=frames_observed,
            analysis_input_complete=analysis_input_complete,
            truncated_packets=truncated_packets,
            event_details_omitted=events_omitted,
        )
        assessment, summary = _assessment(flags)
        evidence = _frames(
            _attribute(attempt, "evidence_frames", "거래 시도"),
            "거래 근거",
        )
        incomplete.append(
            IncompleteAttemptAssessment(
                attempt_id=str(_attribute(attempt, "attempt_id", "거래 시도")),
                protocol=protocol,
                assessment=assessment,
                summary_ko=summary,
                first_frame=_positive(_attribute(attempt, "first_frame", "거래 시도"), "첫 프레임"),
                last_frame=_positive(_attribute(attempt, "last_frame", "거래 시도"), "마지막 프레임"),
                evidence_frames=evidence,
                display_filter=_display_filter(evidence),
                risk_flags=flags,
                request_event_observed=request_observed,
                reply_event_observed=reply_observed,
            )
        )

    cautions = [
        "파일을 끝까지 읽었다는 사실만으로 장애 발생 전부터 캡처를 시작했거나 장애 종료 후까지 캡처했다는 사실은 증명되지 않습니다.",
        "요청·응답 계열 이벤트가 모두 보여도 모든 네트워크 방향과 모든 패킷을 수집했다는 뜻은 아닙니다.",
        "응답 미관찰은 서버·방화벽·ClearPass·DHCP·DNS 장애의 확정 근거가 아닙니다.",
        "캡처 프로그램 내부 드롭, 미러링 누락과 무선 채널 이탈은 현재 파일만으로 배제할 수 없습니다.",
    ]
    if truncated_packets:
        cautions.insert(0, "잘린 패킷이 있어 상위 프로토콜 응답 필드 누락 가능성이 있습니다.")
    if events_omitted:
        cautions.insert(0, "상세 이벤트 보관 상한으로 일부 이벤트가 생략됐습니다.")
    if not analysis_input_complete:
        cautions.insert(0, "구조·타임라인·거래 분석 중 일부가 완전하지 않아 미응답 해석을 제한합니다.")

    return CaptureObservabilityReport(
        packets_scanned=packets_scanned,
        frames_observed=frames_observed,
        analysis_input_complete=analysis_input_complete,
        container_scan_complete=container_complete,
        event_timeline_complete=timeline_complete,
        transaction_report_complete=transaction_complete,
        truncated_packets_observed=truncated_packets,
        event_details_omitted=events_omitted,
        protocol_visibility=tuple(visibility),
        incomplete_attempts=tuple(incomplete),
        capture_start_proven=False,
        capture_end_proven=False,
        capture_loss_excluded=False,
        directionality_proven=False,
        absence_can_confirm_failure=False,
        cautions=tuple(cautions),
    )
