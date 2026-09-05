"""Identifier-free capture-relative time and transaction boundary analysis.

The dedicated TShark profile exposes only frame.number and frame.time_epoch.
Absolute epoch values exist only while parsing local text and are immediately
converted to integer milliseconds relative to the first observed frame.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from wlan_troubleshooter_ko.tshark.fields_output import (
    FieldsOutputError,
    iter_fields_rows,
)
from wlan_troubleshooter_ko.tshark.profiles import ResolvedProfile


_MAX_INTEGER = 2**63 - 1
_MAX_EVIDENCE_FRAMES = 64
_DEFAULT_BOUNDARY_THRESHOLD_MS = 1000
_ATTEMPT_PATTERN = re.compile(
    r"^(EAP|RADIUS|DHCP|DNS|TCP)-[1-9][0-9]{0,5}-A[1-9][0-9]{0,5}$"
)
_ALLOWED_PROTOCOLS = {"eap", "radius", "dhcp", "dns", "tcp"}
_ALLOWED_ATTEMPT_STATES = {
    "complete",
    "success-observed",
    "failure-observed",
    "mixed",
    "incomplete",
}


class CaptureTimeBoundaryError(ValueError):
    """Timestamp text or transaction evidence violates safe invariants."""


@dataclass(frozen=True)
class CaptureTimeIndex:
    """Internal relative-only frame index; absolute epochs are not retained."""

    profile_id: str
    profile_version: str
    frames_observed: int
    expected_frames: Optional[int]
    complete: bool
    frame_relative_ms: Tuple[int, ...]
    first_frame: Optional[int]
    last_frame: Optional[int]
    first_to_last_relative_ms: Optional[int]
    minimum_relative_ms: Optional[int]
    maximum_relative_ms: Optional[int]
    observed_span_ms: Optional[int]
    timestamp_regressions: int
    regression_evidence_frames: Tuple[int, ...]
    regression_evidence_frames_omitted: int


@dataclass(frozen=True)
class TransactionTimeBoundary:
    attempt_id: str
    protocol: str
    attempt_state: str
    boundary_state: str
    first_frame: int
    last_frame: int
    start_distance_ms: int
    end_observation_window_ms: int
    observed_attempt_duration_ms: int
    start_near_boundary: bool
    end_near_boundary: bool
    display_filter: str
    response_wait_sufficiency_assessed: bool = False
    response_absence_confirmed: bool = False
    root_cause_confirmed: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "attempt_id": self.attempt_id,
            "protocol": self.protocol,
            "attempt_state": self.attempt_state,
            "boundary_state": self.boundary_state,
            "first_frame": self.first_frame,
            "last_frame": self.last_frame,
            "start_distance_ms": self.start_distance_ms,
            "end_observation_window_ms": self.end_observation_window_ms,
            "observed_attempt_duration_ms": self.observed_attempt_duration_ms,
            "start_near_boundary": self.start_near_boundary,
            "end_near_boundary": self.end_near_boundary,
            "display_filter": self.display_filter,
            "response_wait_sufficiency_assessed": self.response_wait_sufficiency_assessed,
            "response_absence_confirmed": self.response_absence_confirmed,
            "root_cause_confirmed": self.root_cause_confirmed,
        }


@dataclass(frozen=True)
class CaptureTimeBoundaryReport:
    profile_id: str
    profile_version: str
    frames_observed: int
    expected_frames: Optional[int]
    complete: bool
    first_frame: Optional[int]
    last_frame: Optional[int]
    first_to_last_relative_ms: Optional[int]
    minimum_relative_ms: Optional[int]
    maximum_relative_ms: Optional[int]
    observed_span_ms: Optional[int]
    timestamp_regressions: int
    regression_evidence_frames: Tuple[int, ...]
    regression_evidence_frames_omitted: int
    boundary_threshold_ms: int
    transaction_source_complete: bool
    transaction_attempts_total: int
    transaction_boundaries: Tuple[TransactionTimeBoundary, ...]
    absolute_timestamps_serialized: bool
    capture_start_proven: bool
    capture_end_proven: bool
    incident_window_fully_covered: bool
    response_wait_sufficiency_assessed: bool
    response_absence_confirmed: bool
    capture_loss_excluded: bool
    root_cause_confirmed: bool
    cautions: Tuple[str, ...]

    def to_dict(self) -> Dict[str, object]:
        state_counts: Dict[str, int] = {}
        for item in self.transaction_boundaries:
            state_counts[item.boundary_state] = (
                state_counts.get(item.boundary_state, 0) + 1
            )
        return {
            "schema_version": 1,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "frames_observed": self.frames_observed,
            "expected_frames": self.expected_frames,
            "complete": self.complete,
            "first_frame": self.first_frame,
            "last_frame": self.last_frame,
            "first_to_last_relative_ms": self.first_to_last_relative_ms,
            "minimum_relative_ms": self.minimum_relative_ms,
            "maximum_relative_ms": self.maximum_relative_ms,
            "observed_span_ms": self.observed_span_ms,
            "timestamp_regressions": self.timestamp_regressions,
            "regression_evidence_frames": list(self.regression_evidence_frames),
            "regression_evidence_frames_omitted": self.regression_evidence_frames_omitted,
            "boundary_threshold_ms": self.boundary_threshold_ms,
            "transaction_source_complete": self.transaction_source_complete,
            "transaction_attempts_total": self.transaction_attempts_total,
            "transaction_boundaries_total": len(self.transaction_boundaries),
            "transaction_boundaries_by_state": dict(sorted(state_counts.items())),
            "transaction_boundaries": [
                item.to_dict() for item in self.transaction_boundaries
            ],
            "absolute_timestamps_serialized": self.absolute_timestamps_serialized,
            "capture_start_proven": self.capture_start_proven,
            "capture_end_proven": self.capture_end_proven,
            "incident_window_fully_covered": self.incident_window_fully_covered,
            "response_wait_sufficiency_assessed": self.response_wait_sufficiency_assessed,
            "response_absence_confirmed": self.response_absence_confirmed,
            "capture_loss_excluded": self.capture_loss_excluded,
            "root_cause_confirmed": self.root_cause_confirmed,
            "cautions": list(self.cautions),
        }


def _parse_uint(value: str, label: str) -> int:
    raw = value.strip()
    if not raw or not raw.isascii() or not raw.isdecimal():
        raise CaptureTimeBoundaryError(label + " 값이 올바른 정수가 아닙니다.")
    parsed = int(raw, 10)
    if parsed < 0 or parsed > _MAX_INTEGER:
        raise CaptureTimeBoundaryError(label + " 값이 허용 범위를 벗어났습니다.")
    return parsed


def _parse_epoch_microseconds(value: str) -> int:
    raw = value.strip()
    if not raw or raw.startswith(("+", "-")):
        raise CaptureTimeBoundaryError(
            "프레임 시간이 올바른 양수 epoch 형식이 아닙니다."
        )
    whole, separator, fraction = raw.partition(".")
    if not whole.isascii() or not whole.isdecimal():
        raise CaptureTimeBoundaryError("프레임 시간이 올바른 epoch 형식이 아닙니다.")
    if separator and (
        not fraction or not fraction.isascii() or not fraction.isdecimal()
    ):
        raise CaptureTimeBoundaryError(
            "프레임 시간의 소수부가 올바르지 않습니다."
        )
    if len(whole) > 15 or len(fraction) > 18:
        raise CaptureTimeBoundaryError("프레임 시간이 안전 범위를 벗어났습니다.")
    microseconds = int(whole, 10) * 1_000_000
    microseconds += int((fraction + "000000")[:6] or "0", 10)
    if microseconds > _MAX_INTEGER:
        raise CaptureTimeBoundaryError(
            "프레임 시간이 허용 범위를 벗어났습니다."
        )
    return microseconds


def build_capture_time_index(
    text: str,
    profile: ResolvedProfile,
    *,
    expected_frames: Optional[int],
) -> CaptureTimeIndex:
    """Convert raw epoch text into a frame-complete relative millisecond index."""

    if profile.profile_id != "capture-time-boundaries":
        raise CaptureTimeBoundaryError(
            "캡처 상대 시간 전용 프로파일이 필요합니다."
        )
    if expected_frames is not None and (
        type(expected_frames) is not int or expected_frames < 0
    ):
        raise CaptureTimeBoundaryError("예상 프레임 수가 올바르지 않습니다.")
    positions = {
        item.output_key: index for index, item in enumerate(profile.fields)
    }
    if set(positions) != {"frame_number", "time_epoch"}:
        raise CaptureTimeBoundaryError(
            "캡처 상대 시간 필드 구성이 승인된 최소 프로파일과 다릅니다."
        )

    first_epoch: Optional[int] = None
    previous_epoch: Optional[int] = None
    previous_frame = 0
    relative_values = []
    regressions = 0
    regression_frames = []

    try:
        for row in iter_fields_rows(text, profile):
            frame = _parse_uint(
                row[positions["frame_number"]],
                "프레임 번호",
            )
            if frame != previous_frame + 1:
                raise CaptureTimeBoundaryError(
                    "프레임 번호가 1부터 연속 증가하지 않습니다."
                )
            epoch = _parse_epoch_microseconds(
                row[positions["time_epoch"]]
            )
            if first_epoch is None:
                first_epoch = epoch
            if previous_epoch is not None and epoch < previous_epoch:
                regressions += 1
                regression_frames.append(frame)
            relative_values.append((epoch - first_epoch) // 1000)
            previous_epoch = epoch
            previous_frame = frame
    except FieldsOutputError as exc:
        raise CaptureTimeBoundaryError(str(exc)) from exc

    frames_observed = len(relative_values)
    if expected_frames is not None and frames_observed > expected_frames:
        raise CaptureTimeBoundaryError(
            "상대 시간 프레임 수가 사전 점검 프레임 수보다 큽니다."
        )
    complete = (
        expected_frames is not None
        and frames_observed == expected_frames
    )
    if relative_values:
        first_to_last = relative_values[-1]
        minimum = min(relative_values)
        maximum = max(relative_values)
        span = maximum - minimum
        first_frame = 1
        last_frame = frames_observed
    else:
        first_to_last = None
        minimum = None
        maximum = None
        span = None
        first_frame = None
        last_frame = None

    evidence = tuple(regression_frames[:_MAX_EVIDENCE_FRAMES])
    return CaptureTimeIndex(
        profile_id=profile.profile_id,
        profile_version=profile.profile_version,
        frames_observed=frames_observed,
        expected_frames=expected_frames,
        complete=complete,
        frame_relative_ms=tuple(relative_values),
        first_frame=first_frame,
        last_frame=last_frame,
        first_to_last_relative_ms=first_to_last,
        minimum_relative_ms=minimum,
        maximum_relative_ms=maximum,
        observed_span_ms=span,
        timestamp_regressions=regressions,
        regression_evidence_frames=evidence,
        regression_evidence_frames_omitted=max(
            0,
            len(regression_frames) - len(evidence),
        ),
    )


def _display_filter(first_frame: int, last_frame: int) -> str:
    if first_frame == last_frame:
        return "frame.number == " + str(first_frame)
    return (
        "frame.number == "
        + str(first_frame)
        + " || frame.number == "
        + str(last_frame)
    )


def _boundary_state(
    *,
    index: CaptureTimeIndex,
    first_frame: int,
    last_frame: int,
    start_distance_ms: int,
    end_observation_window_ms: int,
    threshold_ms: int,
) -> Tuple[str, bool, bool]:
    if index.timestamp_regressions:
        return "timestamp-order-risk", False, False
    at_start = first_frame == index.first_frame
    at_end = last_frame == index.last_frame
    near_start = at_start or start_distance_ms <= threshold_ms
    near_end = at_end or end_observation_window_ms <= threshold_ms
    if at_start and at_end:
        return "spans-analysis-window", True, True
    if at_start:
        return "at-analysis-start", True, near_end
    if at_end:
        return "at-analysis-end", near_start, True
    if near_start and near_end:
        return "near-both-boundaries", True, True
    if near_start:
        return "near-analysis-start", True, False
    if near_end:
        return "near-analysis-end", False, True
    return "analysis-window-interior", False, False


def _attempts(transaction_report: object) -> Tuple[Tuple[object, ...], bool]:
    try:
        values = transaction_report.attempts
        complete = transaction_report.complete
    except (AttributeError, TypeError) as exc:
        raise CaptureTimeBoundaryError(
            "거래 시도 보고서 구조가 올바르지 않습니다."
        ) from exc
    if not isinstance(values, (tuple, list)) or type(complete) is not bool:
        raise CaptureTimeBoundaryError(
            "거래 시도 보고서 구조가 올바르지 않습니다."
        )
    if len(values) > 50_000:
        raise CaptureTimeBoundaryError(
            "거래 시도 수가 안전 제한을 초과했습니다."
        )
    return tuple(values), complete


def _build_transaction_boundary(
    index: CaptureTimeIndex,
    attempt: object,
    threshold_ms: int,
) -> TransactionTimeBoundary:
    try:
        attempt_id = attempt.attempt_id
        protocol = attempt.protocol
        state = attempt.state
        first_frame = attempt.first_frame
        last_frame = attempt.last_frame
        duration_ms = attempt.duration_ms
        root_cause_confirmed = attempt.root_cause_confirmed
    except (AttributeError, TypeError) as exc:
        raise CaptureTimeBoundaryError(
            "거래 시도 항목 구조가 올바르지 않습니다."
        ) from exc

    if (
        not isinstance(attempt_id, str)
        or _ATTEMPT_PATTERN.fullmatch(attempt_id) is None
    ):
        raise CaptureTimeBoundaryError("거래 시도 ID가 올바르지 않습니다.")
    expected_protocol = attempt_id.split("-", 1)[0].casefold()
    if protocol != expected_protocol or protocol not in _ALLOWED_PROTOCOLS:
        raise CaptureTimeBoundaryError(
            "거래 시도 ID와 프로토콜이 일치하지 않습니다."
        )
    if state not in _ALLOWED_ATTEMPT_STATES:
        raise CaptureTimeBoundaryError("거래 시도 상태가 올바르지 않습니다.")
    if (
        type(first_frame) is not int
        or type(last_frame) is not int
        or first_frame <= 0
        or last_frame < first_frame
        or last_frame > index.frames_observed
    ):
        raise CaptureTimeBoundaryError(
            "거래 시도 프레임 범위가 상대 시간 분석 범위를 벗어났습니다."
        )
    if (
        type(duration_ms) is not int
        or duration_ms < 0
        or root_cause_confirmed is not False
    ):
        raise CaptureTimeBoundaryError(
            "거래 시도 지속시간 또는 판정 경계가 올바르지 않습니다."
        )

    first_time = index.frame_relative_ms[first_frame - 1]
    last_time = index.frame_relative_ms[last_frame - 1]
    analysis_end = index.frame_relative_ms[-1]
    observed_duration = last_time - first_time
    if observed_duration != duration_ms:
        raise CaptureTimeBoundaryError(
            "거래 시도 지속시간과 상대 시간 프레임 근거가 일치하지 않습니다."
        )
    end_window = analysis_end - last_time
    boundary_state, near_start, near_end = _boundary_state(
        index=index,
        first_frame=first_frame,
        last_frame=last_frame,
        start_distance_ms=first_time,
        end_observation_window_ms=end_window,
        threshold_ms=threshold_ms,
    )
    return TransactionTimeBoundary(
        attempt_id=attempt_id,
        protocol=protocol,
        attempt_state=state,
        boundary_state=boundary_state,
        first_frame=first_frame,
        last_frame=last_frame,
        start_distance_ms=first_time,
        end_observation_window_ms=end_window,
        observed_attempt_duration_ms=observed_duration,
        start_near_boundary=near_start,
        end_near_boundary=near_end,
        display_filter=_display_filter(first_frame, last_frame),
    )


def build_capture_time_boundaries(
    index: CaptureTimeIndex,
    transaction_report: object,
    *,
    boundary_threshold_ms: int = _DEFAULT_BOUNDARY_THRESHOLD_MS,
) -> CaptureTimeBoundaryReport:
    """Combine the relative frame index with identifier-free transactions."""

    if not isinstance(index, CaptureTimeIndex):
        raise CaptureTimeBoundaryError(
            "검증된 상대 시간 프레임 인덱스가 필요합니다."
        )
    if (
        type(boundary_threshold_ms) is not int
        or not 1 <= boundary_threshold_ms <= 60_000
    ):
        raise CaptureTimeBoundaryError(
            "거래 경계 표시 임계값이 허용 범위를 벗어났습니다."
        )
    attempts, source_complete = _attempts(transaction_report)
    seen = set()
    boundaries = []
    for attempt in attempts:
        attempt_id = getattr(attempt, "attempt_id", None)
        if attempt_id in seen:
            raise CaptureTimeBoundaryError("거래 시도 ID가 중복됐습니다.")
        seen.add(attempt_id)
        boundaries.append(
            _build_transaction_boundary(
                index,
                attempt,
                boundary_threshold_ms,
            )
        )

    cautions = [
        "모든 시간은 첫 분석 프레임 기준 상대 밀리초이며 절대 시각을 기록하지 않습니다.",
        "종료 뒤 관찰 시간이 길어도 프로토콜별 응답 대기 시간이 충분했다는 증명이 아닙니다.",
        "거래가 분석 창 내부에 있어도 캡처가 장애 전·후 전체 구간을 포함했다는 뜻은 아닙니다.",
        "타임스탬프가 존재해도 캡처 손실이 없었다는 뜻은 아닙니다.",
    ]
    if not index.complete:
        cautions.insert(
            0,
            "패킷 상한 또는 사전 점검 불완전으로 캡처 전체 종료 시각을 확인하지 못했습니다.",
        )
    if index.timestamp_regressions:
        cautions.insert(
            0,
            "파일 순서상 타임스탬프 역행이 있어 거래 경계 위치를 확정하지 않습니다.",
        )
    if not source_complete:
        cautions.insert(
            0,
            "일부 이벤트가 생략되어 거래 경계 목록이 완전하지 않을 수 있습니다.",
        )

    return CaptureTimeBoundaryReport(
        profile_id=index.profile_id,
        profile_version=index.profile_version,
        frames_observed=index.frames_observed,
        expected_frames=index.expected_frames,
        complete=index.complete and source_complete,
        first_frame=index.first_frame,
        last_frame=index.last_frame,
        first_to_last_relative_ms=index.first_to_last_relative_ms,
        minimum_relative_ms=index.minimum_relative_ms,
        maximum_relative_ms=index.maximum_relative_ms,
        observed_span_ms=index.observed_span_ms,
        timestamp_regressions=index.timestamp_regressions,
        regression_evidence_frames=index.regression_evidence_frames,
        regression_evidence_frames_omitted=index.regression_evidence_frames_omitted,
        boundary_threshold_ms=boundary_threshold_ms,
        transaction_source_complete=source_complete,
        transaction_attempts_total=len(attempts),
        transaction_boundaries=tuple(boundaries),
        absolute_timestamps_serialized=False,
        capture_start_proven=False,
        capture_end_proven=False,
        incident_window_fully_covered=False,
        response_wait_sufficiency_assessed=False,
        response_absence_confirmed=False,
        capture_loss_excluded=False,
        root_cause_confirmed=False,
        cautions=tuple(cautions),
    )
