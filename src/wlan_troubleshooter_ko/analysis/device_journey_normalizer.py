"""Normalize conservative Phase 4E/4F integration edge cases.

Phase 4E clears evidence only on a temporary transaction-report copy before
device linkage when a public attempt exceeded its evidence cap. Phase 4F must
compare against the same redacted copy without ever making such an attempt
eligible for linkage. The wrapper also treats an explicitly mixed stage as
both a success-direction and failure observation while preserving the mixed
journey state.
"""

from __future__ import annotations

from dataclasses import is_dataclass, replace
from typing import Callable, Optional


_UNLINKED_STATES = {"unassigned", "ambiguous"}


def _redact_omitted_unlinked_attempts(
    device_sessions: object,
    transaction_sessions: object,
) -> object:
    """Mirror Phase 4E's temporary evidence redaction for safe exclusion."""

    try:
        links = tuple(getattr(device_sessions, "attempt_links"))
        attempts = tuple(getattr(transaction_sessions, "attempts"))
    except (AttributeError, TypeError):
        return transaction_sessions

    link_by_attempt = {}
    for link in links:
        attempt_id = getattr(link, "attempt_id", None)
        if not isinstance(attempt_id, str) or attempt_id in link_by_attempt:
            return transaction_sessions
        link_by_attempt[attempt_id] = link

    normalized = []
    changed = False
    for attempt in attempts:
        attempt_id = getattr(attempt, "attempt_id", None)
        omitted = getattr(attempt, "evidence_frames_omitted", None)
        link = link_by_attempt.get(attempt_id)
        if (
            type(omitted) is int
            and omitted > 0
            and link is not None
            and getattr(link, "state", None) in _UNLINKED_STATES
            and getattr(link, "device_alias", None) is None
            and tuple(getattr(link, "evidence_frames", ())) == ()
        ):
            if not is_dataclass(attempt):
                return transaction_sessions
            attempt = replace(
                attempt,
                evidence_frames=(),
                display_filter="",
            )
            changed = True
        normalized.append(attempt)

    if not changed or not is_dataclass(transaction_sessions):
        return transaction_sessions
    return replace(
        transaction_sessions,
        attempts=tuple(normalized),
    )


def _mixed_last_positive_stage(journey: object) -> Optional[str]:
    """Return the latest mixed stage, which contains a success direction."""

    try:
        stages = tuple(getattr(journey, "stages"))
    except (AttributeError, TypeError):
        return None
    candidates = [
        stage
        for stage in stages
        if getattr(stage, "state", None) == "mixed"
    ]
    if not candidates:
        return None
    selected = max(
        candidates,
        key=lambda stage: (
            getattr(stage, "last_frame", -1),
            getattr(stage, "first_frame", -1),
            getattr(stage, "protocol", ""),
        ),
    )
    protocol = getattr(selected, "protocol", None)
    return protocol if isinstance(protocol, str) and protocol else None


def _normalize_mixed_last_positive(report: object) -> object:
    """Preserve mixed state while recording its success-direction progress."""

    if not is_dataclass(report):
        return report
    try:
        journeys = tuple(getattr(report, "journeys"))
    except (AttributeError, TypeError):
        return report

    normalized = []
    changed = False
    for journey in journeys:
        if not is_dataclass(journey):
            return report
        mixed_protocol = _mixed_last_positive_stage(journey)
        if mixed_protocol is None:
            normalized.append(journey)
            continue

        stages = tuple(getattr(journey, "stages", ()))
        current_protocol = getattr(journey, "last_positive_stage", None)
        current_stage = next(
            (
                stage
                for stage in stages
                if getattr(stage, "protocol", None) == current_protocol
            ),
            None,
        )
        mixed_stage = next(
            (
                stage
                for stage in stages
                if getattr(stage, "protocol", None) == mixed_protocol
            ),
            None,
        )
        if mixed_stage is None:
            return report
        current_last = (
            getattr(current_stage, "last_frame", -1)
            if current_stage is not None
            else -1
        )
        mixed_last = getattr(mixed_stage, "last_frame", -1)
        if mixed_last > current_last:
            journey = replace(
                journey,
                last_positive_stage=mixed_protocol,
            )
            changed = True
        normalized.append(journey)

    if not changed:
        return report
    return replace(report, journeys=tuple(normalized))


def wrap_device_journey_builder(
    original: Callable[..., object],
) -> Callable[..., object]:
    """Return a strict builder with Phase 4E redaction compatibility."""

    def build(device_sessions: object, transaction_sessions: object) -> object:
        normalized_transactions = _redact_omitted_unlinked_attempts(
            device_sessions,
            transaction_sessions,
        )
        report = original(device_sessions, normalized_transactions)
        return _normalize_mixed_last_positive(report)

    build.__name__ = getattr(original, "__name__", "build_device_journeys")
    build.__doc__ = original.__doc__
    return build
