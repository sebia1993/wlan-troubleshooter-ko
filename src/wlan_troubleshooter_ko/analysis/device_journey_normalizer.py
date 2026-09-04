"""Normalize Phase 4E's intentionally redacted unlinked transaction evidence.

Phase 4E clears packet evidence only on a temporary transaction-report copy
before device linkage when the original attempt had more evidence than the
public cap. The public Phase 4D report remains unchanged. Phase 4F must compare
link evidence with the same redacted copy, but must never make such an attempt
eligible for linking.
"""

from __future__ import annotations

from dataclasses import is_dataclass, replace
from typing import Callable


_UNLINKED_STATES = {"unassigned", "ambiguous"}


def wrap_device_journey_builder(original: Callable[..., object]) -> Callable[..., object]:
    """Return a builder that mirrors Phase 4E redaction for unlinked attempts.

    Malformed, linked or non-empty evidence is not rewritten. It is passed to
    the strict core builder and therefore fails closed under its normal
    validation rules.
    """

    def build(device_sessions: object, transaction_sessions: object) -> object:
        try:
            links = tuple(getattr(device_sessions, "attempt_links"))
            attempts = tuple(getattr(transaction_sessions, "attempts"))
        except (AttributeError, TypeError):
            return original(device_sessions, transaction_sessions)

        link_by_attempt = {}
        for link in links:
            attempt_id = getattr(link, "attempt_id", None)
            if not isinstance(attempt_id, str) or attempt_id in link_by_attempt:
                return original(device_sessions, transaction_sessions)
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
                    return original(device_sessions, transaction_sessions)
                attempt = replace(
                    attempt,
                    evidence_frames=(),
                    display_filter="",
                )
                changed = True
            normalized.append(attempt)

        if changed:
            if not is_dataclass(transaction_sessions):
                return original(device_sessions, transaction_sessions)
            transaction_sessions = replace(
                transaction_sessions,
                attempts=tuple(normalized),
            )
        return original(device_sessions, transaction_sessions)

    build.__name__ = getattr(original, "__name__", "build_device_journeys")
    build.__doc__ = original.__doc__
    return build
