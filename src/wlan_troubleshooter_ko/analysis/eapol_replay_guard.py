"""Fail-closed guard for Phase 4I reports entering Phase 4J.

Phase 4I explicitly states that Replay Counter correlation is unavailable.
Phase 4J performs its own isolated extraction from the same capture. Therefore
an input report that already claims Replay Counter correlation was available
must be rejected instead of being trusted or silently re-used.
"""

from __future__ import annotations

from typing import Callable


class EapolReplayGuardError(ValueError):
    """The Phase 4I source report violates the Phase 4J trust boundary."""


def _require_false(value: object, name: str, label: str) -> None:
    try:
        observed = getattr(value, name)
    except (AttributeError, TypeError) as exc:
        raise EapolReplayGuardError(
            label + " Replay Counter 보호 플래그가 없습니다."
        ) from exc
    if observed is not False:
        raise EapolReplayGuardError(
            label + " Replay Counter 사용 가능 값은 false여야 합니다."
        )


def _observations(report: object) -> tuple[object, ...]:
    try:
        value = getattr(report, "observations")
    except (AttributeError, TypeError) as exc:
        raise EapolReplayGuardError(
            "EAPOL 순서 보고서 관찰 목록이 없습니다."
        ) from exc
    if not isinstance(value, (tuple, list)):
        raise EapolReplayGuardError(
            "EAPOL 순서 보고서 관찰 목록이 올바르지 않습니다."
        )
    return tuple(value)


def wrap_eapol_replay_relation_builder(
    original: Callable[..., object],
) -> Callable[..., object]:
    """Return a builder that rejects pre-correlated Phase 4I input."""

    def build(text: str, profile: object, handshake_report: object) -> object:
        _require_false(
            handshake_report,
            "replay_counter_correlation_available",
            "EAPOL 순서 보고서",
        )
        for observation in _observations(handshake_report):
            _require_false(
                observation,
                "replay_counter_correlation_available",
                "EAPOL 관찰",
            )
        return original(text, profile, handshake_report)

    build.__name__ = getattr(
        original,
        "__name__",
        "build_eapol_replay_relations",
    )
    build.__doc__ = original.__doc__
    return build
