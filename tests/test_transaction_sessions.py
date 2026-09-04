import json
import unittest
from dataclasses import dataclass

from wlan_troubleshooter_ko.analysis.transaction_sessions import (
    TransactionSessionError,
    build_transaction_sessions,
)


@dataclass(frozen=True)
class FakeEvent:
    event_type: str
    frame_number: int
    relative_time_ms: int
    correlation_alias: str | None


@dataclass(frozen=True)
class FakeTimeline:
    events: tuple[FakeEvent, ...]
    complete: bool = True
    events_total: int | None = None
    events_retained: int | None = None
    events_omitted: int = 0

    def __post_init__(self):
        retained = len(self.events) if self.events_retained is None else self.events_retained
        total = retained + self.events_omitted if self.events_total is None else self.events_total
        object.__setattr__(self, "events_retained", retained)
        object.__setattr__(self, "events_total", total)


class TransactionSessionTests(unittest.TestCase):
    def attempts(self, events, **timeline_values):
        return build_transaction_sessions(
            FakeTimeline(tuple(events), **timeline_values)
        ).attempts

    def test_eap_complete_and_radius_failure_are_separate_attempts(self):
        attempts = self.attempts(
            (
                FakeEvent("eap_request", 1, 0, "EAP-1"),
                FakeEvent("eap_response", 2, 10, "EAP-1"),
                FakeEvent("eap_success", 3, 20, "EAP-1"),
                FakeEvent("radius_access_request", 4, 30, "RADIUS-1"),
                FakeEvent("radius_access_reject", 5, 40, "RADIUS-1"),
            )
        )

        self.assertEqual([item.attempt_id for item in attempts], ["EAP-1-A1", "RADIUS-1-A1"])
        self.assertEqual(attempts[0].state, "complete")
        self.assertEqual(attempts[1].state, "failure-observed")
        self.assertFalse(any(item.root_cause_confirmed for item in attempts))
        self.assertFalse(any(item.device_session_confirmed for item in attempts))

    def test_reused_dns_alias_is_split_after_each_terminal_response(self):
        attempts = self.attempts(
            (
                FakeEvent("dns_query", 1, 0, "DNS-1"),
                FakeEvent("dns_response_success", 2, 30, "DNS-1"),
                FakeEvent("dns_query", 3, 100, "DNS-1"),
                FakeEvent("dns_response_error", 4, 130, "DNS-1"),
            )
        )

        self.assertEqual([item.attempt_id for item in attempts], ["DNS-1-A1", "DNS-1-A2"])
        self.assertEqual([item.state for item in attempts], ["complete", "failure-observed"])

    def test_dhcp_full_sequence_is_complete_but_ack_only_is_not(self):
        attempts = self.attempts(
            (
                FakeEvent("dhcp_discover", 1, 0, "DHCP-1"),
                FakeEvent("dhcp_offer", 2, 10, "DHCP-1"),
                FakeEvent("dhcp_request", 3, 20, "DHCP-1"),
                FakeEvent("dhcp_ack", 4, 30, "DHCP-1"),
                FakeEvent("dhcp_ack", 5, 40, "DHCP-2"),
            )
        )

        self.assertEqual(attempts[0].state, "complete")
        self.assertEqual(attempts[1].state, "success-observed")
        self.assertIn("dhcp_discover", attempts[1].missing_event_types)

    def test_tcp_syn_ack_is_not_claimed_as_three_way_handshake_complete(self):
        attempts = self.attempts(
            (
                FakeEvent("tcp_syn", 1, 0, "TCP-1"),
                FakeEvent("tcp_syn_ack", 2, 15, "TCP-1"),
                FakeEvent("tls_client_hello", 3, 30, "TCP-1"),
            )
        )

        self.assertEqual(len(attempts), 1)
        self.assertEqual(attempts[0].state, "success-observed")
        self.assertNotEqual(attempts[0].state, "complete")
        self.assertIn("tls_client_hello", attempts[0].observed_event_types)

    def test_tcp_reset_ends_attempt_and_next_syn_starts_new_attempt(self):
        attempts = self.attempts(
            (
                FakeEvent("tcp_syn", 1, 0, "TCP-1"),
                FakeEvent("tcp_reset", 2, 5, "TCP-1"),
                FakeEvent("tcp_syn", 3, 100, "TCP-1"),
            )
        )

        self.assertEqual([item.attempt_id for item in attempts], ["TCP-1-A1", "TCP-1-A2"])
        self.assertEqual(attempts[0].state, "failure-observed")
        self.assertEqual(attempts[1].state, "incomplete")

    def test_unassigned_wireless_events_are_counted_without_becoming_sessions(self):
        report = build_transaction_sessions(
            FakeTimeline(
                (
                    FakeEvent("wlan_assoc_request", 1, 0, None),
                    FakeEvent("eap_request", 2, 10, "EAP-1"),
                )
            )
        )

        self.assertEqual(report.unassigned_event_count, 1)
        self.assertEqual(len(report.attempts), 1)

    def test_omitted_or_partial_timeline_is_never_marked_complete(self):
        omitted = build_transaction_sessions(
            FakeTimeline(
                (FakeEvent("dns_query", 1, 0, "DNS-1"),),
                events_total=2,
                events_retained=1,
                events_omitted=1,
            )
        )
        partial = build_transaction_sessions(
            FakeTimeline(
                (FakeEvent("dns_query", 1, 0, "DNS-1"),),
                complete=False,
            )
        )

        self.assertFalse(omitted.complete)
        self.assertFalse(partial.complete)
        self.assertTrue(any("생략" in value for value in omitted.cautions))
        self.assertTrue(any("일부 프레임" in value for value in partial.cautions))

    def test_result_is_deterministic_frame_backed_and_identifier_free(self):
        timeline = FakeTimeline(
            (
                FakeEvent("dns_query", 9, 100, "DNS-2"),
                FakeEvent("dns_response_success", 10, 130, "DNS-2"),
            )
        )
        first = build_transaction_sessions(timeline).to_dict()
        second = build_transaction_sessions(timeline).to_dict()
        rendered = json.dumps(first, ensure_ascii=False)

        self.assertEqual(first, second)
        self.assertIn("frame.number == 9", rendered)
        self.assertIn("frame.number == 10", rendered)
        for forbidden in ("192.0.2", "02:00:00", "example.test", "0x1234"):
            self.assertNotIn(forbidden, rendered)

    def test_invalid_alias_event_order_and_counts_are_rejected(self):
        invalid_events = (
            FakeEvent("dns_query", 1, 0, "DNS-0"),
            FakeEvent("dns query", 1, 0, "DNS-1"),
            FakeEvent("eap_request", 1, 0, "DNS-1"),
            FakeEvent("dns_query", 0, 0, "DNS-1"),
            FakeEvent("dns_query", 1, -1, "DNS-1"),
        )
        for event in invalid_events:
            with self.subTest(event=event):
                with self.assertRaises(TransactionSessionError):
                    build_transaction_sessions(FakeTimeline((event,)))

        with self.assertRaises(TransactionSessionError):
            build_transaction_sessions(
                FakeTimeline(
                    (
                        FakeEvent("dns_query", 2, 20, "DNS-1"),
                        FakeEvent("dns_response_success", 1, 10, "DNS-1"),
                    )
                )
            )
        with self.assertRaises(TransactionSessionError):
            build_transaction_sessions(
                FakeTimeline(
                    (FakeEvent("dns_query", 1, 0, "DNS-1"),),
                    events_total=99,
                )
            )


if __name__ == "__main__":
    unittest.main()
