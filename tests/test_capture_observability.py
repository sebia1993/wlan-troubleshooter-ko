import json
import unittest
from types import SimpleNamespace

from wlan_troubleshooter_ko.analysis.capture_observability import (
    CaptureObservabilityError,
    build_capture_observability,
)
from wlan_troubleshooter_ko.analysis.transaction_sessions import (
    TransactionAttempt,
    TransactionSessionReport,
)


class CaptureObservabilityTests(unittest.TestCase):
    def structure(self, *, packets=20, complete=True, truncated=0):
        return SimpleNamespace(
            packets_scanned=packets,
            scan_complete=complete,
            truncated_packets_observed=truncated,
        )

    def timeline(self, *, frames=20, complete=True, total=1, retained=1, omitted=0):
        return SimpleNamespace(
            frames_observed=frames,
            complete=complete,
            events_total=total,
            events_retained=retained,
            events_omitted=omitted,
        )

    def attempt(
        self,
        *,
        attempt_id="DNS-1-A1",
        protocol="dns",
        state="incomplete",
        first=5,
        last=6,
        events=("dns_query",),
        evidence=None,
        omitted=0,
        root=False,
    ):
        frames = tuple(range(first, last + 1)) if evidence is None else tuple(evidence)
        return TransactionAttempt(
            attempt_id=attempt_id,
            correlation_alias=attempt_id.rsplit("-A", 1)[0],
            protocol=protocol,
            label_ko=protocol,
            state=state,
            summary_ko="합성 거래",
            event_count=max(1, len(events)),
            first_frame=first,
            last_frame=last,
            duration_ms=(last - first) * 10,
            evidence_frames=frames,
            evidence_frames_omitted=omitted,
            display_filter=" || ".join(
                "frame.number == {0}".format(value) for value in frames
            ),
            observed_event_types=tuple(events),
            missing_event_types=(),
            next_checks_ko=("관련 로그 확인",),
            root_cause_confirmed=root,
            device_session_confirmed=False,
        )

    def transactions(
        self,
        attempts,
        *,
        complete=True,
        total=None,
        retained=None,
        omitted=0,
    ):
        event_total = (
            sum(item.event_count for item in attempts)
            if total is None
            else total
        )
        event_retained = event_total - omitted if retained is None else retained
        protocol_counts = {}
        state_counts = {}
        for item in attempts:
            protocol_counts[item.protocol] = protocol_counts.get(item.protocol, 0) + 1
            state_counts[item.state] = state_counts.get(item.state, 0) + 1
        return TransactionSessionReport(
            attempts=tuple(attempts),
            attempts_by_protocol=tuple(sorted(protocol_counts.items())),
            attempts_by_state=tuple(sorted(state_counts.items())),
            unassigned_event_count=0,
            source_events_total=event_total,
            source_events_retained=event_retained,
            source_events_omitted=omitted,
            complete=complete,
            cautions=(),
        )

    def report(self, attempt, *, structure=None, timeline=None, transactions=None):
        structure_value = self.structure() if structure is None else structure
        transaction_value = (
            self.transactions((attempt,)) if transactions is None else transactions
        )
        timeline_value = (
            self.timeline(
                total=transaction_value.source_events_total,
                retained=transaction_value.source_events_retained,
                omitted=transaction_value.source_events_omitted,
            )
            if timeline is None
            else timeline
        )
        return build_capture_observability(
            structure_value,
            timeline_value,
            transaction_value,
        )

    def test_middle_incomplete_query_is_response_not_observed_not_failure(self):
        value = self.report(self.attempt()).to_dict()
        assessment = value["incomplete_attempts"][0]

        self.assertTrue(value["analysis_input_complete"])
        self.assertEqual(assessment["assessment"], "response-not-observed")
        self.assertTrue(assessment["request_event_observed"])
        self.assertFalse(assessment["reply_event_observed"])
        self.assertFalse(assessment["absence_is_failure"])
        self.assertFalse(value["absence_can_confirm_failure"])
        self.assertFalse(value["capture_start_proven"])
        self.assertFalse(value["capture_end_proven"])
        self.assertFalse(value["capture_loss_excluded"])
        self.assertFalse(value["directionality_proven"])

    def test_file_edge_attempts_are_capture_boundary_risk(self):
        for attempt in (
            self.attempt(first=1, last=2, evidence=(1, 2)),
            self.attempt(first=19, last=20, evidence=(19, 20)),
        ):
            with self.subTest(attempt=attempt):
                assessment = self.report(attempt).incomplete_attempts[0]
                self.assertEqual(assessment.assessment, "capture-boundary-risk")
                self.assertTrue(
                    any("boundary-risk" in item for item in assessment.risk_flags)
                )
                self.assertFalse(assessment.absence_is_failure)

    def test_truncated_packets_take_precedence_over_middle_absence(self):
        report = self.report(
            self.attempt(),
            structure=self.structure(truncated=1),
        )
        assessment = report.incomplete_attempts[0]

        self.assertEqual(assessment.assessment, "packet-truncation-risk")
        self.assertIn("packet-truncation-observed", assessment.risk_flags)
        self.assertFalse(report.capture_loss_excluded)

    def test_partial_or_omitted_input_is_insufficient(self):
        attempt = self.attempt(omitted=1)
        transactions = self.transactions(
            (attempt,),
            complete=False,
            total=2,
            retained=1,
            omitted=1,
        )
        report = self.report(
            attempt,
            structure=self.structure(complete=False),
            timeline=self.timeline(
                complete=False,
                total=2,
                retained=1,
                omitted=1,
            ),
            transactions=transactions,
        )
        assessment = report.incomplete_attempts[0]

        self.assertFalse(report.analysis_input_complete)
        self.assertEqual(assessment.assessment, "insufficient-analysis-input")
        self.assertIn("analysis-input-incomplete", assessment.risk_flags)
        self.assertIn("event-detail-omitted", assessment.risk_flags)
        self.assertIn("attempt-evidence-omitted", assessment.risk_flags)

    def test_completed_attempt_is_not_reinterpreted_as_missing_response(self):
        attempt = self.attempt(
            state="complete",
            events=("dns_query", "dns_response_success"),
        )
        report = self.report(attempt)

        self.assertEqual(report.incomplete_attempts, ())
        dns = next(
            item for item in report.protocol_visibility if item.protocol == "dns"
        )
        self.assertTrue(dns.request_event_observed)
        self.assertTrue(dns.reply_event_observed)
        self.assertTrue(dns.bidirectional_event_classes_observed)
        self.assertFalse(dns.directionality_proven)

    def test_visibility_is_protocol_specific_and_does_not_prove_direction(self):
        attempts = (
            self.attempt(
                attempt_id="EAP-1-A1",
                protocol="eap",
                state="complete",
                first=2,
                last=4,
                events=("eap_request", "eap_response", "eap_success"),
                evidence=(2, 3, 4),
            ),
            self.attempt(
                attempt_id="TCP-1-A1",
                protocol="tcp",
                state="incomplete",
                first=10,
                last=10,
                events=("tcp_syn",),
                evidence=(10,),
            ),
        )
        transactions = self.transactions(attempts, total=4, retained=4)
        report = build_capture_observability(
            self.structure(),
            self.timeline(total=4, retained=4),
            transactions,
        )
        visibility = {item.protocol: item for item in report.protocol_visibility}

        self.assertTrue(visibility["eap"].bidirectional_event_classes_observed)
        self.assertFalse(visibility["eap"].directionality_proven)
        self.assertTrue(visibility["tcp"].request_event_observed)
        self.assertFalse(visibility["tcp"].reply_event_observed)

    def test_serialization_is_deterministic_and_identifier_free(self):
        report = self.report(self.attempt())
        first = report.to_dict()
        second = report.to_dict()
        rendered = json.dumps(first, ensure_ascii=False)

        self.assertEqual(first, second)
        self.assertIn("DNS-1-A1", rendered)
        self.assertIn("frame.number == 5", rendered)
        for forbidden in (
            "192.0.2",
            "02:00:00",
            "example.test",
            "user@example",
            "0x1234",
        ):
            self.assertNotIn(forbidden, rendered)

    def test_inconsistent_counts_frames_and_confirmation_fail_closed(self):
        attempt = self.attempt()
        cases = (
            (
                self.structure(),
                self.timeline(total=2, retained=1, omitted=0),
                self.transactions((attempt,), total=1, retained=1),
            ),
            (
                self.structure(packets=20),
                self.timeline(frames=19, total=1, retained=1),
                self.transactions((attempt,), total=1, retained=1),
            ),
            (
                self.structure(),
                self.timeline(total=1, retained=1),
                self.transactions((self.attempt(root=True),), total=1, retained=1),
            ),
        )
        for values in cases:
            with self.subTest(values=values):
                with self.assertRaises(CaptureObservabilityError):
                    build_capture_observability(*values)


if __name__ == "__main__":
    unittest.main()
