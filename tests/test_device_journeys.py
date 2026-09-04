import json
import unittest

from wlan_troubleshooter_ko.analysis.device_journeys import (
    DeviceJourneyError,
    build_device_journeys,
)
from wlan_troubleshooter_ko.analysis.device_sessions import (
    DeviceAttemptLink,
    DeviceSession,
    DeviceSessionReport,
)
from wlan_troubleshooter_ko.analysis.transaction_sessions import (
    TransactionAttempt,
    TransactionSessionReport,
)


class DeviceJourneyTests(unittest.TestCase):
    def attempt(
        self,
        attempt_id,
        protocol,
        state,
        first_frame,
        last_frame,
        observed,
        missing=(),
        omitted=0,
    ):
        return TransactionAttempt(
            attempt_id=attempt_id,
            correlation_alias=attempt_id.rsplit("-A", 1)[0],
            protocol=protocol,
            label_ko=protocol,
            state=state,
            summary_ko="합성 거래",
            event_count=max(1, len(observed)),
            first_frame=first_frame,
            last_frame=last_frame,
            duration_ms=(last_frame - first_frame) * 10,
            evidence_frames=tuple(range(first_frame, last_frame + 1)),
            evidence_frames_omitted=omitted,
            display_filter=" || ".join(
                "frame.number == {0}".format(value)
                for value in range(first_frame, last_frame + 1)
            ),
            observed_event_types=tuple(observed),
            missing_event_types=tuple(missing),
            next_checks_ko=(protocol + " 로그 확인",),
            root_cause_confirmed=False,
            device_session_confirmed=False,
        )

    def transactions(self, attempts, complete=True):
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
            source_events_total=sum(item.event_count for item in attempts),
            source_events_retained=sum(item.event_count for item in attempts),
            source_events_omitted=0,
            complete=complete,
            cautions=(),
        )

    def device(self, alias, linked_attempt_ids, ap_aliases=()):
        return DeviceSession(
            alias=alias,
            first_frame=1,
            last_frame=100,
            duration_ms=990,
            frame_count=20,
            evidence_frames=(1, 2, 3),
            evidence_frames_omitted=0,
            evidence_types=("dhcp-client",),
            protocols_observed=("dhcp", "dns", "tcp"),
            ap_aliases=tuple(ap_aliases),
            linked_attempt_ids=tuple(linked_attempt_ids),
            device_identity_confirmed=False,
            cross_protocol_session_confirmed=False,
        )

    def devices(self, device_values, links, complete=True):
        return DeviceSessionReport(
            profile_id="device-identities",
            profile_version="0.5.0",
            frames_observed=100,
            expected_frames=100,
            complete=complete,
            devices=tuple(device_values),
            attempt_links=tuple(links),
            frames_unassigned=0,
            frames_ambiguous=0,
            attempts_unassigned=sum(item.state == "unassigned" for item in links),
            attempts_ambiguous=sum(item.state == "ambiguous" for item in links),
            missing_optional_fields=(),
            raw_identifiers_serialized=False,
            alias_secret_persisted=False,
            aliases_stable_across_runs=False,
            cautions=(),
        )

    def linked_report(self, attempts, alias="DEVICE-1", ap_aliases=()):
        links = tuple(
            DeviceAttemptLink(item.attempt_id, "linked", alias, item.evidence_frames)
            for item in attempts
        )
        return self.devices(
            (self.device(alias, [item.attempt_id for item in attempts], ap_aliases),),
            links,
        )

    def test_dhcp_dns_tcp_progress_is_ordered_by_observed_frames(self):
        attempts = (
            self.attempt(
                "DHCP-1-A1",
                "dhcp",
                "complete",
                10,
                13,
                ("dhcp_discover", "dhcp_offer", "dhcp_request", "dhcp_ack"),
            ),
            self.attempt(
                "DNS-1-A1",
                "dns",
                "complete",
                20,
                21,
                ("dns_query", "dns_response_success"),
            ),
            self.attempt(
                "TCP-1-A1",
                "tcp",
                "success-observed",
                30,
                31,
                ("tcp_syn", "tcp_syn_ack"),
            ),
        )

        report = build_device_journeys(
            self.linked_report(attempts, ap_aliases=("AP-1",)),
            self.transactions(attempts),
        )
        journey = report.journeys[0]

        self.assertEqual(journey.device_alias, "DEVICE-1")
        self.assertEqual(journey.ap_aliases, ("AP-1",))
        self.assertEqual(journey.state, "progress-observed")
        self.assertEqual(journey.observed_stage_order, ("dhcp", "dns", "tcp"))
        self.assertEqual([item.protocol for item in journey.stages], ["dhcp", "dns", "tcp"])
        self.assertEqual(journey.last_positive_stage, "tcp")
        self.assertIsNone(journey.first_failure_stage)
        self.assertTrue(report.complete)

    def test_first_failure_stage_is_packet_order_not_static_protocol_order(self):
        attempts = (
            self.attempt(
                "DNS-1-A1",
                "dns",
                "failure-observed",
                10,
                11,
                ("dns_query", "dns_response_error"),
            ),
            self.attempt(
                "DHCP-1-A1",
                "dhcp",
                "complete",
                20,
                23,
                ("dhcp_discover", "dhcp_offer", "dhcp_request", "dhcp_ack"),
            ),
        )
        journey = build_device_journeys(
            self.linked_report(attempts),
            self.transactions(attempts),
        ).journeys[0]

        self.assertEqual(journey.state, "failure-observed")
        self.assertEqual(journey.first_failure_stage, "dns")
        self.assertEqual(journey.last_positive_stage, "dhcp")
        self.assertFalse(journey.root_cause_confirmed)

    def test_same_stage_success_and_failure_becomes_mixed(self):
        attempts = (
            self.attempt(
                "DNS-1-A1",
                "dns",
                "complete",
                10,
                11,
                ("dns_query", "dns_response_success"),
            ),
            self.attempt(
                "DNS-2-A1",
                "dns",
                "failure-observed",
                20,
                21,
                ("dns_query", "dns_response_error"),
            ),
        )
        journey = build_device_journeys(
            self.linked_report(attempts),
            self.transactions(attempts),
        ).journeys[0]

        self.assertEqual(journey.state, "mixed")
        self.assertEqual(journey.stages[0].state, "mixed")
        self.assertEqual(journey.first_failure_stage, "dns")

    def test_unassigned_and_ambiguous_attempts_are_not_in_device_journey(self):
        linked = self.attempt(
            "DHCP-1-A1",
            "dhcp",
            "complete",
            1,
            4,
            ("dhcp_discover", "dhcp_offer", "dhcp_request", "dhcp_ack"),
        )
        unassigned = self.attempt(
            "RADIUS-1-A1",
            "radius",
            "complete",
            5,
            6,
            ("radius_access_request", "radius_access_accept"),
        )
        ambiguous = self.attempt(
            "DNS-1-A1",
            "dns",
            "complete",
            7,
            8,
            ("dns_query", "dns_response_success"),
        )
        attempts = (linked, unassigned, ambiguous)
        device_report = self.devices(
            (self.device("DEVICE-1", (linked.attempt_id,)),),
            (
                DeviceAttemptLink(linked.attempt_id, "linked", "DEVICE-1", linked.evidence_frames),
                DeviceAttemptLink(unassigned.attempt_id, "unassigned", None, unassigned.evidence_frames),
                DeviceAttemptLink(ambiguous.attempt_id, "ambiguous", None, ambiguous.evidence_frames),
            ),
        )

        report = build_device_journeys(device_report, self.transactions(attempts))

        self.assertEqual(report.journeys[0].linked_attempt_ids, ("DHCP-1-A1",))
        self.assertEqual(report.unassigned_attempts, 1)
        self.assertEqual(report.ambiguous_attempts, 1)
        self.assertFalse(report.linkage_complete)
        self.assertFalse(report.complete)
        self.assertTrue(any("시간만으로" in item for item in report.cautions))

    def test_device_without_transactions_is_retained_without_success_claim(self):
        report = build_device_journeys(
            self.devices((self.device("DEVICE-1", ()),), ()),
            self.transactions(()),
        )
        journey = report.journeys[0]

        self.assertEqual(journey.state, "no-linked-transactions")
        self.assertEqual(journey.stages, ())
        self.assertEqual(report.devices_without_linked_attempts, 1)

    def test_partial_sources_make_report_incomplete(self):
        attempt = self.attempt(
            "DNS-1-A1",
            "dns",
            "complete",
            1,
            2,
            ("dns_query", "dns_response_success"),
        )
        report = build_device_journeys(
            self.devices(
                (self.device("DEVICE-1", (attempt.attempt_id,)),),
                (DeviceAttemptLink(attempt.attempt_id, "linked", "DEVICE-1", attempt.evidence_frames),),
                complete=False,
            ),
            self.transactions((attempt,), complete=True),
        )

        self.assertFalse(report.source_complete)
        self.assertFalse(report.complete)
        self.assertTrue(any("일부 결과" in item for item in report.cautions))

    def test_serialization_is_deterministic_and_contains_no_raw_identifiers(self):
        attempt = self.attempt(
            "DNS-1-A1",
            "dns",
            "complete",
            9,
            10,
            ("dns_query", "dns_response_success"),
        )
        devices = self.linked_report((attempt,), ap_aliases=("AP-1",))
        transactions = self.transactions((attempt,))
        first = build_device_journeys(devices, transactions).to_dict()
        second = build_device_journeys(devices, transactions).to_dict()
        rendered = json.dumps(first, ensure_ascii=False)

        self.assertEqual(first, second)
        self.assertIn("DEVICE-1", rendered)
        self.assertIn("frame.number == 9", rendered)
        for forbidden in (
            "192.0.2",
            "02:00:00",
            "example.test",
            "0x1234",
            "user@example",
        ):
            self.assertNotIn(forbidden, rendered)
        self.assertFalse(first["raw_identifiers_serialized"])
        self.assertFalse(first["aliases_stable_across_runs"])
        self.assertFalse(first["device_identity_confirmed"])
        self.assertFalse(first["cross_protocol_session_confirmed"])
        self.assertFalse(first["root_cause_confirmed"])

    def test_unknown_duplicate_or_inconsistent_links_fail_closed(self):
        attempt = self.attempt(
            "DNS-1-A1",
            "dns",
            "complete",
            1,
            2,
            ("dns_query", "dns_response_success"),
        )
        transactions = self.transactions((attempt,))
        cases = (
            self.devices(
                (self.device("DEVICE-1", ("DNS-9-A1",)),),
                (DeviceAttemptLink("DNS-9-A1", "linked", "DEVICE-1", (1,)),),
            ),
            self.devices(
                (self.device("DEVICE-1", (attempt.attempt_id,)),),
                (
                    DeviceAttemptLink(attempt.attempt_id, "linked", "DEVICE-1", (1, 2)),
                    DeviceAttemptLink(attempt.attempt_id, "linked", "DEVICE-1", (1, 2)),
                ),
            ),
            self.devices(
                (self.device("DEVICE-1", ()),),
                (DeviceAttemptLink(attempt.attempt_id, "linked", "DEVICE-1", (1, 2)),),
            ),
        )
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(DeviceJourneyError):
                    build_device_journeys(value, transactions)

    def test_linked_attempt_with_truncated_evidence_is_rejected(self):
        attempt = self.attempt(
            "DNS-1-A1",
            "dns",
            "complete",
            1,
            2,
            ("dns_query", "dns_response_success"),
            omitted=1,
        )
        with self.assertRaises(DeviceJourneyError):
            build_device_journeys(
                self.linked_report((attempt,)),
                self.transactions((attempt,)),
            )


if __name__ == "__main__":
    unittest.main()
