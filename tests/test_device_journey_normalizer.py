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


class DeviceJourneyNormalizerTests(unittest.TestCase):
    def attempt(self):
        return TransactionAttempt(
            attempt_id="DNS-1-A1",
            correlation_alias="DNS-1",
            protocol="dns",
            label_ko="DNS 이름 조회",
            state="complete",
            summary_ko="합성 거래",
            event_count=2,
            first_frame=1,
            last_frame=2,
            duration_ms=10,
            evidence_frames=(1, 2),
            evidence_frames_omitted=3,
            display_filter="frame.number == 1 || frame.number == 2",
            observed_event_types=("dns_query", "dns_response_success"),
            missing_event_types=(),
            next_checks_ko=("DNS 로그 확인",),
            root_cause_confirmed=False,
            device_session_confirmed=False,
        )

    def transactions(self, attempt):
        return TransactionSessionReport(
            attempts=(attempt,),
            attempts_by_protocol=(("dns", 1),),
            attempts_by_state=(("complete", 1),),
            unassigned_event_count=0,
            source_events_total=5,
            source_events_retained=2,
            source_events_omitted=3,
            complete=False,
            cautions=("상세 이벤트 일부 생략",),
        )

    def report(self, link, devices=(), complete=False):
        return DeviceSessionReport(
            profile_id="device-identities",
            profile_version="0.5.0",
            frames_observed=2,
            expected_frames=2,
            complete=complete,
            devices=tuple(devices),
            attempt_links=(link,),
            frames_unassigned=0,
            frames_ambiguous=0,
            attempts_unassigned=int(link.state == "unassigned"),
            attempts_ambiguous=int(link.state == "ambiguous"),
            missing_optional_fields=(),
            raw_identifiers_serialized=False,
            alias_secret_persisted=False,
            aliases_stable_across_runs=False,
            cautions=(),
        )

    def test_omitted_unassigned_attempt_is_excluded_without_failure(self):
        attempt = self.attempt()
        device_report = self.report(
            DeviceAttemptLink(
                attempt_id=attempt.attempt_id,
                state="unassigned",
                device_alias=None,
                evidence_frames=(),
            )
        )

        result = build_device_journeys(
            device_report,
            self.transactions(attempt),
        )

        self.assertEqual(result.journeys, ())
        self.assertEqual(result.unassigned_attempts, 1)
        self.assertFalse(result.complete)
        self.assertFalse(result.linkage_complete)

    def test_omitted_ambiguous_attempt_is_excluded_without_failure(self):
        attempt = self.attempt()
        device_report = self.report(
            DeviceAttemptLink(
                attempt_id=attempt.attempt_id,
                state="ambiguous",
                device_alias=None,
                evidence_frames=(),
            )
        )

        result = build_device_journeys(
            device_report,
            self.transactions(attempt),
        )

        self.assertEqual(result.ambiguous_attempts, 1)
        self.assertFalse(result.complete)

    def test_omitted_attempt_can_never_be_linked_to_device(self):
        attempt = self.attempt()
        device = DeviceSession(
            alias="DEVICE-1",
            first_frame=1,
            last_frame=2,
            duration_ms=10,
            frame_count=2,
            evidence_frames=(1, 2),
            evidence_frames_omitted=0,
            evidence_types=("dhcp-client",),
            protocols_observed=("dns",),
            ap_aliases=(),
            linked_attempt_ids=(attempt.attempt_id,),
            device_identity_confirmed=False,
            cross_protocol_session_confirmed=False,
        )
        device_report = self.report(
            DeviceAttemptLink(
                attempt_id=attempt.attempt_id,
                state="linked",
                device_alias="DEVICE-1",
                evidence_frames=(1, 2),
            ),
            devices=(device,),
        )

        with self.assertRaises(DeviceJourneyError):
            build_device_journeys(
                device_report,
                self.transactions(attempt),
            )


if __name__ == "__main__":
    unittest.main()
