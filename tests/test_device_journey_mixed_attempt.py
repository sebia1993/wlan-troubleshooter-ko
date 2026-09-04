import unittest

from wlan_troubleshooter_ko.analysis.device_journeys import build_device_journeys
from wlan_troubleshooter_ko.analysis.device_sessions import (
    DeviceAttemptLink,
    DeviceSession,
    DeviceSessionReport,
)
from wlan_troubleshooter_ko.analysis.transaction_sessions import (
    TransactionAttempt,
    TransactionSessionReport,
)


class DeviceJourneyMixedAttemptTests(unittest.TestCase):
    def test_single_mixed_attempt_is_both_failure_and_success_direction(self):
        attempt = TransactionAttempt(
            attempt_id="TCP-1-A1",
            correlation_alias="TCP-1",
            protocol="tcp",
            label_ko="TCP 연결",
            state="mixed",
            summary_ko="SYN/ACK와 RST가 같은 시도에 관찰됨",
            event_count=3,
            first_frame=10,
            last_frame=12,
            duration_ms=20,
            evidence_frames=(10, 11, 12),
            evidence_frames_omitted=0,
            display_filter=(
                "frame.number == 10 || frame.number == 11 || frame.number == 12"
            ),
            observed_event_types=("tcp_syn", "tcp_syn_ack", "tcp_reset"),
            missing_event_types=(),
            next_checks_ko=("서버·방화벽 로그를 확인합니다.",),
            root_cause_confirmed=False,
            device_session_confirmed=False,
        )
        transactions = TransactionSessionReport(
            attempts=(attempt,),
            attempts_by_protocol=(("tcp", 1),),
            attempts_by_state=(("mixed", 1),),
            unassigned_event_count=0,
            source_events_total=3,
            source_events_retained=3,
            source_events_omitted=0,
            complete=True,
            cautions=(),
        )
        device = DeviceSession(
            alias="DEVICE-1",
            first_frame=10,
            last_frame=12,
            duration_ms=20,
            frame_count=3,
            evidence_frames=(10, 11, 12),
            evidence_frames_omitted=0,
            evidence_types=("known-l2-address",),
            protocols_observed=("tcp",),
            ap_aliases=(),
            linked_attempt_ids=(attempt.attempt_id,),
            device_identity_confirmed=False,
            cross_protocol_session_confirmed=False,
        )
        devices = DeviceSessionReport(
            profile_id="device-identities",
            profile_version="0.5.0",
            frames_observed=3,
            expected_frames=3,
            complete=True,
            devices=(device,),
            attempt_links=(
                DeviceAttemptLink(
                    attempt_id=attempt.attempt_id,
                    state="linked",
                    device_alias=device.alias,
                    evidence_frames=attempt.evidence_frames,
                ),
            ),
            frames_unassigned=0,
            frames_ambiguous=0,
            attempts_unassigned=0,
            attempts_ambiguous=0,
            missing_optional_fields=(),
            raw_identifiers_serialized=False,
            alias_secret_persisted=False,
            aliases_stable_across_runs=False,
            cautions=(),
        )

        journey = build_device_journeys(devices, transactions).journeys[0]

        self.assertEqual(journey.state, "mixed")
        self.assertEqual(journey.first_failure_stage, "tcp")
        self.assertEqual(journey.last_positive_stage, "tcp")
        self.assertFalse(journey.root_cause_confirmed)


if __name__ == "__main__":
    unittest.main()
