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


class DeviceJourneyEapTests(unittest.TestCase):
    def test_safely_linked_eap_attempt_becomes_complete_stage(self):
        attempt = TransactionAttempt(
            attempt_id="EAP-1-A1",
            correlation_alias="EAP-1",
            protocol="eap",
            label_ko="EAP 단말 인증",
            state="complete",
            summary_ko="Request·Response·Success 관찰",
            event_count=3,
            first_frame=10,
            last_frame=12,
            duration_ms=25,
            evidence_frames=(10, 11, 12),
            evidence_frames_omitted=0,
            display_filter=(
                "frame.number == 10 || frame.number == 11 || frame.number == 12"
            ),
            observed_event_types=("eap_request", "eap_response", "eap_success"),
            missing_event_types=(),
            next_checks_ko=("Supplicant와 인증 서버 로그를 확인합니다.",),
            root_cause_confirmed=False,
            device_session_confirmed=False,
        )
        transactions = TransactionSessionReport(
            attempts=(attempt,),
            attempts_by_protocol=(("eap", 1),),
            attempts_by_state=(("complete", 1),),
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
            duration_ms=25,
            frame_count=3,
            evidence_frames=(10, 11, 12),
            evidence_frames_omitted=0,
            evidence_types=("wlan-eap-supplicant",),
            protocols_observed=("eap",),
            ap_aliases=("AP-1",),
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

        report = build_device_journeys(devices, transactions)
        journey = report.journeys[0]
        stage = journey.stages[0]

        self.assertEqual(journey.observed_stage_order, ("eap",))
        self.assertEqual(journey.state, "progress-observed")
        self.assertEqual(stage.protocol, "eap")
        self.assertEqual(stage.state, "complete")
        self.assertEqual(stage.attempt_ids, ("EAP-1-A1",))
        self.assertFalse(journey.device_identity_confirmed)
        self.assertFalse(journey.cross_protocol_session_confirmed)
        self.assertFalse(journey.root_cause_confirmed)


if __name__ == "__main__":
    unittest.main()
