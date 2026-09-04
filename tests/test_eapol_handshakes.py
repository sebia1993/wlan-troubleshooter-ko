import json
import unittest

from wlan_troubleshooter_ko.analysis.device_sessions import (
    DeviceSession,
    DeviceSessionReport,
)
from wlan_troubleshooter_ko.analysis.eapol_handshakes import (
    EapolHandshakeError,
    build_eapol_handshakes,
)
from wlan_troubleshooter_ko.analysis.event_timeline import (
    EventTimeline,
    ProtocolEvent,
)


class EapolHandshakeTests(unittest.TestCase):
    def event(self, frame, message, *, time=None):
        relative = frame * 10 if time is None else time
        return ProtocolEvent(
            frame_number=frame,
            relative_time_ms=relative,
            category="eapol",
            event_type="eapol_key_message_" + str(message),
            label_ko="4-Way Handshake 메시지 " + str(message),
            outcome="observed",
            code=None,
            correlation_alias=None,
            evidence_filter="frame.number == " + str(frame),
            details=(("message_number", str(message)),),
        )

    def retry(self, frame, *, time=None):
        relative = frame * 10 if time is None else time
        return ProtocolEvent(
            frame_number=frame,
            relative_time_ms=relative,
            category="wlan",
            event_type="wlan_retry_flag",
            label_ko="802.11 Retry 비트 설정 프레임",
            outcome="warning",
            code=None,
            correlation_alias=None,
            evidence_filter="frame.number == " + str(frame),
            details=(),
        )

    def timeline(self, events, *, complete=True, omitted=0, missing=()):
        values = tuple(events)
        return EventTimeline(
            profile_id="event-timeline",
            profile_version="0.5.0",
            frames_observed=max((item.frame_number for item in values), default=0),
            expected_frames=max((item.frame_number for item in values), default=0),
            complete=complete,
            events_total=len(values) + omitted,
            events_retained=len(values),
            events_omitted=omitted,
            events=values,
            summaries=(),
            stages=(),
            missing_optional_fields=tuple(missing),
            cautions=(),
        )

    def device_report(
        self,
        frames,
        *,
        aps=("AP-1",),
        complete=True,
        omitted=0,
        raw=False,
        secret=False,
        stable=False,
    ):
        device = DeviceSession(
            alias="DEVICE-1",
            first_frame=min(frames) if frames else 1,
            last_frame=max(frames) if frames else 1,
            duration_ms=max(0, (max(frames) - min(frames)) * 10) if frames else 0,
            frame_count=len(frames),
            evidence_frames=tuple(frames),
            evidence_frames_omitted=omitted,
            evidence_types=("wlan-eap-supplicant",),
            protocols_observed=("eapol",),
            ap_aliases=tuple(aps),
            linked_attempt_ids=(),
            device_identity_confirmed=False,
            cross_protocol_session_confirmed=False,
        )
        return DeviceSessionReport(
            profile_id="device-identities",
            profile_version="0.5.0",
            frames_observed=max(frames) if frames else 0,
            expected_frames=max(frames) if frames else 0,
            complete=complete,
            devices=(device,),
            attempt_links=(),
            frames_unassigned=0,
            frames_ambiguous=0,
            attempts_unassigned=0,
            attempts_ambiguous=0,
            missing_optional_fields=(),
            raw_identifiers_serialized=raw,
            alias_secret_persisted=secret,
            aliases_stable_across_runs=stable,
            cautions=(),
        )

    def test_complete_message_sequence_is_observation_not_success_claim(self):
        timeline = self.timeline(
            tuple(self.event(frame, frame) for frame in range(1, 5))
        )
        report = build_eapol_handshakes(
            timeline,
            self.device_report((1, 2, 3, 4)),
        )
        observation = report.observations[0]

        self.assertTrue(report.complete)
        self.assertEqual(report.linked_key_events, 4)
        self.assertEqual(observation.observation_id, "EAPOL-HS-1")
        self.assertEqual(observation.device_alias, "DEVICE-1")
        self.assertEqual(observation.ap_alias, "AP-1")
        self.assertEqual(observation.state, "sequence-observed")
        self.assertEqual(observation.first_observed_order, (1, 2, 3, 4))
        self.assertEqual(observation.missing_message_numbers, ())
        self.assertFalse(observation.same_handshake_confirmed)
        self.assertFalse(observation.key_installation_confirmed)
        self.assertFalse(observation.cryptographic_success_confirmed)
        self.assertFalse(observation.root_cause_confirmed)

    def test_repeated_m3_and_retry_bit_are_reported_without_retransmission_claim(self):
        timeline = self.timeline(
            (
                self.event(1, 1),
                self.event(2, 2),
                self.event(3, 3),
                self.retry(4),
                self.event(4, 3),
                self.event(5, 4),
            )
        )
        observation = build_eapol_handshakes(
            timeline,
            self.device_report((1, 2, 3, 4, 5)),
        ).observations[0]

        self.assertEqual(observation.state, "message-repetition-observed")
        self.assertEqual(observation.observed_message_numbers, (1, 2, 3, 3, 4))
        self.assertEqual(observation.repeated_message_numbers, (3,))
        self.assertEqual(observation.retry_flag_frames, (4,))
        self.assertFalse(observation.replay_counter_correlation_available)

    def test_out_of_order_messages_are_not_sequence_observed(self):
        observation = build_eapol_handshakes(
            self.timeline(
                (
                    self.event(1, 1),
                    self.event(2, 3),
                    self.event(3, 2),
                    self.event(4, 4),
                )
            ),
            self.device_report((1, 2, 3, 4)),
        ).observations[0]

        self.assertEqual(observation.state, "out-of-order")
        self.assertEqual(observation.first_observed_order, (1, 3, 2, 4))

    def test_new_m1_after_progress_starts_new_observation(self):
        report = build_eapol_handshakes(
            self.timeline(
                (
                    self.event(1, 1),
                    self.event(2, 2),
                    self.event(3, 1),
                    self.event(4, 2),
                    self.event(5, 3),
                    self.event(6, 4),
                )
            ),
            self.device_report((1, 2, 3, 4, 5, 6)),
        )

        self.assertEqual(len(report.observations), 2)
        self.assertEqual(report.observations[0].state, "incomplete")
        self.assertEqual(report.observations[0].observed_message_numbers, (1, 2))
        self.assertEqual(report.observations[1].state, "sequence-observed")
        self.assertEqual(report.observations[1].observed_message_numbers, (1, 2, 3, 4))

    def test_multiple_ap_aliases_make_key_events_ambiguous(self):
        report = build_eapol_handshakes(
            self.timeline((self.event(1, 1), self.event(2, 2))),
            self.device_report((1, 2), aps=("AP-1", "AP-2")),
        )

        self.assertEqual(report.observations, ())
        self.assertEqual(report.ambiguous_key_events, 2)
        self.assertFalse(report.linkage_complete)
        self.assertFalse(report.complete)

    def test_missing_device_evidence_is_unassigned_and_partial(self):
        report = build_eapol_handshakes(
            self.timeline((self.event(5, 1),)),
            self.device_report((1, 2), omitted=3),
        )

        self.assertEqual(report.unassigned_key_events, 1)
        self.assertFalse(report.device_evidence_complete)
        self.assertFalse(report.complete)

    def test_missing_tshark_field_is_unavailable_not_no_handshake_claim(self):
        report = build_eapol_handshakes(
            self.timeline((), missing=("eapol_key_message",)),
            self.device_report((), complete=True),
        )

        self.assertFalse(report.field_available)
        self.assertFalse(report.complete)
        self.assertTrue(any("필드" in item for item in report.cautions))

    def test_privacy_flag_or_event_detail_mismatch_fails_closed(self):
        timeline = self.timeline((self.event(1, 1),))
        for values in (
            {"raw": True},
            {"secret": True},
            {"stable": True},
        ):
            with self.subTest(values=values):
                with self.assertRaises(EapolHandshakeError):
                    build_eapol_handshakes(
                        timeline,
                        self.device_report((1,), **values),
                    )

        bad = ProtocolEvent(
            frame_number=1,
            relative_time_ms=10,
            category="eapol",
            event_type="eapol_key_message_1",
            label_ko="4-Way Handshake 메시지 1",
            outcome="observed",
            code=None,
            correlation_alias=None,
            evidence_filter="frame.number == 1",
            details=(("message_number", "2"),),
        )
        with self.assertRaises(EapolHandshakeError):
            build_eapol_handshakes(
                self.timeline((bad,)),
                self.device_report((1,)),
            )

    def test_serialization_is_deterministic_and_contains_no_key_material(self):
        report = build_eapol_handshakes(
            self.timeline(
                tuple(self.event(frame, frame) for frame in range(1, 5))
            ),
            self.device_report((1, 2, 3, 4)),
        )
        first = report.to_dict()
        second = report.to_dict()
        rendered = json.dumps(first, ensure_ascii=False)

        self.assertEqual(first, second)
        self.assertIn("DEVICE-1", rendered)
        self.assertIn("AP-1", rendered)
        self.assertIn("frame.number == 1", rendered)
        for forbidden in (
            "02:00:00",
            "nonce",
            "mic",
            "key_data",
            "replay_counter",
            "192.0.2",
            "example.test",
        ):
            self.assertNotIn(forbidden, rendered.casefold())
        self.assertFalse(first["replay_counter_correlation_available"])
        self.assertFalse(first["raw_key_material_serialized"])
        self.assertFalse(first["raw_identifiers_serialized"])
        self.assertFalse(first["same_handshake_confirmed"])
        self.assertFalse(first["key_installation_confirmed"])
        self.assertFalse(first["cryptographic_success_confirmed"])
        self.assertFalse(first["root_cause_confirmed"])


if __name__ == "__main__":
    unittest.main()
