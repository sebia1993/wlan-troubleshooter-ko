import unittest
from types import SimpleNamespace

from wlan_troubleshooter_ko.ui.eapol_replay_relations import (
    format_eapol_replay_relations,
    install,
)


class EapolReplayRelationsUiTests(unittest.TestCase):
    def report(self):
        repeated = SimpleNamespace(
            message_number=3,
            state="same-counter-observed",
            evidence_frames=(7, 8),
        )
        observation = SimpleNamespace(
            observation_id="EAPOL-HS-1",
            device_alias="DEVICE-1",
            ap_alias="AP-1",
            state="expected-relations-observed",
            summary_ko="관계만 관찰했습니다.",
            m1_m2_relation="equal-observed",
            m3_m4_relation="equal-observed",
            m1_m3_progression="increased-observed",
            repeated_message_relations=(repeated,),
            frames_with_counter=(5, 6, 7, 8, 9),
            missing_counter_frames=(),
            evidence_frames=(5, 6, 7, 8, 9),
            display_filter=(
                "frame.number == 5 || frame.number == 6 || "
                "frame.number == 7 || frame.number == 8 || "
                "frame.number == 9"
            ),
            same_handshake_confirmed=False,
            retransmission_confirmed=False,
            key_installation_confirmed=False,
            cryptographic_success_confirmed=False,
            root_cause_confirmed=False,
        )
        return SimpleNamespace(
            field_available=True,
            rows_observed=9,
            key_rows_observed=5,
            observations_source_total=1,
            observations_evaluated=1,
            complete=True,
            observations=(observation,),
            cautions=("Counter 원문은 표시하지 않습니다.",),
            raw_replay_counters_serialized=False,
            replay_counter_values_persisted=False,
            same_handshake_confirmed=False,
            retransmission_confirmed=False,
            key_installation_confirmed=False,
            cryptographic_success_confirmed=False,
            root_cause_confirmed=False,
        )

    def test_formatter_is_korean_relationship_only_and_identifier_free(self):
        result = SimpleNamespace(eapol_replay_relations=self.report())
        first = format_eapol_replay_relations(result)
        second = format_eapol_replay_relations(result)

        self.assertEqual(first, second)
        self.assertIn("[11. EAPOL Replay Counter 관계]", first)
        self.assertIn("EAPOL-HS-1", first)
        self.assertIn("DEVICE-1 ↔ AP-1", first)
        self.assertIn("같은 Counter 관계 관찰", first)
        self.assertIn("후반 Counter 증가 관계 관찰", first)
        self.assertIn("실제 재전송 확정: 아니오", first)
        self.assertIn("Counter 원문 직렬화 아니오", first)
        for forbidden in (
            "18446744073709551000",
            "192.0.2",
            "02:00:00",
            "example.test",
            "nonce",
            "key_mic",
            "key_data",
        ):
            self.assertNotIn(forbidden, first.casefold())

    def test_missing_report_is_explicit_and_conservative(self):
        value = format_eapol_replay_relations(
            SimpleNamespace(eapol_replay_relations=None)
        )
        self.assertIn("관계 분석 결과가 없습니다", value)
        self.assertIn("동일 Handshake를 추정하지 않습니다", value)

    def test_install_is_idempotent(self):
        module = SimpleNamespace(
            format_analysis_detail=lambda _result: "기존 결과",
        )
        install(module)
        first_function = module.format_analysis_detail
        install(module)

        self.assertIs(module.format_analysis_detail, first_function)
        rendered = module.format_analysis_detail(
            SimpleNamespace(eapol_replay_relations=self.report())
        )
        self.assertTrue(rendered.startswith("기존 결과"))
        self.assertEqual(rendered.count("[11. EAPOL Replay Counter 관계]"), 1)


if __name__ == "__main__":
    unittest.main()
