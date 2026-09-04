import unittest
from types import SimpleNamespace

from wlan_troubleshooter_ko.ui.eapol_handshakes import (
    format_eapol_handshakes,
    install,
)


class EapolHandshakeUiTests(unittest.TestCase):
    def report(self):
        observation = SimpleNamespace(
            state="message-repetition-observed",
            observation_id="EAPOL-HS-1",
            device_alias="DEVICE-1",
            ap_alias="AP-1",
            summary_ko="M1~M4와 M3 반복이 관찰됐습니다.",
            observed_message_numbers=(1, 2, 3, 3, 4),
            first_observed_order=(1, 2, 3, 4),
            missing_message_numbers=(),
            repeated_message_numbers=(3,),
            retry_flag_frames=(14,),
            first_frame=10,
            last_frame=15,
            duration_ms=50,
            evidence_frames=(10, 11, 12, 14, 15),
            display_filter=(
                "frame.number == 10 || frame.number == 11 || "
                "frame.number == 12 || frame.number == 14 || "
                "frame.number == 15"
            ),
        )
        return SimpleNamespace(
            field_available=True,
            complete=True,
            source_key_events_total=5,
            linked_key_events=5,
            unassigned_key_events=0,
            ambiguous_key_events=0,
            source_timeline_complete=True,
            device_report_complete=True,
            device_evidence_complete=True,
            observations=(observation,),
            cautions=("동일 Handshake를 확정하지 않습니다.",),
            replay_counter_correlation_available=False,
            raw_key_material_serialized=False,
            raw_identifiers_serialized=False,
            same_handshake_confirmed=False,
            key_installation_confirmed=False,
            cryptographic_success_confirmed=False,
            root_cause_confirmed=False,
        )

    def test_formatter_is_korean_evidence_backed_and_conservative(self):
        result = SimpleNamespace(eapol_handshakes=self.report())
        first = format_eapol_handshakes(result)
        second = format_eapol_handshakes(result)

        self.assertEqual(first, second)
        self.assertIn("[10. EAPOL 4-Way Handshake 메시지 순서]", first)
        self.assertIn("EAPOL-HS-1", first)
        self.assertIn("DEVICE-1 ↔ AP-1", first)
        self.assertIn("M1 → M2 → M3 → M3 → M4", first)
        self.assertIn("Retry 비트 관찰 프레임: #14", first)
        self.assertIn("동일 Handshake 확정 아니오", first)
        self.assertIn("암호학적 성공 확정 아니오", first)
        self.assertIn("frame.number == 10", first)
        for forbidden in (
            "02:00:00",
            "nonce",
            "mic",
            "key_data",
            "192.0.2",
        ):
            self.assertNotIn(forbidden, first.casefold())

    def test_missing_report_is_explicit(self):
        value = format_eapol_handshakes(
            SimpleNamespace(eapol_handshakes=None)
        )
        self.assertIn("관찰 결과가 없습니다", value)

    def test_install_is_idempotent(self):
        module = SimpleNamespace(
            format_analysis_detail=lambda _result: "기존 결과",
        )
        install(module)
        first_function = module.format_analysis_detail
        install(module)

        self.assertIs(module.format_analysis_detail, first_function)
        rendered = module.format_analysis_detail(
            SimpleNamespace(eapol_handshakes=self.report())
        )
        self.assertTrue(rendered.startswith("기존 결과"))
        self.assertEqual(
            rendered.count("[10. EAPOL 4-Way Handshake 메시지 순서]"),
            1,
        )


if __name__ == "__main__":
    unittest.main()
