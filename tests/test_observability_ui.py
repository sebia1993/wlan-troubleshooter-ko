import unittest
from types import SimpleNamespace

from wlan_troubleshooter_ko.ui.observability import (
    format_observability,
    install,
)


class ObservabilityUiTests(unittest.TestCase):
    def report(self):
        visibility = SimpleNamespace(
            protocol="dns",
            request_event_observed=True,
            reply_event_observed=False,
            bidirectional_event_classes_observed=False,
            directionality_proven=False,
        )
        attempt = SimpleNamespace(
            assessment="capture-boundary-risk",
            attempt_id="DNS-1-A1",
            protocol="dns",
            summary_ko="캡처 종료 경계에 닿았습니다.",
            first_frame=4,
            last_frame=4,
            evidence_frames=(4,),
            risk_flags=("capture-end-boundary-risk",),
            request_event_observed=True,
            reply_event_observed=False,
            absence_is_failure=False,
            display_filter="frame.number == 4",
        )
        return SimpleNamespace(
            analysis_input_complete=True,
            container_scan_complete=True,
            event_timeline_complete=True,
            transaction_report_complete=True,
            packets_scanned=4,
            frames_observed=4,
            truncated_packets_observed=0,
            event_details_omitted=0,
            capture_start_proven=False,
            capture_end_proven=False,
            capture_loss_excluded=False,
            directionality_proven=False,
            absence_can_confirm_failure=False,
            protocol_visibility=(visibility,),
            incomplete_attempts=(attempt,),
            cautions=("응답 미관찰은 실패 확정이 아닙니다.",),
        )

    def test_formatter_is_korean_evidence_backed_and_identifier_free(self):
        result = SimpleNamespace(capture_observability=self.report())
        first = format_observability(result)
        second = format_observability(result)

        self.assertEqual(first, second)
        self.assertIn("[9. 캡처 관찰 가능성과 미응답 해석]", first)
        self.assertIn("캡처 경계 위험", first)
        self.assertIn("DNS-1-A1", first)
        self.assertIn("frame.number == 4", first)
        self.assertIn("응답 미관찰만으로 실패 확정 가능: 아니오", first)
        for forbidden in (
            "192.0.2",
            "02:00:00",
            "example.test",
            "user@example",
            "0x1234",
        ):
            self.assertNotIn(forbidden, first)

    def test_missing_report_is_explicit_not_silent(self):
        value = format_observability(SimpleNamespace(capture_observability=None))
        self.assertIn("관찰 가능성 결과가 없습니다", value)
        self.assertIn("장애를 확정하지 않습니다", value)

    def test_install_is_idempotent(self):
        module = SimpleNamespace(
            format_analysis_detail=lambda _result: "기존 결과",
        )
        install(module)
        first_function = module.format_analysis_detail
        install(module)

        self.assertIs(module.format_analysis_detail, first_function)
        rendered = module.format_analysis_detail(
            SimpleNamespace(capture_observability=self.report())
        )
        self.assertTrue(rendered.startswith("기존 결과"))
        self.assertEqual(rendered.count("[9. 캡처 관찰 가능성과 미응답 해석]"), 1)


if __name__ == "__main__":
    unittest.main()
