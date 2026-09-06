import unittest
from types import SimpleNamespace

from wlan_troubleshooter_ko.ui.capture_time_boundaries import (
    format_capture_time_boundaries,
    install,
)


class CaptureTimeBoundariesUiTests(unittest.TestCase):
    def report(self):
        boundary = SimpleNamespace(
            boundary_state="near-analysis-start",
            attempt_id="DNS-1-A1",
            protocol="dns",
            attempt_state="incomplete",
            first_frame=2,
            last_frame=2,
            start_distance_ms=250,
            end_observation_window_ms=2750,
            observed_attempt_duration_ms=0,
            start_near_boundary=True,
            end_near_boundary=False,
            response_wait_sufficiency_assessed=False,
            response_absence_confirmed=False,
            root_cause_confirmed=False,
            display_filter="frame.number == 2",
        )
        return SimpleNamespace(
            complete=True,
            profile_version="0.6.0",
            frames_observed=4,
            expected_frames=4,
            first_frame=1,
            last_frame=4,
            first_to_last_relative_ms=3000,
            minimum_relative_ms=0,
            maximum_relative_ms=3000,
            observed_span_ms=3000,
            timestamp_regressions=0,
            regression_evidence_frames=(),
            regression_evidence_frames_omitted=0,
            boundary_threshold_ms=1000,
            transaction_attempts_total=1,
            transaction_source_complete=True,
            transaction_boundaries=(boundary,),
            cautions=(
                "절대 시각을 기록하지 않습니다.",
            ),
            absolute_timestamps_serialized=False,
            capture_start_proven=False,
            capture_end_proven=False,
            incident_window_fully_covered=False,
            response_wait_sufficiency_assessed=False,
            response_absence_confirmed=False,
            capture_loss_excluded=False,
            root_cause_confirmed=False,
        )

    def test_formatter_is_relative_only_identifier_free_and_conservative(self):
        result = SimpleNamespace(capture_time_boundaries=self.report())
        first = format_capture_time_boundaries(result)
        second = format_capture_time_boundaries(result)

        self.assertEqual(first, second)
        self.assertIn("[13. 캡처 상대 시간과 거래 경계]", first)
        self.assertIn("전체 span: +3,000ms", first)
        self.assertIn("DNS-1-A1", first)
        self.assertIn("분석 시작에서 첫 프레임까지: +250ms", first)
        self.assertIn("마지막 거래 프레임 뒤 관찰 시간: +2,750ms", first)
        self.assertIn("응답 대기 충분성 평가: 아니오", first)
        self.assertIn("실제 응답 부재 확정: 아니오", first)
        self.assertIn("절대 시각 출력 아니오", first)
        self.assertIn("근본 원인 확정 아니오", first)
        for forbidden in (
            "1700000000",
            "frame.time_epoch",
            "capture.pcapng",
            "192.0.2",
            "02:00:00",
            "private-interface",
        ):
            self.assertNotIn(forbidden, first)

    def test_timestamp_order_risk_is_not_presented_as_capture_edge(self):
        report = self.report()
        boundary = report.transaction_boundaries[0]
        boundary.boundary_state = "timestamp-order-risk"
        boundary.start_distance_ms = -100
        boundary.end_observation_window_ms = 600
        report.timestamp_regressions = 1
        report.regression_evidence_frames = (2,)
        report.minimum_relative_ms = -100
        report.maximum_relative_ms = 500
        report.observed_span_ms = 600

        rendered = format_capture_time_boundaries(
            SimpleNamespace(capture_time_boundaries=report)
        )

        self.assertIn("타임스탬프 순서 위험", rendered)
        self.assertIn("타임스탬프 역행: 1회", rendered)
        self.assertIn("근거 #2", rendered)
        self.assertNotIn("실제 응답 부재 확정: 예", rendered)

    def test_missing_report_is_explicit_and_does_not_guess(self):
        rendered = format_capture_time_boundaries(
            SimpleNamespace(capture_time_boundaries=None)
        )

        self.assertIn("상대 시간 결과가 없습니다", rendered)
        self.assertIn("응답 대기 충분성", rendered)
        self.assertIn("추정하지 않습니다", rendered)

    def test_install_is_idempotent(self):
        module = SimpleNamespace(
            format_analysis_detail=lambda _result: "기존 결과",
        )
        install(module)
        first_function = module.format_analysis_detail
        install(module)

        self.assertIs(module.format_analysis_detail, first_function)
        rendered = module.format_analysis_detail(
            SimpleNamespace(capture_time_boundaries=self.report())
        )
        self.assertTrue(rendered.startswith("기존 결과"))
        self.assertEqual(
            rendered.count("[13. 캡처 상대 시간과 거래 경계]"),
            1,
        )


if __name__ == "__main__":
    unittest.main()
