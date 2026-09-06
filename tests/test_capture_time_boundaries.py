import json
import unittest
from types import SimpleNamespace

from wlan_troubleshooter_ko.analysis.capture_time_boundaries import (
    CaptureTimeBoundaryError,
    build_capture_time_boundaries,
    build_capture_time_index,
)
from wlan_troubleshooter_ko.tshark.profiles import ResolvedField, ResolvedProfile


def profile():
    return ResolvedProfile(
        profile_id="capture-time-boundaries",
        profile_version="0.6.0",
        display_filter_name="capture-overview",
        max_packets=100000,
        fields=(
            ResolvedField("frame_number", "frame.number"),
            ResolvedField("time_epoch", "frame.time_epoch"),
        ),
        missing_optional_fields=(),
    )


def fields(rows):
    values = ['"frame.number"\t"frame.time_epoch"']
    values.extend(
        '"{0}"\t"{1}"'.format(frame, epoch)
        for frame, epoch in rows
    )
    return "\n".join(values) + "\n"


def attempt(
    attempt_id,
    protocol,
    first_frame,
    last_frame,
    duration_ms,
    state="incomplete",
):
    return SimpleNamespace(
        attempt_id=attempt_id,
        protocol=protocol,
        state=state,
        first_frame=first_frame,
        last_frame=last_frame,
        duration_ms=duration_ms,
        root_cause_confirmed=False,
    )


class CaptureTimeBoundaryTests(unittest.TestCase):
    def test_relative_capture_span_and_two_dns_boundaries(self):
        index = build_capture_time_index(
            fields(
                (
                    (1, "1700000000.000000000"),
                    (2, "1700000000.250000000"),
                    (3, "1700000001.500000000"),
                    (4, "1700000003.000000000"),
                )
            ),
            profile(),
            expected_frames=4,
        )
        report = build_capture_time_boundaries(
            index,
            SimpleNamespace(
                attempts=(
                    attempt("DNS-1-A1", "dns", 2, 2, 0),
                    attempt("DNS-2-A1", "dns", 4, 4, 0),
                ),
                complete=True,
            ),
        )
        values = {
            item.attempt_id: item
            for item in report.transaction_boundaries
        }

        self.assertEqual(index.frame_relative_ms, (0, 250, 1500, 3000))
        self.assertTrue(index.complete)
        self.assertEqual(report.first_to_last_relative_ms, 3000)
        self.assertEqual(report.minimum_relative_ms, 0)
        self.assertEqual(report.maximum_relative_ms, 3000)
        self.assertEqual(report.observed_span_ms, 3000)
        self.assertEqual(report.timestamp_regressions, 0)
        self.assertEqual(values["DNS-1-A1"].start_distance_ms, 250)
        self.assertEqual(
            values["DNS-1-A1"].end_observation_window_ms,
            2750,
        )
        self.assertEqual(
            values["DNS-1-A1"].boundary_state,
            "near-analysis-start",
        )
        self.assertEqual(values["DNS-2-A1"].start_distance_ms, 3000)
        self.assertEqual(
            values["DNS-2-A1"].end_observation_window_ms,
            0,
        )
        self.assertEqual(
            values["DNS-2-A1"].boundary_state,
            "at-analysis-end",
        )
        self.assertFalse(report.absolute_timestamps_serialized)
        self.assertFalse(report.capture_start_proven)
        self.assertFalse(report.capture_end_proven)
        self.assertFalse(report.incident_window_fully_covered)
        self.assertFalse(report.response_wait_sufficiency_assessed)
        self.assertFalse(report.response_absence_confirmed)
        self.assertFalse(report.capture_loss_excluded)
        self.assertFalse(report.root_cause_confirmed)

        rendered = json.dumps(report.to_dict(), ensure_ascii=False)
        self.assertNotIn("1700000000", rendered)
        self.assertNotIn("frame.time_epoch", rendered)
        self.assertNotIn("capture.pcap", rendered)

    def test_spanning_and_interior_states_are_observations_not_proofs(self):
        index = build_capture_time_index(
            fields(
                (
                    (1, "1700000100.000000"),
                    (2, "1700000102.000000"),
                    (3, "1700000105.000000"),
                )
            ),
            profile(),
            expected_frames=3,
        )
        report = build_capture_time_boundaries(
            index,
            SimpleNamespace(
                attempts=(
                    attempt("TCP-1-A1", "tcp", 1, 3, 5000),
                    attempt("DNS-1-A1", "dns", 2, 2, 0),
                ),
                complete=True,
            ),
            boundary_threshold_ms=500,
        )
        values = {
            item.attempt_id: item
            for item in report.transaction_boundaries
        }

        self.assertEqual(
            values["TCP-1-A1"].boundary_state,
            "spans-analysis-window",
        )
        self.assertEqual(
            values["DNS-1-A1"].boundary_state,
            "analysis-window-interior",
        )
        self.assertFalse(report.incident_window_fully_covered)
        self.assertFalse(
            values["TCP-1-A1"].response_wait_sufficiency_assessed
        )
        self.assertFalse(values["TCP-1-A1"].response_absence_confirmed)

    def test_timestamp_regression_is_reported_and_boundary_state_is_limited(self):
        index = build_capture_time_index(
            fields(
                (
                    (1, "1700000200.500000"),
                    (2, "1700000200.400000"),
                    (3, "1700000201.000000"),
                )
            ),
            profile(),
            expected_frames=3,
        )
        report = build_capture_time_boundaries(
            index,
            SimpleNamespace(
                attempts=(
                    attempt("DNS-1-A1", "dns", 2, 2, 0),
                ),
                complete=True,
            ),
        )

        self.assertEqual(index.frame_relative_ms, (0, -100, 500))
        self.assertEqual(index.timestamp_regressions, 1)
        self.assertEqual(index.regression_evidence_frames, (2,))
        self.assertEqual(index.minimum_relative_ms, -100)
        self.assertEqual(index.maximum_relative_ms, 500)
        self.assertEqual(index.observed_span_ms, 600)
        self.assertEqual(
            report.transaction_boundaries[0].boundary_state,
            "timestamp-order-risk",
        )
        self.assertTrue(any("역행" in value for value in report.cautions))

    def test_partial_profile_output_is_explicit(self):
        index = build_capture_time_index(
            fields(
                (
                    (1, "1700000300.000000"),
                    (2, "1700000301.000000"),
                )
            ),
            profile(),
            expected_frames=3,
        )
        report = build_capture_time_boundaries(
            index,
            SimpleNamespace(attempts=(), complete=True),
        )

        self.assertFalse(index.complete)
        self.assertFalse(report.complete)
        self.assertEqual(report.expected_frames, 3)
        self.assertTrue(
            any("전체 종료 시각" in value for value in report.cautions)
        )

    def test_invalid_rows_and_transaction_evidence_fail_closed(self):
        invalid_texts = (
            fields(((2, "1700000000.0"),)),
            fields(((1, "-1.0"),)),
            fields(((1, "not-time"),)),
        )
        for value in invalid_texts:
            with self.subTest(value=value):
                with self.assertRaises(CaptureTimeBoundaryError):
                    build_capture_time_index(
                        value,
                        profile(),
                        expected_frames=1,
                    )

        index = build_capture_time_index(
            fields(
                (
                    (1, "1700000400.000000"),
                    (2, "1700000401.000000"),
                )
            ),
            profile(),
            expected_frames=2,
        )
        invalid_attempts = (
            attempt("DNS-1-A1", "tcp", 1, 1, 0),
            attempt("DNS-1-A1", "dns", 1, 3, 0),
            attempt("DNS-1-A1", "dns", 1, 2, 999),
            SimpleNamespace(
                attempt_id="DNS-1-A1",
                protocol="dns",
                state="incomplete",
                first_frame=1,
                last_frame=1,
                duration_ms=0,
                root_cause_confirmed=True,
            ),
        )
        for value in invalid_attempts:
            with self.subTest(value=value):
                with self.assertRaises(CaptureTimeBoundaryError):
                    build_capture_time_boundaries(
                        index,
                        SimpleNamespace(
                            attempts=(value,),
                            complete=True,
                        ),
                    )

    def test_profile_must_be_exact_minimal_profile(self):
        wrong = ResolvedProfile(
            profile_id="connection-events",
            profile_version="0.6.0",
            display_filter_name="capture-overview",
            max_packets=100000,
            fields=profile().fields,
            missing_optional_fields=(),
        )
        with self.assertRaises(CaptureTimeBoundaryError):
            build_capture_time_index(
                fields(((1, "1700000000.0"),)),
                wrong,
                expected_frames=1,
            )


if __name__ == "__main__":
    unittest.main()
