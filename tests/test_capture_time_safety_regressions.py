"""Regression coverage for time-order precision and conservative evidence checks."""

import json
import unittest
from dataclasses import replace
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


def index_for(epochs):
    text = '"frame.number"\t"frame.time_epoch"\n'
    text += "".join(
        '"{0}"\t"{1}"\n'.format(frame, epoch)
        for frame, epoch in enumerate(epochs, 1)
    )
    return build_capture_time_index(text, profile(), expected_frames=len(epochs))


def attempt(first, last, duration, evidence=None, omitted=0):
    value = SimpleNamespace(
        attempt_id="DNS-1-A1",
        protocol="dns",
        state="incomplete",
        first_frame=first,
        last_frame=last,
        duration_ms=duration,
        root_cause_confirmed=False,
    )
    if evidence is not None:
        value.evidence_frames = evidence
        value.evidence_frames_omitted = omitted
    return value


def report_for(index, value):
    return build_capture_time_boundaries(
        index, SimpleNamespace(attempts=(value,), complete=True)
    )


class CaptureTimeSafetyRegressionTests(unittest.TestCase):
    def test_submicrosecond_regression_is_not_erased_by_display_rounding(self):
        index = index_for(("1700000000.123456900", "1700000000.123456100"))
        self.assertEqual(index.frame_relative_ms, (0, 0))
        self.assertEqual(index.timestamp_regressions, 1)
        self.assertEqual(index.regression_evidence_frames, (2,))
        report = report_for(index, attempt(2, 2, 0))
        self.assertEqual(report.transaction_boundaries[0].boundary_state,
                         "timestamp-order-risk")
        self.assertFalse(report.root_cause_confirmed)

    def test_all_accepted_fraction_digits_participate_in_order_comparison(self):
        index = index_for(("1700000000.123456789123456789",
                           "1700000000.123456789123456788"))
        self.assertEqual(index.timestamp_regressions, 1)

    def test_equivalent_decimal_spellings_are_not_regressions(self):
        index = index_for(("100.1", "100.100000000000000000", "101"))
        self.assertEqual(index.timestamp_regressions, 0)
        self.assertEqual(index.frame_relative_ms, (0, 0, 900))

    def test_ordinary_dns_boundaries_keep_existing_millisecond_contract(self):
        index = index_for(("100.0", "100.25", "101.5", "103.0"))
        report = report_for(index, attempt(2, 2, 0))
        value = report.transaction_boundaries[0]
        self.assertEqual((value.start_distance_ms, value.end_observation_window_ms),
                         (250, 2750))
        self.assertEqual(value.boundary_state, "near-analysis-start")
        self.assertTrue(report.complete)

    def test_regression_evidence_is_bounded_but_total_count_is_preserved(self):
        index = index_for(tuple(str(1000 - value) for value in range(200)))
        self.assertEqual(index.timestamp_regressions, 199)
        self.assertEqual(index.regression_evidence_frames, tuple(range(2, 66)))
        self.assertEqual(index.regression_evidence_frames_omitted, 135)

    def test_reverse_endpoint_order_uses_transaction_extrema_for_validation(self):
        index = index_for(("100.0", "99.9"))
        report = report_for(index, attempt(1, 2, 100, (1, 2)))
        value = report.transaction_boundaries[0]
        self.assertEqual(value.boundary_state, "timestamp-order-risk")
        self.assertEqual(value.observed_attempt_duration_ms, -100)
        self.assertFalse(value.start_near_boundary)
        self.assertFalse(value.end_near_boundary)

    def test_middle_event_extreme_is_not_confused_with_endpoint_duration(self):
        index = index_for(("100.0", "99.0", "100.5"))
        report = report_for(index, attempt(1, 3, 1500, (1, 2, 3)))
        self.assertEqual(report.transaction_boundaries[0].observed_attempt_duration_ms,
                         500)
        self.assertEqual(report.transaction_boundaries[0].boundary_state,
                         "timestamp-order-risk")

    def test_unrelated_frame_extreme_is_not_used_as_transaction_evidence(self):
        index = index_for(("100.0", "90.0", "100.5"))
        report_for(index, attempt(1, 3, 500, (1, 3)))
        with self.assertRaises(CaptureTimeBoundaryError):
            report_for(index, attempt(1, 3, 10500, (1, 3)))

    def test_truncated_evidence_uses_bounds_without_claiming_exact_validation(self):
        index = index_for(("100.0", "99.0", "100.5"))
        report = report_for(index, attempt(1, 3, 1500, (1,), omitted=2))
        self.assertFalse(report.complete)
        self.assertEqual(report.transaction_boundaries[0].boundary_state,
                         "timestamp-order-risk")
        for bad in (0, 5000):
            with self.subTest(duration=bad):
                with self.assertRaises(CaptureTimeBoundaryError):
                    report_for(index, attempt(1, 3, bad, (1,), omitted=2))

    def test_incomplete_regression_evidence_is_not_treated_as_complete(self):
        index = index_for(("100.0", "99.0", "100.5"))
        for frames in ((1,), (3,), (1, 4), (1, True, 3), (3, 1), (1, 1, 3)):
            with self.subTest(evidence=frames):
                with self.assertRaises(CaptureTimeBoundaryError):
                    report_for(index, attempt(1, 3, 1500, frames))

    def test_regressing_multiframe_attempt_requires_evidence(self):
        index = index_for(("100.0", "99.9"))
        with self.assertRaises(CaptureTimeBoundaryError):
            report_for(index, attempt(1, 2, 100))

    def test_mismatched_duration_in_monotonic_capture_still_fails_closed(self):
        index = index_for(("100.0", "101.0"))
        with self.assertRaises(CaptureTimeBoundaryError):
            report_for(index, attempt(1, 2, 999, (1, 2)))

    def test_wrong_tshark_field_under_approved_output_key_is_rejected(self):
        bad = replace(profile(), fields=(
            ResolvedField("frame_number", "tcp.stream"),
            ResolvedField("time_epoch", "frame.time_epoch"),
        ))
        text = '"tcp.stream"\t"frame.time_epoch"\n"1"\t"100.0"\n'
        with self.assertRaises(CaptureTimeBoundaryError):
            build_capture_time_index(text, bad, expected_frames=1)

    def test_duplicate_output_key_cannot_hide_an_extra_field(self):
        bad = replace(profile(), fields=profile().fields + (
            ResolvedField("time_epoch", "tcp.time_relative"),
        ))
        text = ('"frame.number"\t"frame.time_epoch"\t"tcp.time_relative"\n'
                '"1"\t"100.0"\t"100.0"\n')
        with self.assertRaises(CaptureTimeBoundaryError):
            build_capture_time_index(text, bad, expected_frames=1)

    def test_changed_filter_or_invalid_packet_limit_is_rejected(self):
        text = '"frame.number"\t"frame.time_epoch"\n"1"\t"100.0"\n'
        for bad in (replace(profile(), display_filter_name="dns-only"),
                    replace(profile(), max_packets=True),
                    replace(profile(), max_packets=500001)):
            with self.subTest(profile=bad):
                with self.assertRaises(CaptureTimeBoundaryError):
                    build_capture_time_index(text, bad, expected_frames=1)

    def test_oversized_frame_number_raises_safe_domain_error(self):
        raw = '9' * 5000
        text = '"frame.number"\t"frame.time_epoch"\n"' + raw + '"\t"100.0"\n'
        with self.assertRaises(CaptureTimeBoundaryError) as error:
            build_capture_time_index(text, profile(), expected_frames=1)
        self.assertNotIn(raw, str(error.exception))

    def test_unhashable_attempt_id_has_safe_domain_error(self):
        index = index_for(("100.0",))
        value = attempt(1, 1, 0)
        value.attempt_id = ["private-identifier"]
        with self.assertRaises(CaptureTimeBoundaryError) as error:
            report_for(index, value)
        self.assertNotIn("private-identifier", str(error.exception))

    def test_raw_precision_and_identifiers_never_appear_in_public_json(self):
        epochs = ("1700000000.123456900", "1700000000.123456100")
        result = report_for(index_for(epochs), attempt(2, 2, 0)).to_dict()
        text = json.dumps(result, ensure_ascii=False)
        for value in (*epochs, "1700000000", "frame.time_epoch", "order_key"):
            self.assertNotIn(value, text)
        for key in ("absolute_timestamps_serialized", "capture_start_proven",
                    "capture_end_proven", "incident_window_fully_covered",
                    "response_wait_sufficiency_assessed", "response_absence_confirmed",
                    "capture_loss_excluded", "root_cause_confirmed"):
            self.assertIs(result[key], False)


if __name__ == "__main__":
    unittest.main()
