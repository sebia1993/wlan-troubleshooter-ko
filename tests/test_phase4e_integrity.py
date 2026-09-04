import tempfile
import unittest
from pathlib import Path
from unittest import mock

from wlan_troubleshooter_ko.analysis.transaction_sessions import (
    TransactionAttempt,
    TransactionSessionReport,
)
from wlan_troubleshooter_ko.core.capture import CaptureInfo
from wlan_troubleshooter_ko.tshark.inventory import (
    _TSharkTextResult,
    _prepare_device_link_transactions,
    _same_verified_capture,
    run_profile_fields_text,
)
from wlan_troubleshooter_ko.tshark.profiles import ResolvedField, ResolvedProfile
from wlan_troubleshooter_ko.tshark.runner import TSharkExecutionError


class Phase4EIntegrityTests(unittest.TestCase):
    def capture(self, path: Path, digest: str) -> CaptureInfo:
        return CaptureInfo(
            path=path,
            capture_format="pcap",
            size_bytes=128,
            sha256=digest,
        )

    def profile(self) -> ResolvedProfile:
        return ResolvedProfile(
            profile_id="connection-events",
            profile_version="0.5.0",
            display_filter_name="capture-overview",
            max_packets=100,
            fields=(ResolvedField("frame_number", "frame.number"),),
            missing_optional_fields=(),
        )

    @mock.patch("wlan_troubleshooter_ko.tshark.inventory.probe_bundle_runtime")
    @mock.patch("wlan_troubleshooter_ko.tshark.inventory.verify_bundle")
    @mock.patch("wlan_troubleshooter_ko.tshark.inventory.validate_capture")
    def test_expected_capture_mismatch_stops_before_tshark(
        self,
        validate_capture_mock,
        verify_bundle_mock,
        probe_mock,
    ):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "capture.pcap"
            expected = self.capture(path, "a" * 64)
            changed = self.capture(path, "b" * 64)
            validate_capture_mock.return_value = changed

            with self.assertRaises(TSharkExecutionError):
                run_profile_fields_text(
                    Path(directory) / "vendor",
                    path,
                    Path(directory) / "isolation",
                    self.profile(),
                    expected_capture=expected,
                )

        verify_bundle_mock.assert_not_called()
        probe_mock.assert_not_called()

    def test_public_and_identity_results_require_same_capture_fingerprint(self):
        path = Path("capture.pcap").resolve()
        first_capture = self.capture(path, "a" * 64)
        same_capture = self.capture(path, "a" * 64)
        changed_capture = self.capture(path, "b" * 64)

        first = _TSharkTextResult("4.6.8", "m" * 64, "", first_capture)
        same = _TSharkTextResult("4.6.8", "m" * 64, "", same_capture)
        changed = _TSharkTextResult("4.6.8", "m" * 64, "", changed_capture)
        missing = _TSharkTextResult("4.6.8", "m" * 64, "")

        self.assertTrue(_same_verified_capture(first, same))
        self.assertFalse(_same_verified_capture(first, changed))
        self.assertFalse(_same_verified_capture(first, missing))

    def transaction_report(self, omitted: int) -> TransactionSessionReport:
        attempt = TransactionAttempt(
            attempt_id="DNS-1-A1",
            correlation_alias="DNS-1",
            protocol="dns",
            label_ko="DNS 이름 조회",
            state="complete",
            summary_ko="정상 응답 관찰",
            event_count=65,
            first_frame=1,
            last_frame=65,
            duration_ms=100,
            evidence_frames=tuple(range(1, 65)),
            evidence_frames_omitted=omitted,
            display_filter="frame.number == 1",
            observed_event_types=("dns_query", "dns_response_success"),
            missing_event_types=(),
            next_checks_ko=("근거를 확인합니다.",),
        )
        return TransactionSessionReport(
            attempts=(attempt,),
            attempts_by_protocol=(("dns", 1),),
            attempts_by_state=(("complete", 1),),
            unassigned_event_count=0,
            source_events_total=65,
            source_events_retained=65,
            source_events_omitted=0,
            complete=True,
            cautions=(),
        )

    def test_truncated_attempt_evidence_is_removed_from_device_link_input(self):
        original = self.transaction_report(1)

        prepared, incomplete = _prepare_device_link_transactions(original)

        self.assertEqual(incomplete, 1)
        self.assertEqual(original.attempts[0].evidence_frames, tuple(range(1, 65)))
        self.assertEqual(prepared.attempts[0].evidence_frames, ())
        self.assertEqual(prepared.attempts[0].display_filter, "")

    def test_complete_attempt_evidence_is_preserved(self):
        original = self.transaction_report(0)

        prepared, incomplete = _prepare_device_link_transactions(original)

        self.assertEqual(incomplete, 0)
        self.assertIs(prepared.attempts[0], original.attempts[0])


if __name__ == "__main__":
    unittest.main()
