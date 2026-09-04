import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from wlan_troubleshooter_ko.analysis.models import (
    CaptureCapabilityReport,
    CaptureStructure,
    InterfaceSummary,
)
from wlan_troubleshooter_ko.analysis.service import analyze_capture
from wlan_troubleshooter_ko.analysis.transaction_sessions import (
    TransactionSessionReport,
)
from wlan_troubleshooter_ko.core.capture import CaptureInfo


class FakeRun:
    def __init__(self, timeline, transactions):
        self.event_timeline = timeline
        self.transaction_sessions = transactions

    def to_dict(self):
        return {
            "event_timeline": {
                "frames_observed": self.event_timeline.frames_observed,
            },
            "transaction_sessions": self.transaction_sessions.to_dict(),
        }


class CaptureObservabilityServiceTests(unittest.TestCase):
    def structure(self):
        interface = InterfaceSummary(
            section_index=0,
            interface_id=0,
            link_type=1,
            link_type_name="Ethernet",
            snaplen=65535,
            timestamp_resolution="10^-6",
            packets_scanned=2,
            truncated_packets_observed=0,
        )
        return CaptureStructure(
            capture_format="pcap",
            byte_order="little",
            timestamp_precision="microsecond",
            sections=1,
            interfaces=(interface,),
            records_scanned=2,
            packets_scanned=2,
            truncated_packets_observed=0,
            scan_complete=True,
            warnings=(),
        )

    def capabilities(self):
        return CaptureCapabilityReport(
            capture_kind="wired-or-controller",
            capture_kind_label="유선·컨트롤러 측 캡처",
            summary="합성 캡처",
            has_80211_link_type=False,
            has_radiotap_link_type=False,
            has_ip_path_link_type=True,
            available_checks=(),
            unavailable_checks=(),
            cautions=(),
        )

    def empty_transactions(self):
        return TransactionSessionReport(
            attempts=(),
            attempts_by_protocol=(),
            attempts_by_state=(),
            unassigned_event_count=0,
            source_events_total=0,
            source_events_retained=0,
            source_events_omitted=0,
            complete=True,
            cautions=(),
        )

    @mock.patch("wlan_troubleshooter_ko.analysis.service.run_connection_analysis")
    @mock.patch("wlan_troubleshooter_ko.analysis.service.load_ruleset")
    @mock.patch("wlan_troubleshooter_ko.analysis.service.inspect_bundle")
    @mock.patch("wlan_troubleshooter_ko.analysis.service.classify_capture_capabilities")
    @mock.patch("wlan_troubleshooter_ko.analysis.service.inspect_capture_structure")
    @mock.patch("wlan_troubleshooter_ko.analysis.service.validate_capture")
    def test_completed_service_serializes_observability_without_paths(
        self,
        validate_capture_mock,
        inspect_structure_mock,
        classify_mock,
        bundle_mock,
        rules_mock,
        run_mock,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            capture_path = root / "private-source.pcap"
            capture_path.write_bytes(b"synthetic")
            capture = CaptureInfo(
                path=capture_path,
                capture_format="pcap",
                size_bytes=9,
                sha256="a" * 64,
            )
            structure = self.structure()
            timeline = SimpleNamespace(
                frames_observed=2,
                complete=True,
                events_total=0,
                events_retained=0,
                events_omitted=0,
            )
            transactions = self.empty_transactions()

            validate_capture_mock.return_value = capture
            inspect_structure_mock.return_value = structure
            classify_mock.return_value = self.capabilities()
            bundle_mock.return_value = SimpleNamespace(code="integrity_verified")
            rules_mock.return_value = {"ruleset_version": "test", "rules": []}
            run_mock.return_value = FakeRun(timeline, transactions)

            result = analyze_capture(
                capture_path,
                root / "vendor",
                root / "profile.json",
                rules_path=root / "rules.json",
                workspace_base=root,
            )
            serialized = result.to_dict()

        self.assertEqual(result.inventory_state, "completed")
        self.assertIsNotNone(result.capture_observability)
        observability = serialized["capture_observability"]
        self.assertEqual(observability["schema_version"], 1)
        self.assertTrue(observability["analysis_input_complete"])
        self.assertFalse(observability["capture_start_proven"])
        self.assertFalse(observability["capture_end_proven"])
        self.assertFalse(observability["capture_loss_excluded"])
        self.assertFalse(observability["directionality_proven"])
        self.assertFalse(observability["absence_can_confirm_failure"])
        self.assertNotIn(str(capture_path), str(serialized))
        self.assertNotIn(capture_path.name, str(serialized))
        run_mock.assert_called_once()

    @mock.patch("wlan_troubleshooter_ko.analysis.service.run_connection_analysis")
    @mock.patch("wlan_troubleshooter_ko.analysis.service.load_ruleset")
    @mock.patch("wlan_troubleshooter_ko.analysis.service.inspect_bundle")
    @mock.patch("wlan_troubleshooter_ko.analysis.service.classify_capture_capabilities")
    @mock.patch("wlan_troubleshooter_ko.analysis.service.inspect_capture_structure")
    @mock.patch("wlan_troubleshooter_ko.analysis.service.validate_capture")
    def test_missing_timeline_fails_closed_without_exception_text_leak(
        self,
        validate_capture_mock,
        inspect_structure_mock,
        classify_mock,
        bundle_mock,
        rules_mock,
        run_mock,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            capture = CaptureInfo(
                path=root / "private-source.pcap",
                capture_format="pcap",
                size_bytes=1,
                sha256="b" * 64,
            )
            capture.path.write_bytes(b"x")
            validate_capture_mock.return_value = capture
            inspect_structure_mock.return_value = self.structure()
            classify_mock.return_value = self.capabilities()
            bundle_mock.return_value = SimpleNamespace(code="integrity_verified")
            rules_mock.return_value = {"ruleset_version": "test", "rules": []}
            run_mock.return_value = FakeRun(None, self.empty_transactions())

            result = analyze_capture(
                capture.path,
                root / "vendor",
                root / "profile.json",
                rules_path=root / "rules.json",
                workspace_base=root,
            )

        self.assertEqual(result.inventory_state, "failed")
        self.assertIsNone(result.protocol_inventory)
        self.assertIsNone(result.capture_observability)
        self.assertIn("이벤트·거래 결과", result.inventory_message)


if __name__ == "__main__":
    unittest.main()
