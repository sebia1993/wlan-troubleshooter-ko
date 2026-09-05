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
from wlan_troubleshooter_ko.analysis.pcapng_interface_statistics import (
    CounterObservation,
    InterfaceStatistics,
    PcapngInterfaceStatisticsError,
    PcapngInterfaceStatisticsReport,
)
from wlan_troubleshooter_ko.analysis.service import (
    CaptureAnalysisError,
    analyze_capture,
)
from wlan_troubleshooter_ko.core.capture import CaptureInfo


class PcapngInterfaceStatisticsServiceTests(unittest.TestCase):
    def capture(self, root):
        path = root / "private.pcapng"
        path.write_bytes(b"pcapng")
        return CaptureInfo(
            path=path,
            capture_format="pcapng",
            size_bytes=6,
            sha256="a" * 64,
        )

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
            capture_format="pcapng",
            byte_order="little",
            timestamp_precision="per-interface",
            sections=1,
            interfaces=(interface,),
            records_scanned=5,
            packets_scanned=2,
            truncated_packets_observed=0,
            scan_complete=True,
            warnings=(),
        )

    def capabilities(self):
        return CaptureCapabilityReport(
            capture_kind="wired-or-controller",
            capture_kind_label="유선·컨트롤러 측 캡처",
            summary="합성 PCAPNG",
            has_80211_link_type=False,
            has_radiotap_link_type=False,
            has_ip_path_link_type=True,
            available_checks=(),
            unavailable_checks=(),
            cautions=(),
        )

    def statistics(self):
        counters = (
            CounterObservation(
                name="ifrecv",
                observations=2,
                first_value=2,
                last_value=5,
                progression="counter-increase-observed",
            ),
            CounterObservation(
                name="ifdrop",
                observations=2,
                first_value=0,
                last_value=3,
                progression="counter-increase-observed",
            ),
            CounterObservation(
                name="filteraccept",
                observations=0,
                first_value=None,
                last_value=None,
                progression="not-reported",
            ),
            CounterObservation(
                name="osdrop",
                observations=2,
                first_value=0,
                last_value=1,
                progression="counter-increase-observed",
            ),
            CounterObservation(
                name="usrdeliv",
                observations=0,
                first_value=None,
                last_value=None,
                progression="not-reported",
            ),
        )
        interface = InterfaceStatistics(
            interface_alias="IFACE-1",
            section_index=0,
            interface_id=0,
            statistics_blocks=2,
            state="reported-drop-observed",
            counters=counters,
        )
        return PcapngInterfaceStatisticsReport(
            supported_capture_format=True,
            complete=True,
            state="reported-drop-observed",
            sections_observed=1,
            interfaces_defined=1,
            statistics_blocks_observed=2,
            interfaces_with_statistics=1,
            interfaces=(interface,),
            raw_interface_identifiers_serialized=False,
            absolute_timestamps_serialized=False,
            capture_loss_excluded=False,
            specific_packet_loss_confirmed=False,
            root_cause_confirmed=False,
            cautions=("특정 패킷 누락은 확정하지 않습니다.",),
        )

    def test_statistics_remain_available_without_bundled_tshark(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            capture = self.capture(root)
            statistics = self.statistics()
            with mock.patch(
                "wlan_troubleshooter_ko.analysis.service.validate_capture",
                return_value=capture,
            ), mock.patch(
                "wlan_troubleshooter_ko.analysis.service.inspect_capture_structure",
                return_value=self.structure(),
            ), mock.patch(
                "wlan_troubleshooter_ko.analysis.service.classify_capture_capabilities",
                return_value=self.capabilities(),
            ), mock.patch(
                "wlan_troubleshooter_ko.analysis.service.inspect_pcapng_interface_statistics",
                return_value=statistics,
            ) as statistics_mock, mock.patch(
                "wlan_troubleshooter_ko.analysis.service.inspect_bundle",
                return_value=SimpleNamespace(code="not_provisioned"),
            ):
                result = analyze_capture(
                    capture.path,
                    root / "vendor",
                    root / "profiles.json",
                )

        self.assertEqual(result.inventory_state, "unavailable")
        self.assertIs(result.pcapng_interface_statistics, statistics)
        serialized = result.to_dict()["pcapng_interface_statistics"]
        self.assertEqual(serialized["state"], "reported-drop-observed")
        self.assertFalse(serialized["capture_loss_excluded"])
        self.assertFalse(serialized["specific_packet_loss_confirmed"])
        statistics_mock.assert_called_once_with(
            capture,
            cancel_event=None,
        )

    def test_unsafe_isb_structure_fails_before_tshark(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            capture = self.capture(root)
            with mock.patch(
                "wlan_troubleshooter_ko.analysis.service.validate_capture",
                return_value=capture,
            ), mock.patch(
                "wlan_troubleshooter_ko.analysis.service.inspect_capture_structure",
                return_value=self.structure(),
            ), mock.patch(
                "wlan_troubleshooter_ko.analysis.service.classify_capture_capabilities",
                return_value=self.capabilities(),
            ), mock.patch(
                "wlan_troubleshooter_ko.analysis.service.inspect_pcapng_interface_statistics",
                side_effect=PcapngInterfaceStatisticsError(
                    "PCAPNG ISB 구조가 올바르지 않습니다."
                ),
            ), mock.patch(
                "wlan_troubleshooter_ko.analysis.service.inspect_bundle"
            ) as bundle_mock:
                with self.assertRaises(CaptureAnalysisError):
                    analyze_capture(
                        capture.path,
                        root / "vendor",
                        root / "profiles.json",
                    )

        bundle_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
