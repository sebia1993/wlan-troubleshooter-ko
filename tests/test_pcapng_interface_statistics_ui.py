import unittest
from types import SimpleNamespace

from wlan_troubleshooter_ko.ui.pcapng_interface_statistics import (
    format_pcapng_interface_statistics,
    install,
)


class PcapngInterfaceStatisticsUiTests(unittest.TestCase):
    def report(self):
        counters = (
            SimpleNamespace(
                name="ifrecv",
                observations=2,
                first_value=2,
                last_value=5,
                progression="counter-increase-observed",
            ),
            SimpleNamespace(
                name="ifdrop",
                observations=2,
                first_value=0,
                last_value=3,
                progression="counter-increase-observed",
            ),
            SimpleNamespace(
                name="filteraccept",
                observations=0,
                first_value=None,
                last_value=None,
                progression="not-reported",
            ),
            SimpleNamespace(
                name="osdrop",
                observations=2,
                first_value=0,
                last_value=1,
                progression="counter-increase-observed",
            ),
            SimpleNamespace(
                name="usrdeliv",
                observations=2,
                first_value=2,
                last_value=5,
                progression="counter-increase-observed",
            ),
        )
        interface = SimpleNamespace(
            interface_alias="IFACE-1",
            section_index=0,
            interface_id=0,
            statistics_blocks=2,
            state="reported-drop-observed",
            counters=counters,
            raw_interface_identifiers_serialized=False,
            absolute_timestamps_serialized=False,
            specific_packet_loss_confirmed=False,
            root_cause_confirmed=False,
        )
        return SimpleNamespace(
            state="reported-drop-observed",
            supported_capture_format=True,
            complete=True,
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
            cautions=(
                "양의 드롭 Counter는 특정 패킷 누락을 확정하지 않습니다.",
            ),
        )

    def test_formatter_is_korean_alias_only_and_conservative(self):
        result = SimpleNamespace(
            pcapng_interface_statistics=self.report()
        )
        first = format_pcapng_interface_statistics(result)
        second = format_pcapng_interface_statistics(result)

        self.assertEqual(first, second)
        self.assertIn("[12. PCAPNG 인터페이스 통계]", first)
        self.assertIn("IFACE-1", first)
        self.assertIn("양의 드롭 Counter 관찰", first)
        self.assertIn("인터페이스 보고 드롭: 최초 0 · 마지막 3", first)
        self.assertIn("캡처 손실 배제: 아니오", first)
        self.assertIn("특정 패킷 손실 확정: 아니오", first)
        self.assertIn("근본 원인 확정: 아니오", first)
        for forbidden in (
            "SECRET-INTERFACE",
            "SECRET-ISB",
            "192.0.2",
            "02:00:00",
            "private-capture",
            "0102030405060708",
        ):
            self.assertNotIn(forbidden, first)

    def test_missing_report_is_explicit(self):
        value = format_pcapng_interface_statistics(
            SimpleNamespace(pcapng_interface_statistics=None)
        )
        self.assertIn("분석 결과가 없습니다", value)
        self.assertIn("캡처 손실이 없다는 뜻이 아닙니다", value)

    def test_install_is_idempotent(self):
        module = SimpleNamespace(
            format_analysis_detail=lambda _result: "기존 결과",
        )
        install(module)
        first_function = module.format_analysis_detail
        install(module)

        self.assertIs(module.format_analysis_detail, first_function)
        rendered = module.format_analysis_detail(
            SimpleNamespace(
                pcapng_interface_statistics=self.report()
            )
        )
        self.assertTrue(rendered.startswith("기존 결과"))
        self.assertEqual(
            rendered.count("[12. PCAPNG 인터페이스 통계]"),
            1,
        )


if __name__ == "__main__":
    unittest.main()
