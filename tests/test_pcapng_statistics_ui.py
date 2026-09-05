import unittest
from types import SimpleNamespace

from wlan_troubleshooter_ko.ui.pcapng_statistics import (
    format_pcapng_statistics,
    install,
)


class PcapngStatisticsUiTests(unittest.TestCase):
    def observation(self):
        return SimpleNamespace(
            interface_alias="IFACE-1",
            section_index=0,
            interface_id=0,
            observation_index=1,
            counter_state="reported-drop-observed",
            ifrecv=2,
            ifdrop=3,
            filteraccept=2,
            osdrop=1,
            usrdeliv=2,
            block_timestamp_present=True,
            start_time_present=True,
            end_time_present=True,
            absolute_timestamps_serialized=False,
            capture_loss_excluded=False,
            root_cause_confirmed=False,
        )

    def test_formatter_shows_counters_without_loss_or_root_claim(self):
        structure = SimpleNamespace(
            capture_format="pcapng",
            interface_statistics_state="observed",
            interface_statistics=(self.observation(),),
        )
        result = SimpleNamespace(structure=structure)
        first = format_pcapng_statistics(result)
        second = format_pcapng_statistics(result)

        self.assertEqual(first, second)
        self.assertIn("[12. PCAPNG 인터페이스 통계]", first)
        self.assertIn("IFACE-1", first)
        self.assertIn("인터페이스 드롭(ifdrop): 3", first)
        self.assertIn("OS 드롭(osdrop): 1", first)
        self.assertIn("캡처 손실 배제: 아니오", first)
        self.assertIn("근본 원인 확정: 아니오", first)
        self.assertIn("서로 합산하지 않습니다", first)
        for forbidden in (
            "ethernet 2",
            "intel",
            "windows adapter",
            "1700000000",
            "02:00:00",
            "192.0.2",
        ):
            self.assertNotIn(forbidden, first.casefold())

    def test_no_isb_does_not_claim_zero_drop(self):
        value = format_pcapng_statistics(
            SimpleNamespace(
                structure=SimpleNamespace(
                    capture_format="pcapng",
                    interface_statistics_state="no-interface-statistics",
                    interface_statistics=(),
                )
            )
        )

        self.assertIn("관찰하지 못했습니다", value)
        self.assertIn("무손실 증명이 아닙니다", value)
        self.assertNotIn("드롭 0", value)

    def test_pcap_is_explicitly_not_pcapng(self):
        value = format_pcapng_statistics(
            SimpleNamespace(
                structure=SimpleNamespace(
                    capture_format="pcap",
                    interface_statistics=(),
                )
            )
        )
        self.assertIn("PCAPNG가 아니어서", value)
        self.assertIn("손실이 없었다는 뜻이 아닙니다", value)

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
                structure=SimpleNamespace(
                    capture_format="pcapng",
                    interface_statistics_state="observed",
                    interface_statistics=(self.observation(),),
                )
            )
        )
        self.assertTrue(rendered.startswith("기존 결과"))
        self.assertEqual(rendered.count("[12. PCAPNG 인터페이스 통계]"), 1)


if __name__ == "__main__":
    unittest.main()
