import unittest
from pathlib import Path

from wlan_troubleshooter_ko.analysis.protocol_inventory import (
    ProtocolInventoryError,
    build_protocol_inventory,
)
from wlan_troubleshooter_ko.tshark.catalog import parse_field_catalog
from wlan_troubleshooter_ko.tshark.profiles import load_field_profiles, resolve_profile


CATALOG_LINES = [
    "P\tFrame\tframe\n",
    "F\tFrame Number\tframe.number\tFT_UINT32\tframe\tBASE_DEC\t0x0\t\n",
    "F\tInterface id\tframe.interface_id\tFT_UINT32\tframe\tBASE_DEC\t0x0\t\n",
    "F\tCapture Length\tframe.cap_len\tFT_UINT32\tframe\tBASE_DEC\t0x0\t\n",
    "F\tFrame Length\tframe.len\tFT_UINT32\tframe\tBASE_DEC\t0x0\t\n",
    "F\tProtocols in frame\tframe.protocols\tFT_STRING\tframe\t\t0x0\t\n",
]


class ProtocolInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "wlan_troubleshooter_ko"
            / "resources"
            / "tshark"
            / "field-profiles.v1.json"
        )
        cls.registry = load_field_profiles(path)
        cls.profile = resolve_profile(cls.registry, parse_field_catalog(CATALOG_LINES), "protocol-inventory")
        cls.header = "\t".join('"{0}"'.format(item) for item in cls.profile.headers())

    def build(self, rows, expected):
        text = self.header + "\n" + "\n".join(rows) + "\n"
        return build_protocol_inventory(
            text,
            self.profile,
            self.registry.protocol_groups,
            expected_frames=expected,
        )

    def test_protocol_counts_are_per_frame_and_deterministic(self):
        result = self.build(
            [
                '"1"\t"0"\t"100"\t"100"\t"eth:ip:udp:dns"',
                '"2"\t"0"\t"90"\t"100"\t"radiotap:wlan:eapol:wlan_rsna_eapol:eap"',
                '"3"\t"0"\t"120"\t"120"\t"eth:ip:tcp:tls"',
            ],
            3,
        )
        counts = {item.group_id: item.frame_count for item in result.observations}
        self.assertEqual(counts["dns"], 1)
        self.assertEqual(counts["eapol"], 1)
        self.assertEqual(counts["wlan"], 1)
        self.assertEqual(counts["tls"], 1)
        self.assertEqual(result.truncated_frames, 1)
        self.assertTrue(result.complete)
        self.assertEqual(result.to_dict(), result.to_dict())

    def test_partial_inventory_is_not_presented_as_complete(self):
        result = self.build(
            ['"1"\t"0"\t"100"\t"100"\t"eth:arp"'],
            10,
        )
        self.assertFalse(result.complete)
        self.assertTrue(any("일부 프레임" in item for item in result.cautions))

    def test_not_observed_protocol_is_not_failure_evidence(self):
        result = self.build(
            ['"1"\t"0"\t"100"\t"100"\t"eth:ip:udp:dns"'],
            1,
        )
        self.assertIn("RADIUS 인증", result.not_observed_labels)
        self.assertTrue(any("장애 증거가 아닙니다" in item for item in result.cautions))

    def test_duplicate_frame_number_and_bad_lengths_are_rejected(self):
        with self.assertRaises(ProtocolInventoryError):
            self.build(
                [
                    '"1"\t"0"\t"100"\t"100"\t"eth:ip"',
                    '"1"\t"0"\t"100"\t"100"\t"eth:ip"',
                ],
                2,
            )
        with self.assertRaises(ProtocolInventoryError):
            self.build(
                ['"1"\t"0"\t"101"\t"100"\t"eth:ip"'],
                1,
            )

    def test_observed_frames_cannot_exceed_preflight_count(self):
        with self.assertRaises(ProtocolInventoryError):
            self.build(
                [
                    '"1"\t"0"\t"100"\t"100"\t"eth:ip"',
                    '"2"\t"0"\t"100"\t"100"\t"eth:ip"',
                ],
                1,
            )


if __name__ == "__main__":
    unittest.main()
