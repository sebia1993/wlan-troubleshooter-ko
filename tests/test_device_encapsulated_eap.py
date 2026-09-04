import unittest
from dataclasses import dataclass

from wlan_troubleshooter_ko.analysis.device_sessions import build_device_sessions
from wlan_troubleshooter_ko.tshark.profiles import ResolvedField, ResolvedProfile


FIELDS = (
    ("frame_number", "frame.number"),
    ("time_epoch", "frame.time_epoch"),
    ("protocols", "frame.protocols"),
    ("wlan_type_subtype", "wlan.fc.type_subtype"),
    ("wlan_auth_sequence", "wlan.fixed.auth_seq"),
    ("eapol_type", "eapol.type"),
    ("eap_code", "eap.code"),
    ("dhcp_message_type", "dhcp.option.dhcp"),
    ("eth_source", "eth.src"),
    ("eth_destination", "eth.dst"),
    ("wlan_source", "wlan.sa"),
    ("wlan_destination", "wlan.da"),
    ("wlan_bssid", "wlan.bssid"),
)


@dataclass(frozen=True)
class EmptyTransactions:
    attempts: tuple[object, ...] = ()
    complete: bool = True


class EncapsulatedEapDeviceTests(unittest.TestCase):
    def profile(self) -> ResolvedProfile:
        return ResolvedProfile(
            profile_id="device-identities",
            profile_version="0.5.0",
            display_filter_name="capture-overview",
            max_packets=100,
            fields=tuple(ResolvedField(key, field) for key, field in FIELDS),
            missing_optional_fields=(),
        )

    def output(self, row: dict[str, object]) -> str:
        profile = self.profile()
        values = {
            "frame_number": 1,
            "time_epoch": "1700000000.000000",
            "protocols": "",
            **row,
        }
        return (
            "\t".join(profile.headers())
            + "\n"
            + "\t".join(str(values.get(key, "")) for key in profile.output_keys())
            + "\n"
        )

    def test_radius_encapsulated_eap_does_not_create_device_alias(self):
        text = self.output(
            {
                "protocols": "eth:ip:udp:radius:eap",
                "eap_code": 2,
                "eth_source": "02:00:00:00:10:01",
                "eth_destination": "02:00:00:00:20:01",
            }
        )

        report = build_device_sessions(
            text,
            self.profile(),
            EmptyTransactions(),
            expected_frames=1,
        )

        self.assertEqual(report.devices, ())
        self.assertEqual(report.frames_unassigned, 1)

    def test_direct_ethernet_eapol_eap_still_creates_supplicant_alias(self):
        text = self.output(
            {
                "protocols": "eth:eapol:eap",
                "eap_code": 2,
                "eth_source": "02:00:00:00:00:10",
                "eth_destination": "02:00:00:00:00:20",
            }
        )

        report = build_device_sessions(
            text,
            self.profile(),
            EmptyTransactions(),
            expected_frames=1,
        )

        self.assertEqual(len(report.devices), 1)
        self.assertEqual(report.devices[0].alias, "DEVICE-1")
        self.assertIn("ethernet-eap-response", report.devices[0].evidence_types)


if __name__ == "__main__":
    unittest.main()
