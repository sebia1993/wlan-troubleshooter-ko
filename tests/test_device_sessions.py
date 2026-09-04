import hashlib
import hmac
import json
import unittest
from dataclasses import dataclass
from unittest import mock

from wlan_troubleshooter_ko.analysis.device_sessions import (
    DeviceSessionError,
    build_device_sessions,
)
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
class FakeAttempt:
    attempt_id: str
    evidence_frames: tuple[int, ...]


@dataclass(frozen=True)
class FakeTransactions:
    attempts: tuple[FakeAttempt, ...]
    complete: bool = True


class DeviceSessionTests(unittest.TestCase):
    def profile(self):
        return ResolvedProfile(
            profile_id="device-identities",
            profile_version="0.5.0",
            display_filter_name="capture-overview",
            max_packets=100_000,
            fields=tuple(ResolvedField(key, field) for key, field in FIELDS),
            missing_optional_fields=(),
        )

    def output(self, rows):
        profile = self.profile()
        keys = profile.output_keys()
        lines = ["\t".join(profile.headers())]
        for row in rows:
            lines.append("\t".join(str(row.get(key, "")) for key in keys))
        return "\n".join(lines) + "\n"

    def row(self, frame, protocols, **values):
        result = {
            "frame_number": frame,
            "time_epoch": "1700000000.{0:06d}".format(frame * 1000),
            "protocols": protocols,
        }
        result.update(values)
        return result

    def test_ethernet_client_becomes_one_device_and_attempts_link(self):
        client = "02:00:00:00:00:10"
        server = "02:00:00:00:00:20"
        broadcast = "ff:ff:ff:ff:ff:ff"
        rows = [
            self.row(1, "eth:eapol:eap", eap_code=1, eth_source=server, eth_destination=client),
            self.row(2, "eth:eapol:eap", eap_code=2, eth_source=client, eth_destination=server),
            self.row(3, "eth:eapol:eap", eap_code=3, eth_source=server, eth_destination=client),
            self.row(4, "eth:ip:udp:dhcp", dhcp_message_type=1, eth_source=client, eth_destination=broadcast),
            self.row(5, "eth:ip:udp:dhcp", dhcp_message_type=2, eth_source=server, eth_destination=broadcast),
            self.row(6, "eth:ip:udp:dns", eth_source=client, eth_destination=server),
            self.row(7, "eth:ip:udp:dns", eth_source=server, eth_destination=client),
            self.row(8, "eth:ip:tcp", eth_source=client, eth_destination=server),
            self.row(9, "eth:ip:tcp", eth_source=server, eth_destination=client),
        ]
        transactions = FakeTransactions(
            (
                FakeAttempt("EAP-1-A1", (1, 2, 3)),
                FakeAttempt("DHCP-1-A1", (4, 5)),
                FakeAttempt("DNS-1-A1", (6, 7)),
                FakeAttempt("TCP-1-A1", (8, 9)),
            )
        )

        report = build_device_sessions(
            self.output(rows),
            self.profile(),
            transactions,
            expected_frames=9,
        )

        self.assertTrue(report.complete)
        self.assertEqual(len(report.devices), 1)
        device = report.devices[0]
        self.assertEqual(device.alias, "DEVICE-1")
        self.assertEqual(
            device.linked_attempt_ids,
            ("DHCP-1-A1", "DNS-1-A1", "EAP-1-A1", "TCP-1-A1"),
        )
        self.assertIn("dhcp-client", device.evidence_types)
        self.assertIn("ethernet-eap-request", device.evidence_types)
        self.assertEqual({link.state for link in report.attempt_links}, {"linked"})
        self.assertFalse(report.raw_identifiers_serialized)
        self.assertFalse(report.alias_secret_persisted)
        self.assertFalse(report.aliases_stable_across_runs)

        rendered = json.dumps(report.to_dict(), ensure_ascii=False)
        self.assertNotIn(client, rendered)
        self.assertNotIn(server, rendered)
        self.assertNotIn("020000000010", rendered)

    @mock.patch(
        "wlan_troubleshooter_ko.analysis.device_sessions.os.urandom",
        side_effect=(b"a" * 32, b"b" * 32),
    )
    def test_each_analysis_uses_new_secret_and_never_serializes_hmac(self, urandom):
        client = "02:00:00:00:00:10"
        text = self.output(
            [
                self.row(
                    1,
                    "eth:ip:udp:dhcp",
                    dhcp_message_type=1,
                    eth_source=client,
                    eth_destination="ff:ff:ff:ff:ff:ff",
                )
            ]
        )
        transactions = FakeTransactions(())

        first = build_device_sessions(
            text,
            self.profile(),
            transactions,
            expected_frames=1,
        )
        second = build_device_sessions(
            text,
            self.profile(),
            transactions,
            expected_frames=1,
        )

        self.assertEqual(urandom.call_args_list, [mock.call(32), mock.call(32)])
        self.assertEqual(first.devices[0].alias, "DEVICE-1")
        self.assertEqual(second.devices[0].alias, "DEVICE-1")
        self.assertFalse(first.aliases_stable_across_runs)
        self.assertFalse(second.aliases_stable_across_runs)

        raw = bytes.fromhex("020000000010")
        first_digest = hmac.new(
            b"a" * 32,
            b"device\x00" + raw,
            hashlib.sha256,
        ).hexdigest()
        second_digest = hmac.new(
            b"b" * 32,
            b"device\x00" + raw,
            hashlib.sha256,
        ).hexdigest()
        rendered = json.dumps(
            {"first": first.to_dict(), "second": second.to_dict()},
            ensure_ascii=False,
        )
        self.assertNotIn(first_digest, rendered)
        self.assertNotIn(second_digest, rendered)
        self.assertNotIn(client, rendered)

    @mock.patch(
        "wlan_troubleshooter_ko.analysis.device_sessions.os.urandom",
        return_value=b"short",
    )
    def test_invalid_analysis_secret_length_fails_closed(self, urandom):
        with self.assertRaises(DeviceSessionError):
            build_device_sessions(
                self.output([]),
                self.profile(),
                FakeTransactions(()),
                expected_frames=0,
            )
        urandom.assert_called_once_with(32)

    def test_wireless_station_and_ap_are_separate_aliases(self):
        station = "02:00:00:00:00:a1"
        ap = "02:00:00:00:00:b1"
        rows = [
            self.row(1, "wlan", wlan_type_subtype=11, wlan_auth_sequence=1, wlan_source=station, wlan_destination=ap, wlan_bssid=ap),
            self.row(2, "wlan", wlan_type_subtype=11, wlan_auth_sequence=2, wlan_source=ap, wlan_destination=station, wlan_bssid=ap),
            self.row(3, "wlan:eapol:eap", eap_code=2, wlan_source=station, wlan_destination=ap, wlan_bssid=ap),
        ]

        report = build_device_sessions(
            self.output(rows),
            self.profile(),
            FakeTransactions((FakeAttempt("EAP-1-A1", (3,)),)),
            expected_frames=3,
        )

        self.assertEqual(len(report.devices), 1)
        self.assertEqual(report.devices[0].alias, "DEVICE-1")
        self.assertEqual(report.devices[0].ap_aliases, ("AP-1",))
        self.assertEqual(report.attempt_links[0].device_alias, "DEVICE-1")
        rendered = json.dumps(report.to_dict(), ensure_ascii=False)
        self.assertNotIn(station, rendered)
        self.assertNotIn(ap, rendered)

    def test_arbitrary_dns_endpoints_do_not_create_devices(self):
        rows = [
            self.row(1, "eth:ip:udp:dns", eth_source="02:00:00:00:00:10", eth_destination="02:00:00:00:00:20")
        ]
        report = build_device_sessions(
            self.output(rows),
            self.profile(),
            FakeTransactions((FakeAttempt("DNS-1-A1", (1,)),)),
            expected_frames=1,
        )

        self.assertEqual(report.devices, ())
        self.assertEqual(report.attempt_links[0].state, "unassigned")
        self.assertEqual(report.frames_unassigned, 1)

    def test_two_known_devices_in_one_frame_are_ambiguous(self):
        first = "02:00:00:00:00:11"
        second = "02:00:00:00:00:12"
        server = "02:00:00:00:00:20"
        rows = [
            self.row(1, "eth:ip:udp:dhcp", dhcp_message_type=1, eth_source=first, eth_destination="ff:ff:ff:ff:ff:ff"),
            self.row(2, "eth:ip:udp:dhcp", dhcp_message_type=1, eth_source=second, eth_destination="ff:ff:ff:ff:ff:ff"),
            self.row(3, "eth:ip:tcp", eth_source=first, eth_destination=second),
            self.row(4, "eth:ip:tcp", eth_source=server, eth_destination=first),
        ]
        transactions = FakeTransactions(
            (
                FakeAttempt("TCP-1-A1", (3,)),
                FakeAttempt("TCP-2-A1", (3, 4)),
            )
        )

        report = build_device_sessions(
            self.output(rows),
            self.profile(),
            transactions,
            expected_frames=4,
        )

        self.assertEqual(len(report.devices), 2)
        self.assertEqual(report.frames_ambiguous, 1)
        self.assertEqual(report.attempt_links[0].state, "unassigned")
        self.assertEqual(report.attempt_links[1].state, "linked")
        self.assertEqual(report.attempt_links[1].device_alias, "DEVICE-1")

    def test_partial_transactions_make_report_partial(self):
        rows = [
            self.row(1, "eth:ip:udp:dhcp", dhcp_message_type=1, eth_source="02:00:00:00:00:10", eth_destination="ff:ff:ff:ff:ff:ff")
        ]
        report = build_device_sessions(
            self.output(rows),
            self.profile(),
            FakeTransactions((), complete=False),
            expected_frames=1,
        )
        self.assertFalse(report.complete)
        self.assertTrue(any("일부 결과" in value for value in report.cautions))

    def test_invalid_profile_mac_order_and_attempt_are_rejected(self):
        wrong_profile = ResolvedProfile(
            profile_id="connection-events",
            profile_version="0.5.0",
            display_filter_name="capture-overview",
            max_packets=1,
            fields=tuple(ResolvedField(key, field) for key, field in FIELDS),
            missing_optional_fields=(),
        )
        with self.assertRaises(DeviceSessionError):
            build_device_sessions(self.output([]), wrong_profile, FakeTransactions(()), expected_frames=0)

        bad_mac = [
            self.row(1, "eth:ip:udp:dhcp", dhcp_message_type=1, eth_source="not-a-mac")
        ]
        with self.assertRaises(DeviceSessionError):
            build_device_sessions(self.output(bad_mac), self.profile(), FakeTransactions(()), expected_frames=1)

        reverse = [
            self.row(2, "eth:ip:udp:dhcp", dhcp_message_type=1, eth_source="02:00:00:00:00:10"),
            self.row(1, "eth:ip:udp:dhcp", dhcp_message_type=1, eth_source="02:00:00:00:00:10"),
        ]
        with self.assertRaises(DeviceSessionError):
            build_device_sessions(self.output(reverse), self.profile(), FakeTransactions(()), expected_frames=2)

        with self.assertRaises(DeviceSessionError):
            build_device_sessions(
                self.output([self.row(1, "eth:ip:udp:dhcp", dhcp_message_type=1, eth_source="02:00:00:00:00:10")]),
                self.profile(),
                FakeTransactions((FakeAttempt("BAD-1", (1,)),)),
                expected_frames=1,
            )


if __name__ == "__main__":
    unittest.main()
