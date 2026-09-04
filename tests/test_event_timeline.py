import json
import unittest
from pathlib import Path

from wlan_troubleshooter_ko.analysis.event_timeline import (
    EventTimelineError,
    build_event_timeline,
)
from wlan_troubleshooter_ko.tshark.catalog import parse_field_catalog
from wlan_troubleshooter_ko.tshark.inventory import adapt_connection_profile_for_timeline
from wlan_troubleshooter_ko.tshark.profiles import load_field_profiles, resolve_profile


FIELD_TYPES = {
    "frame.number": "FT_UINT32",
    "frame.time_epoch": "FT_RELATIVE_TIME",
    "frame.interface_id": "FT_UINT32",
    "frame.cap_len": "FT_UINT32",
    "frame.len": "FT_UINT32",
    "frame.protocols": "FT_STRING",
    "wlan.fc.type_subtype": "FT_UINT16",
    "wlan.fc.retry": "FT_BOOLEAN",
    "wlan.fixed.status_code": "FT_UINT16",
    "wlan.fixed.reason_code": "FT_UINT16",
    "wlan.fixed.auth.alg": "FT_UINT16",
    "wlan.fixed.auth_seq": "FT_UINT16",
    "eapol.type": "FT_UINT8",
    "wlan_rsna_eapol.keydes.msgnr": "FT_UINT8",
    "eap.code": "FT_UINT8",
    "eap.id": "FT_UINT8",
    "eap.type": "FT_UINT8",
    "radius.code": "FT_UINT8",
    "radius.id": "FT_UINT8",
    "dhcp.id": "FT_UINT32",
    "dhcp.option.dhcp": "FT_UINT8",
    "dns.id": "FT_UINT16",
    "dns.flags.response": "FT_BOOLEAN",
    "dns.flags.rcode": "FT_UINT8",
    "udp.stream": "FT_UINT32",
    "arp.opcode": "FT_UINT16",
    "tcp.stream": "FT_UINT32",
    "tcp.flags.syn": "FT_BOOLEAN",
    "tcp.flags.ack": "FT_BOOLEAN",
    "tcp.flags.reset": "FT_BOOLEAN",
    "tcp.analysis.retransmission": "FT_NONE",
    "tls.handshake.type": "FT_UINT8",
}


class EventTimelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry_path = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "wlan_troubleshooter_ko"
            / "resources"
            / "tshark"
            / "field-profiles.v1.json"
        )
        cls.registry = load_field_profiles(cls.registry_path)
        catalog_lines = ["P\tFrame\tframe\n"]
        for field_name, field_type in FIELD_TYPES.items():
            protocol = field_name.split(".", 1)[0]
            catalog_lines.append(
                "F\t{0}\t{0}\t{1}\t{2}\tBASE_DEC\t0x0\t\n".format(
                    field_name,
                    field_type,
                    protocol,
                )
            )
        connection_profile = resolve_profile(
            cls.registry,
            parse_field_catalog(catalog_lines),
            "connection-events",
        )
        cls.profile = adapt_connection_profile_for_timeline(connection_profile)

    def output(self, rows):
        header = "\t".join(self.profile.headers())
        values = [header]
        keys = self.profile.output_keys()
        for row in rows:
            values.append("\t".join(str(row.get(key, "")) for key in keys))
        return "\n".join(values) + "\n"

    def row(self, frame_number, protocols, **values):
        row = {
            "frame_number": frame_number,
            "time_epoch": "1700000000.{0:06d}".format(frame_number * 1000),
            "interface_id": 0,
            "captured_length": 100,
            "frame_length": 100,
            "protocols": protocols,
        }
        row.update(values)
        return row

    def stage(self, timeline, stage_id):
        return next(item for item in timeline.stages if item.stage_id == stage_id)

    def test_wireless_authentication_and_network_events_are_normalized(self):
        rows = [
            self.row(1, "wlan", wlan_type_subtype="0x000b", wlan_auth_algorithm=0, wlan_auth_sequence=1, wlan_status_code=0),
            self.row(2, "wlan", wlan_type_subtype="0x000b", wlan_auth_algorithm=0, wlan_auth_sequence=2, wlan_status_code=0),
            self.row(3, "wlan", wlan_type_subtype=0),
            self.row(4, "wlan", wlan_type_subtype=1, wlan_status_code=0),
            self.row(5, "eapol:wlan_rsna_eapol", eapol_type=3, eapol_key_message=1),
            self.row(6, "eapol:wlan_rsna_eapol", eapol_type=3, eapol_key_message=2),
            self.row(7, "eapol:wlan_rsna_eapol", eapol_type=3, eapol_key_message=3),
            self.row(8, "eapol:wlan_rsna_eapol", eapol_type=3, eapol_key_message=4),
            self.row(9, "eapol:eap", eapol_type=0, eap_code=1, eap_type=1, eap_identifier=7),
            self.row(10, "eapol:eap", eapol_type=0, eap_code=2, eap_type=1, eap_identifier=7),
            self.row(11, "eapol:eap", eapol_type=0, eap_code=3, eap_identifier=7),
            self.row(12, "eth:ip:udp:radius", radius_code=1, radius_identifier=3),
            self.row(13, "eth:ip:udp:radius", radius_code=2, radius_identifier=3),
            self.row(14, "eth:ip:udp:dhcp", dhcp_message_type=1, dhcp_transaction_id="0x01020304"),
            self.row(15, "eth:ip:udp:dhcp", dhcp_message_type=2, dhcp_transaction_id="0x01020304"),
            self.row(16, "eth:ip:udp:dhcp", dhcp_message_type=3, dhcp_transaction_id="0x01020304"),
            self.row(17, "eth:ip:udp:dhcp", dhcp_message_type=5, dhcp_transaction_id="0x01020304"),
            self.row(18, "eth:ip:udp:dns", dns_is_response=0, dns_identifier="0x1234"),
            self.row(19, "eth:ip:udp:dns", dns_is_response=1, dns_response_code=0, dns_identifier="0x1234"),
            self.row(20, "eth:ip:tcp", tcp_syn=1, tcp_ack=0, tcp_stream=0),
            self.row(21, "eth:ip:tcp", tcp_syn=1, tcp_ack=1, tcp_stream=0),
            self.row(22, "eth:ip:tcp", tcp_reset=1, tcp_stream=1),
            self.row(23, "eth:ip:tcp", tcp_retransmission=1, tcp_stream=2),
            self.row(24, "eth:ip:tcp:tls", tls_handshake_type=1, tcp_stream=3),
            self.row(25, "wlan", wlan_type_subtype=12, wlan_reason_code=3),
        ]

        timeline = build_event_timeline(
            self.output(rows),
            self.profile,
            expected_frames=len(rows),
        )
        event_types = {item.event_type for item in timeline.events}

        self.assertTrue(timeline.complete)
        self.assertIn("wlan_auth_response_success", event_types)
        self.assertIn("wlan_assoc_response_success", event_types)
        self.assertIn("eapol_key_message_4", event_types)
        self.assertIn("eap_success", event_types)
        self.assertIn("radius_access_accept", event_types)
        self.assertIn("dhcp_ack", event_types)
        self.assertIn("dns_response_success", event_types)
        self.assertIn("tcp_syn_ack", event_types)
        self.assertIn("tcp_reset", event_types)
        self.assertIn("tls_client_hello", event_types)
        self.assertIn("wlan_deauthentication", event_types)
        self.assertEqual(self.stage(timeline, "wlan-management").state, "success-observed")
        self.assertEqual(self.stage(timeline, "eapol-key").state, "sequence-observed")
        self.assertEqual(self.stage(timeline, "eap").state, "success-observed")
        self.assertEqual(self.stage(timeline, "radius").state, "success-observed")
        self.assertEqual(self.stage(timeline, "dhcp").state, "success-observed")
        self.assertEqual(self.stage(timeline, "dns").state, "success-observed")

        dns_events = [item for item in timeline.events if item.category == "dns"]
        dhcp_events = [item for item in timeline.events if item.category == "dhcp"]
        tcp_events = [item for item in timeline.events if item.correlation_alias == "TCP-1"]
        self.assertEqual({item.correlation_alias for item in dns_events}, {"DNS-1"})
        self.assertEqual({item.correlation_alias for item in dhcp_events}, {"DHCP-1"})
        self.assertEqual({item.event_type for item in tcp_events}, {"tcp_syn", "tcp_syn_ack"})

        rendered = json.dumps(timeline.to_dict(), ensure_ascii=False)
        self.assertNotIn("1700000000", rendered)
        self.assertNotIn("0x01020304", rendered)
        self.assertNotIn("0x1234", rendered)
        self.assertIn("frame.number == 1", rendered)

    def test_success_and_failure_are_reported_as_mixed_not_single_session(self):
        rows = [
            self.row(1, "eap", eap_code=3, eap_identifier=1),
            self.row(2, "eap", eap_code=4, eap_identifier=2),
            self.row(3, "radius", radius_code=2, radius_identifier=1),
            self.row(4, "radius", radius_code=3, radius_identifier=2),
            self.row(5, "dhcp", dhcp_message_type=5, dhcp_transaction_id=1),
            self.row(6, "dhcp", dhcp_message_type=6, dhcp_transaction_id=2),
            self.row(7, "dns", dns_is_response=1, dns_response_code=0, dns_identifier=1),
            self.row(8, "dns", dns_is_response=1, dns_response_code=3, dns_identifier=2),
        ]
        timeline = build_event_timeline(self.output(rows), self.profile, expected_frames=8)

        for stage_id in ("eap", "radius", "dhcp", "dns"):
            stage = self.stage(timeline, stage_id)
            self.assertEqual(stage.state, "mixed")
            self.assertIn("여러 접속", stage.summary_ko)

    def test_missing_optional_fields_make_only_relevant_stage_unavailable(self):
        base_fields = {
            key: value
            for key, value in FIELD_TYPES.items()
            if key.startswith("frame.")
        }
        lines = ["P\tFrame\tframe\n"]
        for field_name, field_type in base_fields.items():
            lines.append(
                "F\t{0}\t{0}\t{1}\tframe\tBASE_DEC\t0x0\t\n".format(
                    field_name,
                    field_type,
                )
            )
        connection_profile = resolve_profile(
            self.registry,
            parse_field_catalog(lines),
            "connection-events",
        )
        profile = adapt_connection_profile_for_timeline(connection_profile)
        header = "\t".join(profile.headers())
        row = "\t".join(
            {
                "frame_number": "1",
                "time_epoch": "1700000000.000000",
                "interface_id": "0",
                "captured_length": "64",
                "frame_length": "64",
                "protocols": "eth:ip",
            }.get(key, "")
            for key in profile.output_keys()
        )
        timeline = build_event_timeline(header + "\n" + row + "\n", profile, expected_frames=1)

        self.assertEqual(self.stage(timeline, "eap").state, "unavailable")
        self.assertEqual(self.stage(timeline, "dhcp").state, "unavailable")
        self.assertTrue(timeline.missing_optional_fields)

    def test_event_retention_limit_preserves_full_summary_count(self):
        rows = [self.row(index, "wlan", wlan_retry=1) for index in range(1, 21)]
        timeline = build_event_timeline(
            self.output(rows),
            self.profile,
            expected_frames=20,
            max_retained_events=5,
        )

        retry_summary = next(
            item for item in timeline.summaries if item.event_type == "wlan_retry_flag"
        )
        self.assertEqual(timeline.events_total, 20)
        self.assertEqual(timeline.events_retained, 5)
        self.assertEqual(timeline.events_omitted, 15)
        self.assertEqual(retry_summary.count, 20)

    def test_reverse_time_and_bad_frame_order_are_rejected(self):
        reverse_time = [
            self.row(1, "arp", arp_opcode=1),
            self.row(2, "arp", arp_opcode=2),
        ]
        reverse_time[1]["time_epoch"] = "1699999999.000000"
        with self.assertRaises(EventTimelineError):
            build_event_timeline(self.output(reverse_time), self.profile, expected_frames=2)

        duplicate_frame = [
            self.row(1, "arp", arp_opcode=1),
            self.row(1, "arp", arp_opcode=2),
        ]
        with self.assertRaises(EventTimelineError):
            build_event_timeline(self.output(duplicate_frame), self.profile, expected_frames=2)


if __name__ == "__main__":
    unittest.main()
