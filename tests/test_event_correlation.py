import json
import unittest
from pathlib import Path

from wlan_troubleshooter_ko.analysis.event_correlation import (
    EventCorrelationError,
    build_event_correlation,
)
from wlan_troubleshooter_ko.core.config import load_ruleset
from wlan_troubleshooter_ko.tshark.catalog import parse_field_catalog
from wlan_troubleshooter_ko.tshark.profiles import load_field_profiles, resolve_profile


class EventCorrelationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.profile_path = (
            root
            / "src"
            / "wlan_troubleshooter_ko"
            / "resources"
            / "tshark"
            / "field-profiles.v1.json"
        )
        cls.rules_path = (
            root
            / "src"
            / "wlan_troubleshooter_ko"
            / "resources"
            / "rules"
            / "v1"
            / "rules.json"
        )
        cls.registry = load_field_profiles(cls.profile_path)
        lines = ["P\tFrame\tframe\n"]
        seen = set()
        for requirement in cls.registry.get_profile("connection-events").fields:
            field_name = requirement.candidates[0]
            if field_name in seen:
                continue
            seen.add(field_name)
            lines.append(
                "F\t{0}\t{0}\tFT_STRING\tframe\t\t0x0\t\n".format(field_name)
            )
        cls.profile = resolve_profile(
            cls.registry,
            parse_field_catalog(lines),
            "connection-events",
        )
        cls.ruleset = load_ruleset(cls.rules_path)

    def render(self, rows):
        header = "\t".join('"{0}"'.format(item) for item in self.profile.headers())
        rendered = [header]
        positions = {item.output_key: item.field_name for item in self.profile.fields}
        for values in rows:
            by_field = {
                positions[key]: value
                for key, value in values.items()
                if key in positions
            }
            rendered.append(
                "\t".join(
                    '"{0}"'.format(str(by_field.get(field_name, "")).replace('"', '""'))
                    for field_name in self.profile.headers()
                )
            )
        return "\n".join(rendered) + "\n"

    def base(self, frame, seconds, protocols):
        return {
            "frame_number": frame,
            "time_epoch": "{0}.000000000".format(seconds),
            "captured_length": 100,
            "frame_length": 100,
            "protocols": protocols,
        }

    def test_explicit_failures_generate_evidence_backed_findings(self):
        rows = []
        values = self.base(1, 1, "eth:eapol:eap")
        values.update({"eapol_type": 0, "eap_code": 4, "eap_id": 7})
        rows.append(values)
        values = self.base(2, 2, "eth:ip:udp:radius")
        values.update({"radius_code": 3, "radius_id": 9, "udp_stream": 1})
        rows.append(values)
        values = self.base(3, 3, "eth:ip:udp:dhcp")
        values.update({"dhcp_id": 100, "dhcp_message_type": 6, "udp_stream": 2})
        rows.append(values)
        values = self.base(4, 4, "eth:ip:udp:dns")
        values.update(
            {
                "dns_id": 5,
                "dns_is_response": 1,
                "dns_rcode": 3,
                "udp_stream": 3,
            }
        )
        rows.append(values)
        values = self.base(5, 5, "eth:ip:tcp")
        values.update(
            {
                "tcp_stream": 4,
                "tcp_syn": 0,
                "tcp_ack": 1,
                "tcp_reset": 1,
            }
        )
        rows.append(values)

        result = build_event_correlation(
            self.render(rows),
            self.profile,
            self.ruleset,
            expected_frames=len(rows),
            has_80211_link_type=False,
        )

        findings = {item.rule_id: item for item in result.findings}
        self.assertEqual(findings["EAP-FAILURE"].classification, "확정")
        self.assertEqual(findings["RADIUS-ACCESS-REJECT"].evidence_frames, (2,))
        self.assertEqual(findings["DHCP-NAK"].evidence_frames, (3,))
        self.assertIn("NXDOMAIN", findings["DNS-ERROR-RESPONSE"].summary_ko)
        self.assertEqual(findings["TCP-RST"].display_filter, "frame.number == 5")
        stages = {item.stage_id: item.state for item in result.stages}
        self.assertEqual(stages["eap"], "failure")
        self.assertEqual(stages["radius"], "failure")
        self.assertEqual(stages["dhcp"], "failure")
        self.assertEqual(stages["dns"], "failure")
        self.assertEqual(stages["tcp"], "failure")
        self.assertEqual(stages["wlan"], "unavailable")
        self.assertTrue(result.complete)

    def test_success_sequences_are_separated_from_failure_findings(self):
        rows = []
        values = self.base(1, 1, "eth:ip:tcp")
        values.update({"tcp_stream": 1, "tcp_syn": 1, "tcp_ack": 0})
        rows.append(values)
        values = self.base(2, 2, "eth:ip:tcp")
        values.update({"tcp_stream": 1, "tcp_syn": 1, "tcp_ack": 1})
        rows.append(values)
        values = self.base(3, 3, "eth:ip:tcp")
        values.update({"tcp_stream": 1, "tcp_syn": 0, "tcp_ack": 1})
        rows.append(values)
        values = self.base(4, 4, "eth:ip:udp:dhcp")
        values.update({"dhcp_id": 1, "dhcp_message_type": 5})
        rows.append(values)
        values = self.base(5, 5, "eth:ip:udp:dns")
        values.update({"dns_id": 1, "dns_is_response": 1, "dns_rcode": 0})
        rows.append(values)
        values = self.base(6, 6, "eth:eap")
        values.update({"eap_code": 3})
        rows.append(values)
        values = self.base(7, 7, "eth:ip:udp:radius")
        values.update({"radius_code": 2})
        rows.append(values)

        result = build_event_correlation(
            self.render(rows),
            self.profile,
            self.ruleset,
            expected_frames=len(rows),
            has_80211_link_type=False,
        )
        stages = {item.stage_id: item.state for item in result.stages}
        self.assertEqual(stages["tcp"], "success")
        self.assertEqual(stages["dhcp"], "success")
        self.assertEqual(stages["dns"], "success")
        self.assertEqual(stages["eap"], "success")
        self.assertEqual(stages["radius"], "success")
        self.assertFalse(
            {"EAP-FAILURE", "RADIUS-ACCESS-REJECT", "DHCP-NAK"}
            & {item.rule_id for item in result.findings}
        )

    def test_complete_capture_can_report_unanswered_without_calling_it_failure(self):
        rows = []
        values = self.base(1, 1, "eth:ip:udp:dhcp")
        values.update({"dhcp_id": 10, "dhcp_message_type": 1})
        rows.append(values)
        values = self.base(2, 2, "eth:ip:udp:dns")
        values.update({"dns_id": 11, "dns_is_response": 0, "udp_stream": 2})
        rows.append(values)
        values = self.base(3, 3, "eth:ip:tcp")
        values.update({"tcp_stream": 3, "tcp_syn": 1, "tcp_ack": 0})
        rows.append(values)
        rows.append(self.base(4, 10, "eth:arp"))

        result = build_event_correlation(
            self.render(rows),
            self.profile,
            self.ruleset,
            expected_frames=len(rows),
            has_80211_link_type=False,
        )
        findings = {item.rule_id: item for item in result.findings}
        for rule_id in (
            "DHCP-RESPONSE-NOT-OBSERVED",
            "DNS-RESPONSE-NOT-OBSERVED",
            "TCP-SYNACK-NOT-OBSERVED",
        ):
            self.assertEqual(findings[rule_id].classification, "판단 불가")
        self.assertFalse(any(item.classification == "유력" for item in result.findings))

    def test_partial_capture_suppresses_unanswered_findings(self):
        values = self.base(1, 1, "eth:ip:udp:dns")
        values.update({"dns_id": 1, "dns_is_response": 0, "udp_stream": 1})
        result = build_event_correlation(
            self.render([values]),
            self.profile,
            self.ruleset,
            expected_frames=10,
            has_80211_link_type=False,
        )
        self.assertFalse(result.complete)
        self.assertNotIn(
            "DNS-RESPONSE-NOT-OBSERVED",
            {item.rule_id for item in result.findings},
        )
        self.assertTrue(any("미응답 여부" in item for item in result.cautions))

    def test_wlan_reject_and_disconnect_use_only_frame_evidence(self):
        rows = []
        values = self.base(1, 1, "radiotap:wlan")
        values.update({"wlan_type_subtype": 1, "wlan_status_code": 17})
        rows.append(values)
        values = self.base(2, 2, "radiotap:wlan")
        values.update({"wlan_type_subtype": 12, "wlan_reason_code": 4})
        rows.append(values)
        result = build_event_correlation(
            self.render(rows),
            self.profile,
            self.ruleset,
            expected_frames=2,
            has_80211_link_type=True,
        )
        findings = {item.rule_id: item for item in result.findings}
        self.assertEqual(findings["WLAN-ASSOC-REJECT"].classification, "확정")
        self.assertEqual(findings["WLAN-DISCONNECT"].classification, "참고")
        self.assertEqual(findings["WLAN-DISCONNECT"].evidence_frames, (2,))

    def test_ruleset_missing_required_rule_fails_closed(self):
        broken = dict(self.ruleset)
        broken["rules"] = self.ruleset["rules"][:-1]
        with self.assertRaises(EventCorrelationError):
            build_event_correlation(
                self.render([self.base(1, 1, "eth:arp")]),
                self.profile,
                broken,
                expected_frames=1,
                has_80211_link_type=False,
            )

    def test_result_is_deterministic_and_identifier_free(self):
        values = self.base(1, 1, "eth:ip:udp:dns")
        values.update(
            {
                "dns_id": 1,
                "dns_is_response": 1,
                "dns_rcode": 2,
                "udp_stream": 9,
            }
        )
        result = build_event_correlation(
            self.render([values]),
            self.profile,
            self.ruleset,
            expected_frames=1,
            has_80211_link_type=False,
        )
        self.assertEqual(result.to_dict(), result.to_dict())
        rendered = json.dumps(result.to_dict(), ensure_ascii=False)
        self.assertNotIn("udp_stream", rendered)
        self.assertNotIn("dns_id", rendered)
        self.assertNotIn("192.0.2", rendered)


if __name__ == "__main__":
    unittest.main()
