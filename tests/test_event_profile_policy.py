import unittest
from pathlib import Path

from wlan_troubleshooter_ko.tshark.catalog import parse_field_catalog
from wlan_troubleshooter_ko.tshark.policy import (
    APPROVED_FIELDS,
    TSharkPolicyError,
    assert_safe_profile_argv,
)
from wlan_troubleshooter_ko.tshark.profiles import load_field_profiles, resolve_profile


SENSITIVE_FIELD_FRAGMENTS = (
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "eth.src",
    "eth.dst",
    "wlan.sa",
    "wlan.da",
    "wlan.ta",
    "wlan.ra",
    "wlan.bssid",
    "wlan.ssid",
    "radius.user",
    "eap.identity",
    "dns.qry.name",
    "http.",
    "tcp.payload",
    "data.data",
)


class EventProfilePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.registry = load_field_profiles(
            cls.root
            / "src"
            / "wlan_troubleshooter_ko"
            / "resources"
            / "tshark"
            / "field-profiles.v1.json"
        )

    def test_event_profile_has_no_address_identity_or_payload_field(self):
        profile = self.registry.get_profile("connection-events")
        candidates = [
            candidate
            for requirement in profile.fields
            for candidate in requirement.candidates
        ]
        rendered = "\n".join(candidates).casefold()
        for fragment in SENSITIVE_FIELD_FRAGMENTS:
            self.assertNotIn(fragment, rendered)
        self.assertEqual(len(profile.fields), 32)
        self.assertEqual(self.registry.profile_version, "0.4.0")
        self.assertIn("wlan.fc.retry", candidates)
        self.assertIn("wlan_rsna_eapol.keydes.msgnr", candidates)
        self.assertIn("tls.handshake.type", candidates)

    def test_every_profile_candidate_is_explicitly_approved(self):
        approved = set(APPROVED_FIELDS)
        for profile in self.registry.profiles:
            for requirement in profile.fields:
                for candidate in requirement.candidates:
                    self.assertIn(candidate, approved)

    def test_event_profile_required_fields_are_minimal_metadata(self):
        profile = self.registry.get_profile("connection-events")
        required = {
            requirement.output_key
            for requirement in profile.fields
            if requirement.required
        }
        self.assertEqual(
            required,
            {
                "frame_number",
                "time_epoch",
                "captured_length",
                "frame_length",
                "protocols",
            },
        )

    def test_generated_event_argv_rejects_live_capture_and_sensitive_field(self):
        catalog_lines = ["P\tFrame\tframe\n"]
        for field in APPROVED_FIELDS:
            protocol = field.split(".", 1)[0]
            catalog_lines.append(
                "F\t{0}\t{0}\tFT_STRING\t{1}\t\t0x0\t\n".format(
                    field,
                    protocol,
                )
            )
        catalog = parse_field_catalog(catalog_lines)
        profile = resolve_profile(self.registry, catalog, "connection-events")

        executable = (
            Path.cwd() / "portable" / "vendor" / "wireshark" / "tshark.exe"
        ).resolve()
        capture = (Path.cwd() / "capture" / "test.pcap").resolve()
        arguments = [
            str(executable),
            "-n",
            "-2",
            "-r",
            str(capture),
            "-c",
            str(profile.max_packets),
            "-T",
            "fields",
            "-E",
            "header=y",
            "-E",
            "separator=/t",
            "-E",
            "occurrence=f",
            "-E",
            "quote=d",
            "-E",
            "escape=y",
            "-Y",
            "frame.number >= 1",
        ]
        for field in profile.headers():
            arguments.extend(("-e", field))
        assert_safe_profile_argv(arguments)

        with self.assertRaises(TSharkPolicyError):
            assert_safe_profile_argv(arguments + ["-i", "1"])
        sensitive = list(arguments)
        sensitive[-1] = "ip.src"
        with self.assertRaises(TSharkPolicyError):
            assert_safe_profile_argv(sensitive)


if __name__ == "__main__":
    unittest.main()
