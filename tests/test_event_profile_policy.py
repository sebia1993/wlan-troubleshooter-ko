import unittest
from pathlib import Path

from wlan_troubleshooter_ko.tshark.catalog import parse_field_catalog
from wlan_troubleshooter_ko.tshark.policy import (
    APPROVED_FIELDS,
    TRANSIENT_EAPOL_RELATION_FIELDS,
    TRANSIENT_IDENTITY_FIELDS,
    TSharkPolicyError,
    assert_safe_profile_argv,
)
from wlan_troubleshooter_ko.tshark.profiles import load_field_profiles, resolve_profile


FORBIDDEN_PUBLIC_FIELD_FRAGMENTS = (
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
    "eapol.keydes.replay_counter",
    "http.",
    "tcp.payload",
    "data.data",
)

FORBIDDEN_IDENTITY_PROFILE_FRAGMENTS = (
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "wlan.ssid",
    "radius.user",
    "eap.identity",
    "dns.qry.name",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "eapol.keydes.replay_counter",
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

    def candidates(self, profile_id):
        profile = self.registry.get_profile(profile_id)
        return [
            candidate
            for requirement in profile.fields
            for candidate in requirement.candidates
        ]

    def catalog(self):
        catalog_lines = ["P\tFrame\tframe\n"]
        fields = (
            *APPROVED_FIELDS,
            *TRANSIENT_IDENTITY_FIELDS,
            *TRANSIENT_EAPOL_RELATION_FIELDS,
        )
        for field in fields:
            protocol = field.split(".", 1)[0]
            catalog_lines.append(
                "F\t{0}\t{0}\tFT_STRING\t{1}\t\t0x0\t\n".format(
                    field,
                    protocol,
                )
            )
        return parse_field_catalog(catalog_lines)

    def arguments(self, profile):
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
        return arguments

    def test_public_event_profile_has_no_address_identity_key_or_payload_field(self):
        candidates = self.candidates("connection-events")
        rendered = "\n".join(candidates).casefold()
        for fragment in FORBIDDEN_PUBLIC_FIELD_FRAGMENTS:
            self.assertNotIn(fragment, rendered)
        self.assertEqual(
            len(self.registry.get_profile("connection-events").fields),
            32,
        )
        self.assertEqual(self.registry.profile_version, "0.6.0")

    def test_identity_profile_has_only_reviewed_transient_l2_identifiers(self):
        candidates = self.candidates("device-identities")
        rendered = "\n".join(candidates).casefold()
        for fragment in FORBIDDEN_IDENTITY_PROFILE_FRAGMENTS:
            self.assertNotIn(fragment, rendered)
        transient = {
            value for value in candidates if value in TRANSIENT_IDENTITY_FIELDS
        }
        self.assertEqual(transient, set(TRANSIENT_IDENTITY_FIELDS))
        self.assertEqual(
            len(self.registry.get_profile("device-identities").fields),
            13,
        )
        self.assertNotIn("wlan.ssid", transient)

    def test_replay_profile_is_minimal_and_counter_is_not_generally_approved(self):
        candidates = self.candidates("eapol-replay-relations")
        self.assertEqual(
            candidates,
            [
                "frame.number",
                "wlan_rsna_eapol.keydes.msgnr",
                "eapol.keydes.replay_counter",
            ],
        )
        self.assertNotIn("eapol.keydes.replay_counter", APPROVED_FIELDS)
        self.assertEqual(
            set(TRANSIENT_EAPOL_RELATION_FIELDS),
            {"eapol.keydes.replay_counter"},
        )
        rendered = "\n".join(candidates).casefold()
        for forbidden in (
            "eth.",
            "wlan.sa",
            "wlan.da",
            "wlan.bssid",
            "wlan.ssid",
            "ip.",
            "ipv6.",
            "radius.",
            "dns.",
            "tcp.",
            "udp.",
            "nonce",
            "mic",
            "key_data",
            "payload",
        ):
            self.assertNotIn(forbidden, rendered)

    def test_every_profile_candidate_is_explicitly_approved(self):
        public = set(APPROVED_FIELDS)
        identity = set(TRANSIENT_IDENTITY_FIELDS)
        replay = set(TRANSIENT_EAPOL_RELATION_FIELDS)
        for profile in self.registry.profiles:
            for requirement in profile.fields:
                for candidate in requirement.candidates:
                    if profile.profile_id == "device-identities":
                        self.assertIn(candidate, public | identity)
                        self.assertNotIn(candidate, replay)
                    elif profile.profile_id == "eapol-replay-relations":
                        self.assertIn(candidate, public | replay)
                        self.assertNotIn(candidate, identity)
                    else:
                        self.assertIn(candidate, public)
                        self.assertNotIn(candidate, identity | replay)

    def test_profile_required_fields_are_minimal_metadata(self):
        event_required = {
            requirement.output_key
            for requirement in self.registry.get_profile("connection-events").fields
            if requirement.required
        }
        identity_required = {
            requirement.output_key
            for requirement in self.registry.get_profile("device-identities").fields
            if requirement.required
        }
        replay_required = {
            requirement.output_key
            for requirement in self.registry.get_profile(
                "eapol-replay-relations"
            ).fields
            if requirement.required
        }
        self.assertEqual(
            event_required,
            {
                "frame_number",
                "time_epoch",
                "captured_length",
                "frame_length",
                "protocols",
            },
        )
        self.assertEqual(
            identity_required,
            {"frame_number", "time_epoch", "protocols"},
        )
        self.assertEqual(replay_required, {"frame_number"})

    def test_public_event_argv_rejects_live_capture_and_transient_fields(self):
        profile = resolve_profile(
            self.registry,
            self.catalog(),
            "connection-events",
        )
        arguments = self.arguments(profile)
        assert_safe_profile_argv(arguments)

        with self.assertRaises(TSharkPolicyError):
            assert_safe_profile_argv(arguments + ["-i", "1"])
        for sensitive_field in (
            "eth.src",
            "eapol.keydes.replay_counter",
        ):
            sensitive = list(arguments)
            sensitive[-1] = sensitive_field
            with self.subTest(sensitive_field=sensitive_field):
                with self.assertRaises(TSharkPolicyError):
                    assert_safe_profile_argv(sensitive)

    def test_identity_argv_requires_explicit_profile_context(self):
        profile = resolve_profile(
            self.registry,
            self.catalog(),
            "device-identities",
        )
        arguments = self.arguments(profile)

        assert_safe_profile_argv(arguments, "device-identities")
        with self.assertRaises(TSharkPolicyError):
            assert_safe_profile_argv(arguments)

        sensitive = list(arguments)
        sensitive[-1] = "ip.src"
        with self.assertRaises(TSharkPolicyError):
            assert_safe_profile_argv(sensitive, "device-identities")

    def test_replay_argv_requires_explicit_profile_context(self):
        profile = resolve_profile(
            self.registry,
            self.catalog(),
            "eapol-replay-relations",
        )
        arguments = self.arguments(profile)

        assert_safe_profile_argv(arguments, "eapol-replay-relations")
        with self.assertRaises(TSharkPolicyError):
            assert_safe_profile_argv(arguments)
        with self.assertRaises(TSharkPolicyError):
            assert_safe_profile_argv(arguments, "connection-events")

        sensitive = list(arguments)
        sensitive[-1] = "eapol.keydes.nonce"
        with self.assertRaises(TSharkPolicyError):
            assert_safe_profile_argv(
                sensitive,
                "eapol-replay-relations",
            )


if __name__ == "__main__":
    unittest.main()
