import json
import unittest
from pathlib import Path


class PortableSupplyChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.support = cls.root / "tests" / "portable_build"
        cls.value = json.loads(
            (cls.support / "supply-chain.json").read_text(encoding="utf-8")
        )

    def text(self, relative):
        return (self.root / relative).read_text(encoding="utf-8")

    def support_text(self, filename):
        return (self.support / filename).read_text(encoding="utf-8")

    def test_supply_chain_schema_and_versions_are_exact(self):
        self.assertEqual(
            set(self.value),
            {
                "schema_version",
                "python_version",
                "pyinstaller_version",
                "wireshark",
            },
        )
        self.assertEqual(self.value["schema_version"], 1)
        self.assertEqual(self.value["python_version"], "3.13")
        self.assertEqual(self.value["pyinstaller_version"], "6.22.2")
        wireshark = self.value["wireshark"]
        self.assertEqual(wireshark["version"], "4.6.8")
        self.assertEqual(set(wireshark), {"version", "msi", "source"})

    def test_downloads_are_exact_official_versioned_paths(self):
        expected = {
            "msi": "Wireshark-4.6.8-x64.msi",
            "source": "wireshark-4.6.8.tar.xz",
        }
        for name, filename in expected.items():
            component = self.value["wireshark"][name]
            self.assertEqual(component["filename"], filename)
            scheme, separator, remainder = component["url"].partition("://")
            self.assertEqual((scheme, separator), ("https", "://"))
            host, slash, path = remainder.partition("/")
            self.assertEqual(host, "www.wireshark.org")
            self.assertEqual(slash, "/")
            self.assertTrue(path.startswith("download/"))
            self.assertTrue(path.endswith(filename))
            self.assertNotIn("latest", path.casefold())

    def test_hashes_and_build_packages_are_pinned(self):
        for component_name in ("msi", "source"):
            digest = self.value["wireshark"][component_name]["sha256"]
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            self.assertNotEqual(digest, "0" * 64)

        requirements = [
            line.strip()
            for line in self.support_text("requirements-build.txt").splitlines()
            if line.strip()
        ]
        self.assertEqual(requirements, sorted(requirements, key=str.casefold))
        for line in requirements:
            self.assertRegex(line, r"^[A-Za-z0-9_.-]+==[0-9A-Za-z_.-]+$")
        self.assertIn(
            "pyinstaller==" + self.value["pyinstaller_version"],
            [line.casefold() for line in requirements],
        )

    def test_build_and_verification_scripts_accept_no_supply_chain_override(self):
        scripts = (
            "build_portable.ps1",
            "finalize_portable.ps1",
            "verify_protocol_inventory.ps1",
            "verify_event_timeline.ps1",
            "verify_transaction_sessions.ps1",
            "verify_device_sessions.ps1",
            "verify_device_journeys.ps1",
            "verify_capture_observability.ps1",
            "verify_eapol_handshakes.ps1",
            "verify_eapol_replay_relations.ps1",
            "verify_pcapng_interface_statistics.ps1",
        )
        for filename in scripts:
            parameter_block = self.support_text(filename).split(")", 1)[0]
            for forbidden in ("Url", "Uri", "Version", "Hash", "Installer"):
                self.assertNotIn("$" + forbidden, parameter_block)

        build_text = self.support_text("build_portable.ps1")
        self.assertIn("supply-chain.json", build_text)
        self.assertIn("Get-AuthenticodeSignature", build_text)
        self.assertIn("--windowed", build_text)
        self.assertIn("--onedir", build_text)

    def test_finalizer_requires_licenses_executables_and_privacy_boundaries(self):
        finalizer = self.support_text("finalize_portable.ps1")
        required = (
            "PYTHON-LICENSE.txt",
            "TCL-LICENSE.txt",
            "TK-LICENSE.txt",
            "PYINSTALLER-COPYING.txt",
            "vendor/wireshark/COPYING",
            "vendor/wireshark/tshark.exe",
            "WlanTroubleshooterKO.exe",
            "release-tag",
            "protocol_inventory_runtime",
            "event_timeline_runtime",
            "transaction_session_runtime",
            "device_session_runtime",
            "device_journey_runtime",
            "capture_observability_runtime",
            "eapol_handshake_runtime",
            "eapol_replay_relation_runtime",
            "pcapng_interface_statistics_runtime",
            "raw_replay_counter_serialization",
            "replay_counter_persistence",
            "absolute_timestamp_serialization",
            "pcapng_string_option_serialization",
            "interface_name_serialization",
            "raw_identifier_serialization",
            "alias_secret_persistence",
            "cross_run_alias_stability",
        )
        for value in required:
            self.assertIn(value, finalizer)

    def test_portable_workflows_run_all_real_analysis_and_privacy_gates(self):
        required = (
            "verify_protocol_inventory.ps1",
            "verify_event_timeline.ps1",
            "verify_transaction_sessions.ps1",
            "verify_device_sessions.ps1",
            "verify_device_journeys.ps1",
            "verify_capture_observability.ps1",
            "verify_eapol_handshakes.ps1",
            "verify_eapol_replay_relations.ps1",
            "verify_pcapng_interface_statistics.ps1",
        )
        for relative in (
            ".github/workflows/windows-portable.yml",
            ".github/workflows/preview-release.yml",
        ):
            workflow = self.text(relative)
            for value in required:
                self.assertIn(value, workflow)

    def test_replay_and_pcapng_verifiers_preserve_false_claim_boundaries(self):
        replay = self.support_text("verify_eapol_replay_relations.ps1")
        for value in (
            "raw_replay_counter_serialization",
            "replay_counter_persistence",
            "raw_replay_counters_serialized",
            "same_handshake_confirmed",
            "retransmission_confirmed",
            "root_cause_confirmed",
        ):
            self.assertIn(value, replay)

        statistics = self.support_text(
            "verify_pcapng_interface_statistics.ps1"
        )
        for value in (
            "pcapng_interface_statistics_runtime",
            "pcapng_string_option_serialization",
            "interface_name_serialization",
            "pcapng_interface_statistics",
            "supported_capture_format",
            "reported-drop-observed",
            "IFACE-1",
            "ifrecv",
            "ifdrop",
            "filteraccept",
            "osdrop",
            "usrdeliv",
            "capture_loss_excluded",
            "specific_packet_loss_confirmed",
            "root_cause_confirmed",
            "private-interface-name-phase4k",
            "private-statistics-comment-phase4k",
        ):
            self.assertIn(value, statistics)

    def test_packet_fixtures_are_generated_at_runtime_not_committed(self):
        fixtures = (
            ("generate_event_fixture.py", "build_pcap"),
            ("generate_wireless_event_fixture.py", "build_pcap"),
            ("generate_eap_fixture.py", "build_pcap"),
            ("generate_observability_fixture.py", "build_pcap"),
            ("generate_eapol_handshake_fixture.py", "build_pcap"),
            ("generate_eapol_replay_fixture.py", "build_pcap"),
            ("generate_pcapng_statistics_fixture.py", "build_pcapng"),
        )
        for filename, builder in fixtures:
            self.assertIn(builder, self.support_text(filename))

        pcapng = self.support_text("generate_pcapng_statistics_fixture.py")
        for value in (
            "PRIVATE_SECTION_COMMENT",
            "PRIVATE_HARDWARE",
            "PRIVATE_OS",
            "PRIVATE_APPLICATION",
            "PRIVATE_INTERFACE_NAME",
            "PRIVATE_INTERFACE_DESCRIPTION",
            "PRIVATE_PACKET_COMMENT",
            "PRIVATE_STATISTICS_COMMENT",
        ):
            self.assertIn(value, pcapng)
        self.assertFalse(any(self.root.rglob("*.pcap")))
        self.assertFalse(any(self.root.rglob("*.pcapng")))


if __name__ == "__main__":
    unittest.main()
