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
        wireshark = self.value["wireshark"]
        expected = {
            "msi": "Wireshark-4.6.8-x64.msi",
            "source": "wireshark-4.6.8.tar.xz",
        }
        for name, filename in expected.items():
            component = wireshark[name]
            self.assertEqual(component["filename"], filename)
            scheme, separator, remainder = component["url"].partition("://")
            self.assertEqual((scheme, separator), ("https", "://"))
            host, slash, path = remainder.partition("/")
            self.assertEqual(host, "www.wireshark.org")
            self.assertEqual(slash, "/")
            self.assertTrue(path.startswith("download/"))
            self.assertTrue(path.endswith(filename))
            self.assertNotIn("latest", path.casefold())

    def test_hashes_are_pinned_lowercase_sha256(self):
        for component_name in ("msi", "source"):
            digest = self.value["wireshark"][component_name]["sha256"]
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            self.assertNotEqual(digest, "0" * 64)

    def test_build_requirements_are_exact_and_match_pyinstaller(self):
        lines = [
            line.strip()
            for line in (
                self.support / "requirements-build.txt"
            ).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertTrue(lines)
        self.assertEqual(lines, sorted(lines, key=str.casefold))
        for line in lines:
            self.assertRegex(line, r"^[A-Za-z0-9_.-]+==[0-9A-Za-z_.-]+$")
        self.assertIn(
            "pyinstaller==" + self.value["pyinstaller_version"],
            [line.casefold() for line in lines],
        )

    def test_build_scripts_accept_no_url_or_version_parameters(self):
        for filename in (
            "build_portable.ps1",
            "finalize_portable.ps1",
            "verify_protocol_inventory.ps1",
            "verify_event_timeline.ps1",
            "verify_transaction_sessions.ps1",
            "verify_device_sessions.ps1",
            "verify_device_journeys.ps1",
            "verify_capture_observability.ps1",
        ):
            text = (self.support / filename).read_text(encoding="utf-8")
            parameter_block = text.split(")", 1)[0]
            for forbidden in ("Url", "Uri", "Version", "Hash", "Installer"):
                self.assertNotIn("$" + forbidden, parameter_block)
        build_text = (self.support / "build_portable.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("supply-chain.json", build_text)
        self.assertIn("Get-AuthenticodeSignature", build_text)
        self.assertIn("--windowed", build_text)
        self.assertIn("--onedir", build_text)

    def test_finalize_requires_licenses_exact_executables_and_privacy_metadata(self):
        text = (self.support / "finalize_portable.ps1").read_text(
            encoding="utf-8"
        )
        for value in (
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
            "raw_identifier_serialization",
            "alias_secret_persistence",
            "cross_run_alias_stability",
        ):
            self.assertIn(value, text)

    def test_portable_workflows_run_all_real_analysis_and_privacy_gates(self):
        required = (
            "verify_protocol_inventory.ps1",
            "verify_event_timeline.ps1",
            "verify_transaction_sessions.ps1",
            "verify_device_sessions.ps1",
            "verify_device_journeys.ps1",
            "verify_capture_observability.ps1",
        )
        for relative in (
            ".github/workflows/windows-portable.yml",
            ".github/workflows/preview-release.yml",
        ):
            text = (self.root / relative).read_text(encoding="utf-8")
            for value in required:
                self.assertIn(value, text)

        finding_verifier = (
            self.support / "verify_protocol_inventory.ps1"
        ).read_text(encoding="utf-8")
        for value in (
            "--analyze-capture",
            "frames_observed",
            '"arp"',
            '"dns"',
            '"tcp"',
            '"DNS-ERROR-RESPONSE"',
            '"TCP-RST"',
            "event_correlation",
            "transaction_sessions",
            "DNS-1-A1",
            "TCP-1-A1",
            "root_cause_confirmed",
            "device_session_confirmed",
        ):
            self.assertIn(value, finding_verifier)

        timeline_verifier = (
            self.support / "verify_event_timeline.ps1"
        ).read_text(encoding="utf-8")
        for value in (
            "generate_event_fixture.py",
            "generate_wireless_event_fixture.py",
            "generate_eap_fixture.py",
            "event_timeline_runtime",
            "eap_success",
            "radius_access_accept",
            "dhcp_ack",
            "dns_response_success",
            "tcp_syn_ack",
            "wlan_auth_response_success",
            "wlan_assoc_response_success",
            "wlan_deauthentication",
            "PPP EAP",
        ):
            self.assertIn(value, timeline_verifier)

        transaction_verifier = (
            self.support / "verify_transaction_sessions.ps1"
        ).read_text(encoding="utf-8")
        for value in (
            "transaction_session_runtime",
            "radius_access_request",
            "radius_access_accept",
            "dhcp_discover",
            "dhcp_ack",
            "dns_query",
            "dns_response_success",
            "tcp_syn",
            "tcp_syn_ack",
            "tcp_reset",
            "eap_request",
            "eap_response",
            "eap_success",
            "root_cause_confirmed",
            "device_session_confirmed",
        ):
            self.assertIn(value, transaction_verifier)

        device_verifier = (
            self.support / "verify_device_sessions.ps1"
        ).read_text(encoding="utf-8")
        for value in (
            "device_session_runtime",
            "raw_identifier_serialization",
            "alias_secret_persistence",
            "cross_run_alias_stability",
            "DEVICE-1",
            "AP-1",
            "device_identity_confirmed",
            "cross_protocol_session_confirmed",
            "attempt_links",
            "frames_ambiguous",
        ):
            self.assertIn(value, device_verifier)

        journey_verifier = (
            self.support / "verify_device_journeys.ps1"
        ).read_text(encoding="utf-8")
        for value in (
            "device_journeys",
            "DEVICE-1",
            '"dhcp"',
            '"dns"',
            '"tcp"',
            "first_failure_stage",
            "last_positive_stage",
            "cross_protocol_session_confirmed",
            "root_cause_confirmed",
        ):
            self.assertIn(value, journey_verifier)

        observability_verifier = (
            self.support / "verify_capture_observability.ps1"
        ).read_text(encoding="utf-8")
        for value in (
            "generate_observability_fixture.py",
            "capture_observability_runtime",
            "capture_observability",
            "DNS-1-A1",
            "DNS-2-A1",
            "response-not-observed",
            "capture-boundary-risk",
            "capture-end-boundary-risk",
            "capture_start_proven",
            "capture_end_proven",
            "capture_loss_excluded",
            "directionality_proven",
            "absence_can_confirm_failure",
        ):
            self.assertIn(value, observability_verifier)

    def test_event_fixtures_are_generated_at_runtime_not_committed(self):
        ethernet = (self.support / "generate_event_fixture.py").read_text(
            encoding="utf-8"
        )
        wireless = (
            self.support / "generate_wireless_event_fixture.py"
        ).read_text(encoding="utf-8")
        eap = (self.support / "generate_eap_fixture.py").read_text(
            encoding="utf-8"
        )
        observability = (
            self.support / "generate_observability_fixture.py"
        ).read_text(encoding="utf-8")
        for value in (
            "build_pcap",
            "_eapol",
            "_radius",
            "_dhcp",
            "_dns_response",
            "_tcp_frame",
        ):
            self.assertIn(value, ethernet)
        for value in (
            "build_pcap",
            "_authentication",
            "_association_response",
            "_eapol_data",
            "_radiotap_header",
        ):
            self.assertIn(value, wireless)
        for value in (
            "build_pcap",
            "PPP_EAP_PROTOCOL",
            "_eap_packet",
            "_ppp_eap",
        ):
            self.assertIn(value, eap)
        for value in (
            "build_pcap",
            "_dns_query",
            "observability",
        ):
            self.assertIn(value, observability)
        self.assertFalse(any(self.root.rglob("*.pcap")))
        self.assertFalse(any(self.root.rglob("*.pcapng")))


if __name__ == "__main__":
    unittest.main()
