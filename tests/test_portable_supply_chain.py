import json
import re
import unittest
from pathlib import Path


class PortableSupplyChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.support = cls.root / "tests" / "portable_build"
        cls.value = json.loads((cls.support / "supply-chain.json").read_text(encoding="utf-8"))

    def test_supply_chain_schema_and_versions_are_exact(self):
        self.assertEqual(set(self.value), {"schema_version", "python_version", "pyinstaller_version", "wireshark"})
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
            for line in (self.support / "requirements-build.txt").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertTrue(lines)
        self.assertEqual(lines, sorted(lines, key=str.casefold))
        for line in lines:
            self.assertRegex(line, r"^[A-Za-z0-9_.-]+==[0-9A-Za-z_.-]+$")
        self.assertIn("pyinstaller==" + self.value["pyinstaller_version"], [line.casefold() for line in lines])

    def test_build_scripts_accept_no_url_or_version_parameters(self):
        for filename in (
            "build_portable.ps1",
            "finalize_portable.ps1",
            "verify_protocol_inventory.ps1",
            "verify_event_timeline.ps1",
        ):
            text = (self.support / filename).read_text(encoding="utf-8")
            parameter_block = text.split(")", 1)[0]
            for forbidden in ("Url", "Uri", "Version", "Hash", "Installer"):
                self.assertNotIn("$" + forbidden, parameter_block)
        build_text = (self.support / "build_portable.ps1").read_text(encoding="utf-8")
        self.assertIn("supply-chain.json", build_text)
        self.assertIn("Get-AuthenticodeSignature", build_text)
        self.assertIn("--windowed", build_text)
        self.assertIn("--onedir", build_text)

    def test_finalize_requires_licenses_exact_executables_and_release_metadata(self):
        text = (self.support / "finalize_portable.ps1").read_text(encoding="utf-8")
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
        ):
            self.assertIn(value, text)

    def test_portable_workflows_run_real_finding_and_timeline_gates(self):
        for relative in (
            ".github/workflows/windows-portable.yml",
            ".github/workflows/preview-release.yml",
        ):
            text = (self.root / relative).read_text(encoding="utf-8")
            self.assertIn("verify_protocol_inventory.ps1", text)
            self.assertIn("verify_event_timeline.ps1", text)

        finding_verifier = (self.support / "verify_protocol_inventory.ps1").read_text(encoding="utf-8")
        for value in (
            "--analyze-capture",
            "frames_observed",
            '"arp"',
            '"dns"',
            '"tcp"',
            '"DNS-ERROR-RESPONSE"',
            '"TCP-RST"',
            "event_correlation",
            "evidence_frames",
            "display_filter",
        ):
            self.assertIn(value, finding_verifier)

        timeline_verifier = (self.support / "verify_event_timeline.ps1").read_text(encoding="utf-8")
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

    def test_event_fixtures_are_generated_at_runtime_not_committed(self):
        ethernet = (self.support / "generate_event_fixture.py").read_text(encoding="utf-8")
        wireless = (self.support / "generate_wireless_event_fixture.py").read_text(encoding="utf-8")
        eap = (self.support / "generate_eap_fixture.py").read_text(encoding="utf-8")
        for value in ("build_pcap", "_eapol", "_radius", "_dhcp", "_dns_response", "_tcp_frame"):
            self.assertIn(value, ethernet)
        for value in ("build_pcap", "_authentication", "_association_response", "_eapol_data", "_radiotap_header"):
            self.assertIn(value, wireless)
        for value in ("build_pcap", "PPP_EAP_PROTOCOL", "_eap_packet", "_ppp_eap"):
            self.assertIn(value, eap)
        self.assertFalse(any(self.root.rglob("*.pcap")))
        self.assertFalse(any(self.root.rglob("*.pcapng")))


if __name__ == "__main__":
    unittest.main()
