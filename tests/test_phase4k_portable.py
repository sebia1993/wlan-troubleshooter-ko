import unittest
from pathlib import Path


class Phase4KPortableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.support = cls.root / "tests" / "portable_build"

    def text(self, relative):
        return (self.root / relative).read_text(encoding="utf-8")

    def test_release_metadata_is_exact(self):
        project = self.text("pyproject.toml")
        for value in (
            'version = "0.13.0a1"',
            'phase = "4K"',
            'pcapng-interface-statistics-version = "1"',
            'release-tag = "v0.13.0-alpha.1"',
        ):
            self.assertIn(value, project)
        release = self.text(".github/workflows/preview-release.yml")
        self.assertIn('if ($Tag -ne "v0.13.0-alpha.1"', release)

    def test_workflows_require_pcapng_statistics_gate(self):
        for relative in (
            ".github/workflows/windows-portable.yml",
            ".github/workflows/preview-release.yml",
        ):
            with self.subTest(relative=relative):
                text = self.text(relative)
                self.assertIn(
                    "verify_pcapng_interface_statistics.ps1",
                    text,
                )
                self.assertIn("verify_eapol_replay_relations.ps1", text)

    def test_finalizer_enables_statistics_and_disables_sensitive_metadata(self):
        text = self.text("tests/portable_build/finalize_portable.ps1")
        for value in (
            'pcapng_interface_statistics_runtime = "enabled"',
            'absolute_timestamp_serialization = "disabled"',
            'pcapng_string_option_serialization = "disabled"',
            'interface_name_serialization = "disabled"',
            'raw_identifier_serialization = "disabled"',
            'eapol_replay_relation_runtime = "enabled"',
        ):
            self.assertIn(value, text)

    def test_verifier_checks_report_counters_and_conservative_flags(self):
        text = self.text(
            "tests/portable_build/verify_pcapng_interface_statistics.ps1"
        )
        for value in (
            "generate_pcapng_statistics_fixture.py",
            "pcapng_interface_statistics",
            "supported_capture_format",
            "IFACE-1",
            "reported-drop-observed",
            "ifrecv",
            "ifdrop",
            "filteraccept",
            "osdrop",
            "usrdeliv",
            "absolute_timestamps_serialized",
            "capture_loss_excluded",
            "specific_packet_loss_confirmed",
            "root_cause_confirmed",
            "Corp-WLAN-Private-Adapter",
            "Internal monitor path",
        ):
            self.assertIn(value, text)

    def test_fixture_is_generated_at_runtime_not_committed(self):
        fixture = self.text(
            "tests/portable_build/generate_pcapng_statistics_fixture.py"
        )
        for value in (
            "PRIVATE_INTERFACE_NAME",
            "PRIVATE_INTERFACE_DESCRIPTION",
            "START_TIME",
            "END_TIME",
            "BLOCK_TIME",
            "_interface_statistics",
            "build_pcapng",
        ):
            self.assertIn(value, fixture)
        self.assertFalse(any(self.root.rglob("*.pcap")))
        self.assertFalse(any(self.root.rglob("*.pcapng")))


if __name__ == "__main__":
    unittest.main()
