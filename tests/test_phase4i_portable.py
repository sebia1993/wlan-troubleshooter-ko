import unittest
from pathlib import Path


class Phase4IPortableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.support = cls.root / "tests" / "portable_build"

    def text(self, relative):
        return (self.root / relative).read_text(encoding="utf-8")

    def test_release_metadata_is_exact(self):
        project = self.text("pyproject.toml")
        for value in (
            'version = "0.11.0a1"',
            'phase = "4I"',
            'eapol-handshake-version = "1"',
            'release-tag = "v0.11.0-alpha.1"',
        ):
            self.assertIn(value, project)
        release = self.text(".github/workflows/preview-release.yml")
        self.assertIn('if ($Tag -ne "v0.11.0-alpha.1"', release)

    def test_workflows_require_eapol_handshake_integration_gate(self):
        for relative in (
            ".github/workflows/windows-portable.yml",
            ".github/workflows/preview-release.yml",
        ):
            with self.subTest(relative=relative):
                workflow = self.text(relative)
                self.assertIn("verify_eapol_handshakes.ps1", workflow)
                self.assertIn("verify_capture_observability.ps1", workflow)
                self.assertIn("verify_device_journeys.ps1", workflow)

    def test_finalizer_enables_handshake_runtime_without_weakening_privacy(self):
        finalizer = self.text("tests/portable_build/finalize_portable.ps1")
        for value in (
            'eapol_handshake_runtime = "enabled"',
            'capture_observability_runtime = "enabled"',
            'raw_identifier_serialization = "disabled"',
            'alias_secret_persistence = "disabled"',
            'cross_run_alias_stability = "disabled"',
        ):
            self.assertIn(value, finalizer)

    def test_handshake_verifier_has_no_download_or_version_parameters(self):
        verifier = self.text("tests/portable_build/verify_eapol_handshakes.ps1")
        parameter_block = verifier.split(")", 1)[0]
        for forbidden in ("Url", "Uri", "Version", "Hash", "Installer"):
            self.assertNotIn("$" + forbidden, parameter_block)

    def test_handshake_verifier_checks_sequence_repetition_and_false_claims(self):
        verifier = self.text("tests/portable_build/verify_eapol_handshakes.ps1")
        for value in (
            "generate_eapol_handshake_fixture.py",
            "eapol_handshake_runtime",
            "eapol_handshakes",
            "EAPOL-HS-1",
            "DEVICE-1",
            "AP-1",
            "message-repetition-observed",
            "observed_message_numbers",
            "first_observed_order",
            "repeated_message_numbers",
            "retry_flag_frames",
            "replay_counter_correlation_available",
            "raw_key_material_serialized",
            "raw_identifiers_serialized",
            "same_handshake_confirmed",
            "key_installation_confirmed",
            "cryptographic_success_confirmed",
            "root_cause_confirmed",
        ):
            self.assertIn(value, verifier)

    def test_empty_missing_message_sequence_is_explicitly_supported(self):
        verifier = self.text("tests/portable_build/verify_eapol_handshakes.ps1")
        self.assertIn("[AllowEmptyCollection()]", verifier)
        self.assertIn(
            "$Observation.missing_message_numbers -Expected @()",
            verifier,
        )

    def test_fixture_is_generated_at_runtime_and_uses_radiotap(self):
        fixture = self.text(
            "tests/portable_build/generate_eapol_handshake_fixture.py"
        )
        for value in (
            "build_pcap",
            "_radiotap_header",
            "_eapol_key",
            "_key_descriptor",
            "M1, M2, M3",
            "retry=True",
            "65535, 127",
        ):
            self.assertIn(value, fixture)
        self.assertFalse(any(self.root.rglob("*.pcap")))
        self.assertFalse(any(self.root.rglob("*.pcapng")))


if __name__ == "__main__":
    unittest.main()
