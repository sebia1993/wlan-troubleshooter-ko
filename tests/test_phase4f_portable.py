import unittest
from pathlib import Path


class Phase4FPortableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.support = cls.root / "tests" / "portable_build"

    def text(self, relative):
        return (self.root / relative).read_text(encoding="utf-8")

    def test_workflows_preserve_device_journey_integration_gate(self):
        for relative in (
            ".github/workflows/windows-portable.yml",
            ".github/workflows/preview-release.yml",
        ):
            with self.subTest(relative=relative):
                workflow = self.text(relative)
                self.assertIn("verify_device_sessions.ps1", workflow)
                self.assertIn("verify_device_journeys.ps1", workflow)

    def test_finalizer_preserves_journey_runtime_and_privacy_flags(self):
        finalizer = self.text("tests/portable_build/finalize_portable.ps1")
        for value in (
            'device_session_runtime = "enabled"',
            'device_journey_runtime = "enabled"',
            'raw_identifier_serialization = "disabled"',
            'alias_secret_persistence = "disabled"',
            'cross_run_alias_stability = "disabled"',
        ):
            self.assertIn(value, finalizer)

    def test_journey_verifier_checks_real_ethernet_scope_and_separate_radius_nad(self):
        verifier = self.text("tests/portable_build/verify_device_journeys.ps1")
        for value in (
            "generate_device_journey_fixture.py",
            "device_journeys",
            "DEVICE-1",
            '"mixed"',
            '"dhcp"',
            '"dns"',
            '"tcp"',
            "first_failure_stage",
            "last_positive_stage",
            "raw_identifiers_serialized",
            "aliases_stable_across_runs",
            "device_identity_confirmed",
            "cross_protocol_session_confirmed",
            "root_cause_confirmed",
            "display_filter",
        ):
            self.assertIn(value, verifier)
        self.assertNotIn(
            'Get-Stage -Journey $Journey -Protocol "eap"',
            verifier,
        )
        self.assertNotIn(
            'Get-Stage -Journey $Journey -Protocol "radius"',
            verifier,
        )

    def test_device_journey_fixture_changes_only_radius_l2_headers(self):
        fixture = self.text(
            "tests/portable_build/generate_device_journey_fixture.py"
        )
        for value in (
            "generate_event_fixture.py",
            "NAD_MAC",
            "timestamp == 6",
            "timestamp == 7",
            "build_pcap",
        ):
            self.assertIn(value, fixture)

    def test_device_journey_schema_version_remains_available(self):
        project = self.text("pyproject.toml")
        self.assertIn('device-journey-version = "1"', project)

    def test_no_capture_fixture_is_committed(self):
        self.assertFalse(any(self.root.rglob("*.pcap")))
        self.assertFalse(any(self.root.rglob("*.pcapng")))


if __name__ == "__main__":
    unittest.main()
