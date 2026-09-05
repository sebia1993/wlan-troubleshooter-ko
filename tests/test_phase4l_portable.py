import unittest
from pathlib import Path


class Phase4LPortableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.support = cls.root / "tests" / "portable_build"

    def text(self, relative):
        return (self.root / relative).read_text(encoding="utf-8")

    def test_release_metadata_is_exact(self):
        project = self.text("pyproject.toml")
        for value in (
            'version = "0.14.0a1"',
            'phase = "4L"',
            'field-profile-version = "0.6.0"',
            'capture-time-boundary-version = "1"',
            'release-tag = "v0.14.0-alpha.1"',
        ):
            self.assertIn(value, project)
        release = self.text(".github/workflows/preview-release.yml")
        self.assertIn('if ($Tag -ne "v0.14.0-alpha.1"', release)

    def test_workflows_require_capture_time_gate(self):
        for relative in (
            ".github/workflows/windows-portable.yml",
            ".github/workflows/preview-release.yml",
        ):
            with self.subTest(relative=relative):
                workflow = self.text(relative)
                self.assertIn(
                    "verify_capture_time_boundaries.ps1",
                    workflow,
                )
                self.assertIn(
                    "verify_pcapng_interface_statistics.ps1",
                    workflow,
                )
                self.assertIn(
                    "verify_eapol_replay_relations.ps1",
                    workflow,
                )

    def test_finalizer_declares_time_runtime_and_conservative_boundary(self):
        finalizer = self.text("tests/portable_build/finalize_portable.ps1")
        for value in (
            'capture_time_boundary_runtime = "enabled"',
            'absolute_timestamp_serialization = "disabled"',
            'response_absence_confirmation = "disabled"',
            'raw_identifier_serialization = "disabled"',
        ):
            self.assertIn(value, finalizer)

    def test_verifier_checks_relative_offsets_and_false_claims(self):
        verifier = self.text(
            "tests/portable_build/verify_capture_time_boundaries.ps1"
        )
        for value in (
            "generate_capture_time_fixture.py",
            "capture_time_boundary_runtime",
            "capture_time_boundaries",
            "capture-time-boundaries",
            "observed_span_ms",
            "DNS-1-A1",
            "DNS-2-A1",
            "near-analysis-start",
            "at-analysis-end",
            "start_distance_ms",
            "end_observation_window_ms",
            "absolute_timestamps_serialized",
            "capture_start_proven",
            "capture_end_proven",
            "incident_window_fully_covered",
            "response_wait_sufficiency_assessed",
            "response_absence_confirmed",
            "capture_loss_excluded",
            "root_cause_confirmed",
            "private-time-interface-phase4l",
            "1700005000",
        ):
            self.assertIn(value, verifier)

    def test_fixture_is_runtime_generated_and_no_capture_is_committed(self):
        fixture = self.text(
            "tests/portable_build/generate_capture_time_fixture.py"
        )
        for value in (
            "BASE_TIMESTAMP_TICKS",
            "PRIVATE_SECTION_COMMENT",
            "PRIVATE_HARDWARE",
            "PRIVATE_OPERATING_SYSTEM",
            "PRIVATE_APPLICATION",
            "PRIVATE_INTERFACE_NAME",
            "PRIVATE_INTERFACE_DESCRIPTION",
            "PRIVATE_PACKET_COMMENT",
            "generate_observability_fixture.py",
            "build_pcapng",
        ):
            self.assertIn(value, fixture)
        self.assertFalse(any(self.root.rglob("*.pcap")))
        self.assertFalse(any(self.root.rglob("*.pcapng")))


if __name__ == "__main__":
    unittest.main()
