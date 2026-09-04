import unittest
from pathlib import Path


class Phase4GPortableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.support = cls.root / "tests" / "portable_build"

    def text(self, relative):
        return (self.root / relative).read_text(encoding="utf-8")

    def test_phase4g_release_metadata_is_exact(self):
        project = self.text("pyproject.toml")
        for value in (
            'version = "0.10.0a1"',
            'phase = "4G"',
            'capture-observability-version = "1"',
            'release-tag = "v0.10.0-alpha.1"',
        ):
            self.assertIn(value, project)
        release = self.text(".github/workflows/preview-release.yml")
        self.assertIn('if ($Tag -ne "v0.10.0-alpha.1"', release)

    def test_workflows_require_observability_integration_gate(self):
        for relative in (
            ".github/workflows/windows-portable.yml",
            ".github/workflows/preview-release.yml",
        ):
            with self.subTest(relative=relative):
                self.assertIn(
                    "verify_capture_observability.ps1",
                    self.text(relative),
                )

    def test_finalizer_enables_observability_without_weakening_privacy(self):
        finalizer = self.text("tests/portable_build/finalize_portable.ps1")
        for value in (
            'capture_observability_runtime = "enabled"',
            'raw_identifier_serialization = "disabled"',
            'alias_secret_persistence = "disabled"',
            'cross_run_alias_stability = "disabled"',
        ):
            self.assertIn(value, finalizer)

    def test_observability_gate_forbids_absence_as_failure(self):
        verifier = self.text("tests/portable_build/verify_capture_observability.ps1")
        for value in (
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
            "absence_is_failure",
        ):
            self.assertIn(value, verifier)


if __name__ == "__main__":
    unittest.main()
