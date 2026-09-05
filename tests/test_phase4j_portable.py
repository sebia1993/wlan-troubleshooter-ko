import importlib.util
import unittest
from pathlib import Path


class Phase4JPortableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.support = cls.root / "tests" / "portable_build"

    def text(self, relative):
        return (self.root / relative).read_text(encoding="utf-8")

    def test_phase4j_schema_and_profile_remain_available(self):
        project = self.text("pyproject.toml")
        self.assertIn('field-profile-version = "0.6.0"', project)
        self.assertIn('eapol-handshake-version = "1"', project)
        self.assertIn('eapol-replay-relation-version = "1"', project)

    def test_workflows_preserve_replay_relation_gate(self):
        for relative in (
            ".github/workflows/windows-portable.yml",
            ".github/workflows/preview-release.yml",
        ):
            with self.subTest(relative=relative):
                text = self.text(relative)
                self.assertIn("verify_eapol_handshakes.ps1", text)
                self.assertIn("verify_eapol_replay_relations.ps1", text)

    def test_finalizer_preserves_relation_runtime_and_raw_value_protection(self):
        text = self.text("tests/portable_build/finalize_portable.ps1")
        for value in (
            'eapol_replay_relation_runtime = "enabled"',
            'raw_replay_counter_serialization = "disabled"',
            'replay_counter_persistence = "disabled"',
            'raw_identifier_serialization = "disabled"',
        ):
            self.assertIn(value, text)

    def test_verifier_checks_relationships_and_false_claims(self):
        text = self.text(
            "tests/portable_build/verify_eapol_replay_relations.ps1"
        )
        for value in (
            "generate_eapol_replay_fixture.py",
            "expected-relations-observed",
            "equal-observed",
            "increased-observed",
            "same-counter-observed",
            "raw_replay_counters_serialized",
            "replay_counter_values_persisted",
            "same_handshake_confirmed",
            "retransmission_confirmed",
            "key_installation_confirmed",
            "cryptographic_success_confirmed",
            "root_cause_confirmed",
            "18446744073709551000",
            "18446744073709551001",
        ):
            self.assertIn(value, text)

    def test_fixture_uses_distinctive_uint64_values_without_committed_pcap(self):
        path = self.support / "generate_eapol_replay_fixture.py"
        specification = importlib.util.spec_from_file_location(
            "phase4j_fixture_test",
            path,
        )
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)

        self.assertEqual(module.LATER_COUNTER, module.FIRST_COUNTER + 1)
        self.assertGreater(module.FIRST_COUNTER, 2**63)
        first = module.build_pcap()
        second = module.build_pcap()
        self.assertEqual(first, second)
        self.assertGreater(len(first), 500)
        self.assertFalse(any(self.root.rglob("*.pcap")))
        self.assertFalse(any(self.root.rglob("*.pcapng")))


if __name__ == "__main__":
    unittest.main()
