import json
import tempfile
import unittest
from pathlib import Path

from wlan_troubleshooter_ko.core.config import (
    ConfigurationError,
    load_example_profile,
    load_messages,
    load_ruleset,
)


BASE_RULESET = {
    "schema_version": 1,
    "ruleset_version": "test",
    "classifications": ["확정", "유력", "참고", "판단 불가"],
    "rules": [],
}


class ConfigurationTests(unittest.TestCase):
    def _write_json(self, directory, name, value):
        path = Path(directory) / name
        path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
        return path

    def test_empty_phase_one_ruleset_is_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_json(directory, "rules.json", BASE_RULESET)
            self.assertEqual(load_ruleset(path)["rules"], [])

    def test_duplicate_and_conflicting_rules_fail_closed(self):
        rule = {
            "id": "TEST-001",
            "classification": "유력",
            "conditions": {"offer": 0},
            "exclusions": {},
        }
        with tempfile.TemporaryDirectory() as directory:
            duplicate = dict(BASE_RULESET, rules=[rule, dict(rule)])
            with self.assertRaises(ConfigurationError):
                load_ruleset(self._write_json(directory, "duplicate.json", duplicate))

            conflicting_rule = dict(rule, exclusions={"offer": 0})
            conflict = dict(BASE_RULESET, rules=[conflicting_rule])
            with self.assertRaises(ConfigurationError):
                load_ruleset(self._write_json(directory, "conflict.json", conflict))

    def test_non_korean_message_catalog_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_json(
                directory,
                "messages.json",
                {
                    "schema_version": 1,
                    "catalog_version": "test",
                    "locale": "en-US",
                    "messages": {},
                },
            )
            with self.assertRaises(ConfigurationError):
                load_messages(path)

    def test_only_empty_synthetic_example_profile_is_allowed(self):
        base = {
            "schema_version": 1,
            "profile_version": "test",
            "profile_id": "SYNTHETIC-TEST",
            "display_name": "합성 테스트",
            "synthetic": True,
            "radius_servers": [],
            "dhcp_servers": [],
            "dns_servers": [],
            "vlans": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_json(directory, "profile.json", base)
            self.assertTrue(load_example_profile(path)["synthetic"])
            unsafe = dict(base, dns_servers=["internal-value"])
            with self.assertRaises(ConfigurationError):
                load_example_profile(self._write_json(directory, "unsafe.json", unsafe))

    def test_duplicate_unknown_and_non_finite_json_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate = root / "duplicate.json"
            duplicate.write_text(
                '{"schema_version":1,"catalog_version":"x","locale":"ko-KR",'
                '"messages":{"same":"a","same":"b"}}',
                encoding="utf-8",
            )
            with self.assertRaises(ConfigurationError):
                load_messages(duplicate)

            overflow = root / "overflow.json"
            overflow.write_text(
                '{"schema_version":1,"ruleset_version":"x",'
                '"classifications":["확정","유력","참고","판단 불가"],'
                '"rules":[],"unexpected":1e10000}',
                encoding="utf-8",
            )
            with self.assertRaises(ConfigurationError):
                load_ruleset(overflow)

            boolean_schema = dict(BASE_RULESET, schema_version=True)
            with self.assertRaises(ConfigurationError):
                load_ruleset(self._write_json(directory, "boolean.json", boolean_schema))

            surrogate = root / "surrogate.json"
            surrogate.write_text(
                '{"schema_version":1,"catalog_version":"x","locale":"ko-KR",'
                '"messages":{"bad":"\\ud800"}}',
                encoding="utf-8",
            )
            with self.assertRaises(ConfigurationError):
                load_messages(surrogate)


if __name__ == "__main__":
    unittest.main()
