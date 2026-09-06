import re
import unittest
from pathlib import Path

import wlan_troubleshooter_ko


class ReleaseMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.project = (cls.root / "pyproject.toml").read_text(encoding="utf-8")

    def value(self, key):
        match = re.search(
            r'^' + re.escape(key) + r'\s*=\s*"([^"]+)"',
            self.project,
            re.MULTILINE,
        )
        self.assertIsNotNone(match)
        return match.group(1)

    def test_project_module_and_release_versions_match(self):
        self.assertEqual(self.value("version"), wlan_troubleshooter_ko.__version__)
        self.assertEqual(self.value("version"), "0.14.0a1")
        self.assertEqual(self.value("release-tag"), "v0.14.0-alpha.1")
        self.assertEqual(self.value("phase"), "4L")
        self.assertEqual(self.value("ruleset-version"), "0.2.0")
        self.assertEqual(self.value("field-profile-version"), "0.6.0")
        self.assertEqual(self.value("transaction-session-version"), "1")
        self.assertEqual(self.value("device-session-version"), "1")
        self.assertEqual(self.value("device-journey-version"), "1")
        self.assertEqual(self.value("capture-observability-version"), "1")
        self.assertEqual(self.value("eapol-handshake-version"), "1")
        self.assertEqual(self.value("eapol-replay-relation-version"), "1")
        self.assertEqual(
            self.value("pcapng-interface-statistics-version"),
            "1",
        )
        self.assertEqual(self.value("capture-time-boundary-version"), "1")

    def test_portable_component_versions_are_pinned(self):
        self.assertEqual(self.value("portable-python"), "3.13")
        self.assertEqual(self.value("portable-pyinstaller"), "6.22.2")
        self.assertEqual(self.value("portable-wireshark"), "4.6.8")


if __name__ == "__main__":
    unittest.main()
