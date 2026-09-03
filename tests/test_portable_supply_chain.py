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

    def test_hashes_are_discovery_marker_or_lowercase_sha256(self):
        for component_name in ("msi", "source"):
            digest = self.value["wireshark"][component_name]["sha256"]
            self.assertTrue(digest == "DISCOVER" or re.fullmatch(r"[0-9a-f]{64}", digest))

    def test_build_script_accepts_no_url_or_version_parameters(self):
        text = (self.support / "build_portable.ps1").read_text(encoding="utf-8")
        parameter_block = text.split(")", 1)[0]
        for forbidden in ("Url", "Uri", "Version", "Hash", "Installer"):
            self.assertNotIn("$" + forbidden, parameter_block)
        self.assertIn("supply-chain.json", text)
        self.assertIn("Get-AuthenticodeSignature", text)
        self.assertIn("--windowed", text)
        self.assertIn("--onedir", text)


if __name__ == "__main__":
    unittest.main()
