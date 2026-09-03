import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from wlan_troubleshooter_ko.tshark.catalog import parse_field_catalog
from wlan_troubleshooter_ko.tshark.inventory import (
    prepare_field_catalog_invocation,
    prepare_protocol_inventory_invocation,
)
from wlan_troubleshooter_ko.tshark.policy import (
    TSharkPolicyError,
    assert_safe_field_catalog_argv,
    assert_safe_profile_argv,
)


PCAP_HEADER = bytes.fromhex("d4c3b2a1") + bytes(20)
CATALOG_LINES = [
    "P\tFrame\tframe\n",
    "F\tFrame Number\tframe.number\tFT_UINT32\tframe\tBASE_DEC\t0x0\t\n",
    "F\tInterface id\tframe.interface_id\tFT_UINT32\tframe\tBASE_DEC\t0x0\t\n",
    "F\tCapture Length\tframe.cap_len\tFT_UINT32\tframe\tBASE_DEC\t0x0\t\n",
    "F\tFrame Length\tframe.len\tFT_UINT32\tframe\tBASE_DEC\t0x0\t\n",
    "F\tProtocols in frame\tframe.protocols\tFT_STRING\tframe\t\t0x0\t\n",
]


def write_bundle(root: Path, executable_content=b"binary"):
    executable = root / "tshark.exe"
    copying = root / "COPYING"
    executable.write_bytes(executable_content)
    copying.write_text("license", encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "version": "1.2.3-internal",
        "approval_reference": "APPROVAL-TEST",
        "executable": "tshark.exe",
        "files": [
            {
                "path": "tshark.exe",
                "sha256": hashlib.sha256(executable_content).hexdigest(),
                "size_bytes": len(executable_content),
            },
            {
                "path": "COPYING",
                "sha256": hashlib.sha256(b"license").hexdigest(),
                "size_bytes": len(b"license"),
            },
        ],
    }
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


class Phase2BPreparationTests(unittest.TestCase):
    def profile_path(self):
        return (
            Path(__file__).resolve().parents[1]
            / "src"
            / "wlan_troubleshooter_ko"
            / "resources"
            / "tshark"
            / "field-profiles.v1.json"
        )

    def setup_paths(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        vendor = root / "vendor"
        vendor.mkdir()
        write_bundle(vendor)
        capture = root / "capture.pcap"
        capture.write_bytes(PCAP_HEADER)
        return root, vendor, capture

    @mock.patch("wlan_troubleshooter_ko.tshark.runner.subprocess.Popen")
    def test_catalog_preparation_does_not_start_process(self, popen_mock):
        root, vendor, _capture = self.setup_paths()
        prepared = prepare_field_catalog_invocation(vendor, root / "catalog-isolation")

        self.assertEqual(prepared.arguments[1:], ("-n", "-G", "fields"))
        self.assertNotIn("PATH", prepared.environment)
        assert_safe_field_catalog_argv(list(prepared.arguments))
        popen_mock.assert_not_called()

    @mock.patch("wlan_troubleshooter_ko.tshark.runner.subprocess.Popen")
    def test_protocol_profile_preparation_is_fixed_and_does_not_execute(self, popen_mock):
        root, vendor, capture = self.setup_paths()
        catalog = parse_field_catalog(CATALOG_LINES)
        prepared = prepare_protocol_inventory_invocation(
            vendor,
            capture,
            root / "inventory-isolation",
            self.profile_path(),
            catalog,
        )

        arguments = list(prepared.arguments)
        self.assertEqual(arguments.count("-n"), 1)
        self.assertEqual(arguments.count("-2"), 1)
        self.assertEqual(arguments.count("-r"), 1)
        self.assertEqual(arguments.count("-c"), 1)
        self.assertIn("header=y", arguments)
        self.assertIn("separator=/t", arguments)
        self.assertIn("occurrence=f", arguments)
        self.assertIn("quote=d", arguments)
        self.assertIn("escape=y", arguments)
        self.assertNotIn("-i", arguments)
        self.assertNotIn("ip.src", arguments)
        self.assertNotIn("eth.src", arguments)
        assert_safe_profile_argv(arguments)
        popen_mock.assert_not_called()

    def test_profile_argv_rejects_live_capture_and_unknown_field(self):
        root, vendor, capture = self.setup_paths()
        prepared = prepare_protocol_inventory_invocation(
            vendor,
            capture,
            root / "inventory-isolation",
            self.profile_path(),
            parse_field_catalog(CATALOG_LINES),
        )
        live = list(prepared.arguments) + ["-i", "1"]
        with self.assertRaises(TSharkPolicyError):
            assert_safe_profile_argv(live)
        unknown = list(prepared.arguments)
        unknown[-1] = "ip.src"
        with self.assertRaises(TSharkPolicyError):
            assert_safe_profile_argv(unknown)


if __name__ == "__main__":
    unittest.main()
