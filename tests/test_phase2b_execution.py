import hashlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from wlan_troubleshooter_ko.tshark.catalog import parse_field_catalog
from wlan_troubleshooter_ko.tshark.manifest import verify_bundle
from wlan_troubleshooter_ko.tshark.policy import (
    TSharkPolicyError,
    assert_safe_field_catalog_argv,
    assert_safe_profile_argv,
    build_field_catalog_argv,
    build_profile_argv,
)
from wlan_troubleshooter_ko.tshark.profiles import load_field_profiles, resolve_profile
from wlan_troubleshooter_ko.tshark.runner import (
    TSharkExecutionError,
    run_field_catalog,
    run_protocol_inventory,
)


PCAP_HEADER = bytes.fromhex("d4c3b2a1") + bytes(20)
CATALOG_TEXT = """P\tFrame\tframe
F\tFrame Number\tframe.number\tFT_UINT32\tframe\tBASE_DEC\t0x0\t
F\tInterface id\tframe.interface_id\tFT_UINT32\tframe\tBASE_DEC\t0x0\t
F\tCapture Length\tframe.cap_len\tFT_UINT32\tframe\tBASE_DEC\t0x0\t
F\tFrame Length\tframe.len\tFT_UINT32\tframe\tBASE_DEC\t0x0\t
F\tProtocols in frame\tframe.protocols\tFT_STRING\tframe\t\t0x0\t
"""
FIELDS_TEXT = """"frame.number"\t"frame.interface_id"\t"frame.cap_len"\t"frame.len"\t"frame.protocols"
"1"\t"0"\t"100"\t"100"\t"eth:ip:udp:dns"
"""


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


class FakeProcess:
    def __init__(self, stdout=b"", stderr=b"", return_code=0):
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self._return_code = return_code
        self.terminated = False
        self.killed = False

    def poll(self):
        return self._return_code

    def wait(self, timeout=None):
        return self._return_code

    def terminate(self):
        self.terminated = True
        self._return_code = -1

    def kill(self):
        self.killed = True
        self._return_code = -9


class Phase2BExecutionTests(unittest.TestCase):
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

    def resolved_profile(self):
        registry = load_field_profiles(self.profile_path())
        return resolve_profile(
            registry,
            parse_field_catalog(CATALOG_TEXT.splitlines(keepends=True)),
            "protocol-inventory",
        )

    def test_fixed_catalog_and_profile_argv(self):
        _root, vendor, capture = self.setup_paths()
        bundle = verify_bundle(vendor)
        catalog_arguments = build_field_catalog_argv(bundle)
        self.assertEqual(catalog_arguments[1:], ["-n", "-G", "fields"])
        assert_safe_field_catalog_argv(catalog_arguments)

        profile_arguments = build_profile_argv(bundle, capture, self.resolved_profile())
        self.assertEqual(profile_arguments.count("-n"), 1)
        self.assertEqual(profile_arguments.count("-2"), 1)
        self.assertEqual(profile_arguments.count("-r"), 1)
        self.assertEqual(profile_arguments.count("-c"), 1)
        self.assertIn("header=y", profile_arguments)
        self.assertIn("separator=/t", profile_arguments)
        self.assertIn("occurrence=f", profile_arguments)
        self.assertIn("quote=d", profile_arguments)
        self.assertIn("escape=y", profile_arguments)
        self.assertNotIn("-i", profile_arguments)
        assert_safe_profile_argv(profile_arguments)

    def test_profile_argv_rejects_live_capture_and_unknown_field(self):
        _root, vendor, capture = self.setup_paths()
        arguments = build_profile_argv(
            verify_bundle(vendor),
            capture,
            self.resolved_profile(),
        )
        live = list(arguments) + ["-i", "1"]
        with self.assertRaises(TSharkPolicyError):
            assert_safe_profile_argv(live)
        unknown = list(arguments)
        unknown[-1] = "ip.src"
        with self.assertRaises(TSharkPolicyError):
            assert_safe_profile_argv(unknown)

    @mock.patch("wlan_troubleshooter_ko.tshark.runner.subprocess.Popen")
    def test_field_catalog_execution_uses_bounded_isolated_pipe(self, popen):
        root, vendor, _capture = self.setup_paths()
        popen.return_value = FakeProcess(CATALOG_TEXT.encode("utf-8"))

        result = run_field_catalog(vendor, root / "catalog-isolation")

        self.assertTrue(result.catalog.has_field("frame.protocols"))
        call = popen.call_args
        self.assertFalse(call.kwargs["shell"])
        self.assertIs(call.kwargs["stdout"], subprocess.PIPE)
        self.assertIs(call.kwargs["stderr"], subprocess.PIPE)
        self.assertNotIn("PATH", call.kwargs["env"])

    @mock.patch("wlan_troubleshooter_ko.tshark.runner.subprocess.Popen")
    def test_protocol_inventory_execution_uses_catalog_then_fixed_fields(self, popen):
        root, vendor, capture = self.setup_paths()
        popen.side_effect = [
            FakeProcess(CATALOG_TEXT.encode("utf-8")),
            FakeProcess(FIELDS_TEXT.encode("utf-8")),
        ]
        workspace = root / "workspace"
        workspace.mkdir()

        result = run_protocol_inventory(
            vendor,
            capture,
            workspace,
            self.profile_path(),
            expected_frames=1,
        )

        self.assertEqual(result.inventory.frames_observed, 1)
        self.assertTrue(result.inventory.complete)
        self.assertEqual(result.inventory.observations[0].group_id, "dns")
        self.assertEqual(popen.call_count, 2)
        second_arguments = popen.call_args_list[1].args[0]
        self.assertIn("-c", second_arguments)
        self.assertNotIn("ip.src", second_arguments)
        self.assertNotIn("eth.src", second_arguments)

    @mock.patch("wlan_troubleshooter_ko.tshark.runner.subprocess.Popen")
    def test_nonzero_exit_hides_stderr_text(self, popen):
        root, vendor, _capture = self.setup_paths()
        popen.return_value = FakeProcess(
            b"",
            b"/private/customer/path and secret payload",
            return_code=2,
        )
        with self.assertRaises(TSharkExecutionError) as captured:
            run_field_catalog(vendor, root / "catalog-isolation")
        self.assertNotIn("customer", str(captured.exception))
        self.assertNotIn("payload", str(captured.exception))


if __name__ == "__main__":
    unittest.main()
