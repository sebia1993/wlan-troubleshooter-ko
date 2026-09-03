import hashlib
import io
import json
import struct
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from wlan_troubleshooter_ko.analysis.service import analyze_capture
from wlan_troubleshooter_ko.tshark.inventory import (
    run_field_catalog_text,
    run_protocol_inventory,
)
from wlan_troubleshooter_ko.tshark.runner import TSharkExecutionError


CATALOG_TEXT = """P\tFrame\tframe
F\tFrame Number\tframe.number\tFT_UINT32\tframe\tBASE_DEC\t0x0\t
F\tEpoch time\tframe.time_epoch\tFT_RELATIVE_TIME\tframe\t\t0x0\t
F\tInterface id\tframe.interface_id\tFT_UINT32\tframe\tBASE_DEC\t0x0\t
F\tCapture Length\tframe.cap_len\tFT_UINT32\tframe\tBASE_DEC\t0x0\t
F\tFrame Length\tframe.len\tFT_UINT32\tframe\tBASE_DEC\t0x0\t
F\tProtocols in frame\tframe.protocols\tFT_STRING\tframe\t\t0x0\t
"""
FIELDS_TEXT = """"frame.number"\t"frame.interface_id"\t"frame.cap_len"\t"frame.len"\t"frame.protocols"
"1"\t"0"\t"42"\t"42"\t"eth:ethertype:arp"
"2"\t"0"\t"71"\t"71"\t"eth:ethertype:ip:udp:dns"
"""
EVENT_FIELDS_TEXT = """"frame.number"\t"frame.time_epoch"\t"frame.interface_id"\t"frame.cap_len"\t"frame.len"\t"frame.protocols"
"1"\t"1.000000000"\t"0"\t"42"\t"42"\t"eth:ethertype:arp"
"2"\t"2.000000000"\t"0"\t"71"\t"71"\t"eth:ethertype:ip:udp:dns"
"""


def pcap_with_packets(count=2):
    output = bytearray(bytes.fromhex("d4c3b2a1"))
    output += struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    for index in range(count):
        data = bytes([index + 1]) * 42
        output += struct.pack("<IIII", index + 1, 0, len(data), len(data))
        output += data
    return bytes(output)


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
        self.return_code = return_code
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.return_code

    def wait(self, timeout=None):
        return self.return_code

    def terminate(self):
        self.terminated = True
        self.return_code = -15

    def kill(self):
        self.killed = True
        self.return_code = -9


class Phase4RuntimeTests(unittest.TestCase):
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
        capture.write_bytes(pcap_with_packets())
        workspace = root / "workspace"
        workspace.mkdir()
        return root, vendor, capture, workspace

    @mock.patch("wlan_troubleshooter_ko.tshark.runner.subprocess.Popen")
    def test_field_catalog_runs_fixed_bounded_pipe(self, popen):
        root, vendor, _capture, _workspace = self.setup_paths()
        popen.return_value = FakeProcess(CATALOG_TEXT.encode("utf-8"))

        result = run_field_catalog_text(vendor, root / "catalog")

        self.assertIn("frame.protocols", result.text)
        arguments = popen.call_args.args[0]
        keywords = popen.call_args.kwargs
        self.assertEqual(arguments[1:], ["-n", "-G", "fields"])
        self.assertIs(keywords["shell"], False)
        self.assertIs(keywords["stdout"], subprocess.PIPE)
        self.assertIs(keywords["stderr"], subprocess.PIPE)
        self.assertNotIn("PATH", keywords["env"])

    @mock.patch("wlan_troubleshooter_ko.tshark.runner.subprocess.Popen")
    def test_protocol_inventory_executes_catalog_then_profile(self, popen):
        _root, vendor, capture, workspace = self.setup_paths()
        popen.side_effect = [
            FakeProcess(CATALOG_TEXT.encode("utf-8")),
            FakeProcess(FIELDS_TEXT.encode("utf-8")),
        ]

        result = run_protocol_inventory(
            vendor,
            capture,
            workspace,
            self.profile_path(),
            expected_frames=2,
        )

        counts = {
            item.group_id: item.frame_count
            for item in result.inventory.observations
        }
        self.assertEqual(counts["arp"], 1)
        self.assertEqual(counts["dns"], 1)
        self.assertTrue(result.inventory.complete)
        self.assertEqual(popen.call_count, 2)
        inventory_arguments = popen.call_args_list[1].args[0]
        self.assertIn("-r", inventory_arguments)
        self.assertIn("-c", inventory_arguments)
        self.assertNotIn("-i", inventory_arguments)
        self.assertNotIn("ip.src", inventory_arguments)

    @mock.patch("wlan_troubleshooter_ko.tshark.runner.subprocess.Popen")
    def test_nonzero_exit_never_exposes_stderr(self, popen):
        root, vendor, _capture, _workspace = self.setup_paths()
        popen.return_value = FakeProcess(
            b"",
            b"C:/private/customer/secret.pcap token=value",
            return_code=2,
        )

        with self.assertRaises(TSharkExecutionError) as captured:
            run_field_catalog_text(vendor, root / "catalog")

        message = str(captured.exception)
        self.assertNotIn("customer", message)
        self.assertNotIn("token", message)

    @mock.patch("wlan_troubleshooter_ko.tshark.runner.subprocess.Popen")
    def test_stdout_limit_terminates_analysis(self, popen):
        root, vendor, _capture, _workspace = self.setup_paths()
        process = FakeProcess(b"x" * 2048)
        popen.return_value = process

        with self.assertRaises(TSharkExecutionError):
            run_field_catalog_text(
                vendor,
                root / "catalog",
                max_stdout_bytes=1024,
            )

        self.assertTrue(
            process.terminated or process.killed or process.poll() is not None
        )

    @mock.patch("wlan_troubleshooter_ko.tshark.runner.subprocess.Popen")
    def test_service_returns_identifier_free_inventory_and_stage_summary(self, popen):
        root, vendor, capture, _workspace = self.setup_paths()
        popen.side_effect = [
            FakeProcess(CATALOG_TEXT.encode("utf-8")),
            FakeProcess(EVENT_FIELDS_TEXT.encode("utf-8")),
        ]

        result = analyze_capture(
            capture,
            vendor,
            self.profile_path(),
            workspace_base=root,
        )
        serialized = result.to_dict()

        self.assertEqual(result.inventory_state, "completed")
        self.assertIsNotNone(result.protocol_inventory)
        self.assertIsNotNone(result.protocol_inventory.event_correlation)
        text = json.dumps(serialized, ensure_ascii=False)
        self.assertNotIn(str(capture), text)
        self.assertNotIn(capture.name, text)
        self.assertNotIn("192.0.2", text)
        self.assertEqual(
            serialized["protocol_inventory"]["inventory"]["frames_observed"],
            2,
        )
        self.assertEqual(
            serialized["protocol_inventory"]["event_correlation"]["frames_scanned"],
            2,
        )

    @mock.patch("wlan_troubleshooter_ko.tshark.runner.subprocess.Popen")
    def test_corrupted_bundle_is_reported_without_execution(self, popen):
        root, vendor, capture, _workspace = self.setup_paths()
        (vendor / "tshark.exe").write_bytes(b"changed")

        result = analyze_capture(
            capture,
            vendor,
            self.profile_path(),
            workspace_base=root,
        )

        self.assertEqual(result.inventory_state, "failed")
        self.assertIn("누락되었거나 변경", result.inventory_message)
        popen.assert_not_called()

    @mock.patch("wlan_troubleshooter_ko.tshark.runner.subprocess.Popen")
    def test_cancelled_before_start_does_not_create_process(self, popen):
        root, vendor, _capture, _workspace = self.setup_paths()
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(TSharkExecutionError):
            run_field_catalog_text(
                vendor,
                root / "catalog",
                cancel_event=cancel,
            )
        popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
