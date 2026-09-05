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
F\tDHCP transaction ID\tdhcp.id\tFT_UINT32\tdhcp\tBASE_HEX\t0x0\t
F\tDHCP message type\tdhcp.option.dhcp\tFT_UINT8\tdhcp\tBASE_DEC\t0x0\t
F\tEthernet source\teth.src\tFT_ETHER\teth\t\t0x0\t
F\tEthernet destination\teth.dst\tFT_ETHER\teth\t\t0x0\t
"""
REPLAY_CATALOG_TEXT = CATALOG_TEXT + """F\tEAPOL message number\twlan_rsna_eapol.keydes.msgnr\tFT_UINT8\twlan_rsna_eapol\tBASE_DEC\t0x0\t
F\tEAPOL Replay Counter\teapol.keydes.replay_counter\tFT_UINT64\teapol\tBASE_DEC\t0x0\t
"""
FIELDS_TEXT = """"frame.number"\t"frame.interface_id"\t"frame.cap_len"\t"frame.len"\t"frame.protocols"
"1"\t"0"\t"42"\t"42"\t"eth:ethertype:arp"
"2"\t"0"\t"71"\t"71"\t"eth:ethertype:ip:udp:dns"
"""
EVENT_FIELDS_TEXT = """"frame.number"\t"frame.time_epoch"\t"frame.interface_id"\t"frame.cap_len"\t"frame.len"\t"frame.protocols"\t"dhcp.id"\t"dhcp.option.dhcp"
"1"\t"1700000000.000000000"\t"0"\t"342"\t"342"\t"eth:ethertype:ip:udp:dhcp"\t"0x01020304"\t"1"
"2"\t"1700000001.000000000"\t"0"\t"342"\t"342"\t"eth:ethertype:ip:udp:dhcp"\t"0x01020304"\t"5"
"""
IDENTITY_FIELDS_TEXT = """"frame.number"\t"frame.time_epoch"\t"frame.protocols"\t"dhcp.option.dhcp"\t"eth.src"\t"eth.dst"
"1"\t"1700000000.000000000"\t"eth:ethertype:ip:udp:dhcp"\t"1"\t"02:00:00:00:00:10"\t"ff:ff:ff:ff:ff:ff"
"2"\t"1700000001.000000000"\t"eth:ethertype:ip:udp:dhcp"\t"5"\t"02:00:00:00:00:20"\t"ff:ff:ff:ff:ff:ff"
"""
TIME_FIELDS_TEXT = """"frame.number"\t"frame.time_epoch"
"1"\t"1700000000.000000000"
"2"\t"1700000001.000000000"
"""
REPLAY_FIELDS_TEXT = """"frame.number"\t"wlan_rsna_eapol.keydes.msgnr"\t"eapol.keydes.replay_counter"
"1"\t\t
"2"\t\t
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
    (root / "manifest.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )


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
        self.assertNotIn("eth.src", inventory_arguments)
        self.assertNotIn("eapol.keydes.replay_counter", inventory_arguments)

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
    def test_service_returns_aliases_replay_and_relative_time_without_raw_values(self, popen):
        root, vendor, capture, _workspace = self.setup_paths()
        popen.side_effect = [
            FakeProcess(CATALOG_TEXT.encode("utf-8")),
            FakeProcess(EVENT_FIELDS_TEXT.encode("utf-8")),
            FakeProcess(IDENTITY_FIELDS_TEXT.encode("utf-8")),
            FakeProcess(CATALOG_TEXT.encode("utf-8")),
            FakeProcess(TIME_FIELDS_TEXT.encode("utf-8")),
            FakeProcess(REPLAY_CATALOG_TEXT.encode("utf-8")),
            FakeProcess(REPLAY_FIELDS_TEXT.encode("utf-8")),
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
        self.assertIsNotNone(result.protocol_inventory.event_timeline)
        self.assertIsNotNone(result.protocol_inventory.transaction_sessions)
        self.assertIsNotNone(result.protocol_inventory.device_sessions)
        self.assertIsNotNone(result.capture_time_boundaries)
        self.assertIsNotNone(result.eapol_replay_relations)

        device_report = result.protocol_inventory.device_sessions
        self.assertEqual(len(device_report.devices), 1)
        self.assertEqual(device_report.devices[0].alias, "DEVICE-1")
        self.assertEqual(
            device_report.devices[0].linked_attempt_ids,
            ("DHCP-1-A1",),
        )
        self.assertFalse(device_report.raw_identifiers_serialized)
        self.assertFalse(device_report.alias_secret_persisted)
        self.assertFalse(device_report.aliases_stable_across_runs)

        timing = result.capture_time_boundaries
        self.assertEqual(timing.frames_observed, 2)
        self.assertEqual(timing.expected_frames, 2)
        self.assertTrue(timing.complete)
        self.assertEqual(timing.observed_span_ms, 1000)
        self.assertEqual(len(timing.transaction_boundaries), 1)
        transaction = timing.transaction_boundaries[0]
        self.assertEqual(transaction.attempt_id, "DHCP-1-A1")
        self.assertEqual(transaction.start_distance_ms, 0)
        self.assertEqual(transaction.end_observation_window_ms, 0)
        self.assertEqual(transaction.observed_attempt_duration_ms, 1000)
        self.assertEqual(transaction.boundary_state, "spans-analysis-window")
        self.assertFalse(timing.absolute_timestamps_serialized)
        self.assertFalse(timing.response_wait_sufficiency_assessed)
        self.assertFalse(timing.response_absence_confirmed)

        replay = result.eapol_replay_relations
        self.assertTrue(replay.field_available)
        self.assertEqual(replay.observations_source_total, 0)
        self.assertEqual(replay.observations, ())
        self.assertFalse(replay.raw_replay_counters_serialized)
        self.assertFalse(replay.replay_counter_values_persisted)
        self.assertFalse(replay.same_handshake_confirmed)
        self.assertFalse(replay.retransmission_confirmed)

        text = json.dumps(serialized, ensure_ascii=False)
        for forbidden in (
            str(capture),
            capture.name,
            "192.0.2",
            "1700000000",
            "frame.time_epoch",
            "02:00:00:00:00:10",
            "02:00:00:00:00:20",
            "020000000010",
            '"replay_counter":',
        ):
            self.assertNotIn(forbidden, text)
        self.assertEqual(serialized["schema_version"], 2)
        self.assertEqual(
            serialized["protocol_inventory"]["inventory"]["frames_observed"],
            2,
        )
        self.assertEqual(
            serialized["protocol_inventory"]["event_correlation"][
                "frames_scanned"
            ],
            2,
        )
        self.assertEqual(
            serialized["protocol_inventory"]["event_timeline"][
                "frames_observed"
            ],
            2,
        )
        self.assertEqual(
            serialized["protocol_inventory"]["transaction_sessions"][
                "attempts_total"
            ],
            1,
        )
        self.assertEqual(
            serialized["protocol_inventory"]["device_sessions"][
                "devices_total"
            ],
            1,
        )
        self.assertEqual(
            serialized["capture_time_boundaries"]["observed_span_ms"],
            1000,
        )
        self.assertEqual(
            serialized["eapol_replay_relations"]["observations_evaluated"],
            0,
        )
        self.assertEqual(popen.call_count, 7)

        event_arguments = popen.call_args_list[1].args[0]
        identity_arguments = popen.call_args_list[2].args[0]
        time_arguments = popen.call_args_list[4].args[0]
        replay_arguments = popen.call_args_list[6].args[0]
        self.assertNotIn("eth.src", event_arguments)
        self.assertNotIn("eth.dst", event_arguments)
        self.assertNotIn("eapol.keydes.replay_counter", event_arguments)
        self.assertIn("eth.src", identity_arguments)
        self.assertIn("eth.dst", identity_arguments)
        self.assertNotIn("eapol.keydes.replay_counter", identity_arguments)
        self.assertNotIn("ip.src", identity_arguments)
        self.assertNotIn("dns.qry.name", identity_arguments)
        self.assertIn("frame.number", time_arguments)
        self.assertIn("frame.time_epoch", time_arguments)
        self.assertNotIn("eth.src", time_arguments)
        self.assertNotIn("wlan.bssid", time_arguments)
        self.assertNotIn("eapol.keydes.replay_counter", time_arguments)
        self.assertIn("eapol.keydes.replay_counter", replay_arguments)
        self.assertNotIn("eth.src", replay_arguments)
        self.assertNotIn("wlan.bssid", replay_arguments)

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
