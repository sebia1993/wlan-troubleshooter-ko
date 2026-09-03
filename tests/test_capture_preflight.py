import struct
import tempfile
import threading
import unittest
from pathlib import Path

from wlan_troubleshooter_ko.analysis.preflight import (
    CaptureStructureError,
    classify_capture_capabilities,
    inspect_capture_structure,
)
from wlan_troubleshooter_ko.core.capture import validate_capture


def pcap_bytes(link_type=1, records=(), endian="<", nanosecond=False):
    if endian == "<":
        magic = bytes.fromhex("4d3cb2a1" if nanosecond else "d4c3b2a1")
    else:
        magic = bytes.fromhex("a1b23c4d" if nanosecond else "a1b2c3d4")
    output = bytearray(magic)
    output += struct.pack(endian + "HHiIII", 2, 4, 0, 0, 65535, link_type)
    for data, original_length in records:
        output += struct.pack(endian + "IIII", 1, 2, len(data), original_length)
        output += data
    return bytes(output)


def block(block_type, body, endian="<", raw_type=None):
    total = 12 + len(body)
    if total % 4:
        raise ValueError("test block must be padded")
    type_bytes = raw_type if raw_type is not None else struct.pack(endian + "I", block_type)
    return type_bytes + struct.pack(endian + "I", total) + body + struct.pack(endian + "I", total)


def shb(endian="<"):
    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    body = bom + struct.pack(endian + "HHq", 1, 0, -1)
    return block(0x0A0D0D0A, body, endian, bytes.fromhex("0a0d0d0a"))


def idb(link_type, snaplen=65535, endian="<", tsresol=None):
    options = b""
    if tsresol is not None:
        options += struct.pack(endian + "HH", 9, 1) + bytes([tsresol]) + b"\x00" * 3
        options += struct.pack(endian + "HH", 0, 0)
    body = struct.pack(endian + "HHI", link_type, 0, snaplen) + options
    return block(1, body, endian)


def epb(interface_id=0, data=b"abcd", original_length=None, endian="<"):
    original_length = len(data) if original_length is None else original_length
    padded = data + b"\x00" * ((4 - len(data) % 4) % 4)
    body = struct.pack(
        endian + "IIIII",
        interface_id,
        0,
        1,
        len(data),
        original_length,
    ) + padded
    return block(6, body, endian)


class CapturePreflightTests(unittest.TestCase):
    def inspect(self, data, suffix):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / ("sample" + suffix)
        path.write_bytes(data)
        return inspect_capture_structure(validate_capture(path))

    def test_ethernet_pcap_is_wired_or_controller(self):
        structure = self.inspect(pcap_bytes(1, [(b"abc", 3)]), ".pcap")
        report = classify_capture_capabilities(structure)
        self.assertEqual(report.capture_kind, "wired-or-controller")
        self.assertFalse(report.has_80211_link_type)
        self.assertFalse(report.has_radiotap_link_type)
        self.assertEqual(structure.packets_scanned, 1)

    def test_radiotap_pcap_enables_air_and_rf_preflight(self):
        report = classify_capture_capabilities(self.inspect(pcap_bytes(127), ".pcap"))
        self.assertEqual(report.capture_kind, "wireless-air-radiotap")
        self.assertTrue(report.has_80211_link_type)
        self.assertTrue(report.has_radiotap_link_type)

    def test_plain_dot11_does_not_claim_rf_metadata(self):
        report = classify_capture_capabilities(self.inspect(pcap_bytes(105), ".pcap"))
        self.assertEqual(report.capture_kind, "wireless-air-no-radiotap")
        self.assertTrue(report.has_80211_link_type)
        self.assertFalse(report.has_radiotap_link_type)
        self.assertTrue(any("RSSI" in item for item in report.unavailable_checks))

    def test_truncated_packet_is_reported_as_caution(self):
        structure = self.inspect(pcap_bytes(1, [(b"abc", 100)]), ".pcap")
        report = classify_capture_capabilities(structure)
        self.assertEqual(structure.truncated_packets_observed, 1)
        self.assertTrue(any("잘린 패킷" in item for item in report.cautions))

    def test_declared_packet_larger_than_file_is_rejected(self):
        data = pcap_bytes(1) + struct.pack("<IIII", 1, 0, 10, 10) + b"x"
        with self.assertRaises(CaptureStructureError):
            self.inspect(data, ".pcap")

    def test_scan_limit_marks_result_incomplete(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "limited.pcap"
        path.write_bytes(pcap_bytes(1, [(b"a", 1), (b"b", 1)]))
        limited = inspect_capture_structure(validate_capture(path), max_records=1)
        self.assertFalse(limited.scan_complete)
        self.assertEqual(limited.packets_scanned, 1)

    def test_big_endian_nanosecond_pcap(self):
        structure = self.inspect(
            pcap_bytes(1, [(b"abc", 3)], endian=">", nanosecond=True),
            ".pcap",
        )
        self.assertEqual(structure.byte_order, "big")
        self.assertEqual(structure.timestamp_precision, "nanosecond")
        self.assertEqual(structure.interfaces[0].timestamp_resolution, "10^-9")

    def test_pcapng_radiotap_interface_and_packet(self):
        structure = self.inspect(shb() + idb(127, tsresol=9) + epb(), ".pcapng")
        report = classify_capture_capabilities(structure)
        self.assertEqual(structure.sections, 1)
        self.assertEqual(structure.interfaces[0].timestamp_resolution, "10^-9")
        self.assertEqual(structure.interfaces[0].packets_scanned, 1)
        self.assertEqual(report.capture_kind, "wireless-air-radiotap")

    def test_pcapng_mixed_interfaces_are_not_merged(self):
        structure = self.inspect(
            shb() + idb(127) + idb(1) + epb(0) + epb(1),
            ".pcapng",
        )
        report = classify_capture_capabilities(structure)
        self.assertEqual(report.capture_kind, "mixed")
        self.assertEqual([item.packets_scanned for item in structure.interfaces], [1, 1])

    def test_pcapng_mixed_endian_sections(self):
        structure = self.inspect(
            shb("<") + idb(1, endian="<") + epb(endian="<")
            + shb(">") + idb(127, endian=">") + epb(endian=">"),
            ".pcapng",
        )
        self.assertEqual(structure.byte_order, "mixed")
        self.assertEqual(structure.sections, 2)
        self.assertEqual([item.section_index for item in structure.interfaces], [0, 1])

    def test_pcapng_trailing_length_mismatch_is_rejected(self):
        data = bytearray(shb() + idb(1))
        data[-4:] = struct.pack("<I", 999)
        with self.assertRaises(CaptureStructureError):
            self.inspect(bytes(data), ".pcapng")

    def test_ppi_does_not_claim_wireless_or_ip_visibility(self):
        report = classify_capture_capabilities(self.inspect(pcap_bytes(192), ".pcap"))
        self.assertEqual(report.capture_kind, "unknown")
        self.assertFalse(report.has_80211_link_type)
        self.assertFalse(report.has_radiotap_link_type)
        self.assertFalse(report.has_ip_path_link_type)
        self.assertTrue(any("PPI" in item for item in report.cautions))

    def test_unknown_link_type_does_not_claim_protocol_visibility(self):
        report = classify_capture_capabilities(self.inspect(pcap_bytes(65000), ".pcap"))
        self.assertEqual(report.capture_kind, "unknown")
        self.assertFalse(report.has_ip_path_link_type)
        self.assertTrue(any("IP 계층" in item for item in report.unavailable_checks))

    def test_cancelled_scan_fails_closed(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "cancelled.pcap"
        path.write_bytes(pcap_bytes(1, [(b"a", 1)]))
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(CaptureStructureError):
            inspect_capture_structure(validate_capture(path), cancel_event=cancel)

    def test_serialization_is_deterministic(self):
        structure = self.inspect(shb() + idb(1) + epb(), ".pcapng")
        self.assertEqual(structure.to_dict(), structure.to_dict())
        self.assertEqual(
            classify_capture_capabilities(structure).to_dict(),
            classify_capture_capabilities(structure).to_dict(),
        )


if __name__ == "__main__":
    unittest.main()
