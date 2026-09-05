import json
import struct
import tempfile
import unittest
from pathlib import Path

from wlan_troubleshooter_ko.analysis.models import CaptureStructureError
from wlan_troubleshooter_ko.analysis.preflight import (
    classify_capture_capabilities,
    inspect_capture_structure,
)
from wlan_troubleshooter_ko.core.capture import validate_capture


def block(block_type, body, endian="<", raw_type=None):
    total = 12 + len(body)
    if total % 4:
        raise ValueError("test block must be padded")
    type_bytes = raw_type if raw_type is not None else struct.pack(endian + "I", block_type)
    return type_bytes + struct.pack(endian + "I", total) + body + struct.pack(endian + "I", total)


def shb(endian="<"):
    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    return block(
        0x0A0D0D0A,
        bom + struct.pack(endian + "HHq", 1, 0, -1),
        endian,
        bytes.fromhex("0a0d0d0a"),
    )


def idb(link_type=1, endian="<"):
    return block(1, struct.pack(endian + "HHI", link_type, 0, 65535), endian)


def epb(interface_id=0, endian="<"):
    data = b"abcd"
    body = struct.pack(
        endian + "IIIII",
        interface_id,
        0,
        1,
        len(data),
        len(data),
    ) + data
    return block(6, body, endian)


def option(code, value, endian="<"):
    padding = b"\x00" * ((4 - len(value) % 4) % 4)
    return struct.pack(endian + "HH", code, len(value)) + value + padding


def counter_option(code, value, endian="<"):
    return option(code, struct.pack(endian + "Q", value), endian)


def isb(interface_id=0, options=b"", endian="<"):
    body = struct.pack(endian + "III", interface_id, 0x01020304, 0x05060708)
    body += options + struct.pack(endian + "HH", 0, 0)
    return block(5, body, endian)


class PcapngInterfaceStatisticsTests(unittest.TestCase):
    def inspect(self, data, *, max_records=1_000_000):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "statistics.pcapng"
        path.write_bytes(data)
        return inspect_capture_structure(
            validate_capture(path),
            max_records=max_records,
        )

    def test_positive_drop_counters_are_observed_without_loss_or_root_claim(self):
        options = b"".join(
            (
                option(2, struct.pack("<Q", 100)),
                option(3, struct.pack("<Q", 200)),
                counter_option(4, 2),
                counter_option(5, 3),
                counter_option(6, 2),
                counter_option(7, 1),
                counter_option(8, 2),
            )
        )
        structure = self.inspect(shb() + idb() + epb() + isb(options=options))
        item = structure.interface_statistics[0]

        self.assertEqual(structure.interface_statistics_state, "observed")
        self.assertEqual(item.interface_alias, "IFACE-1")
        self.assertEqual(item.observation_index, 1)
        self.assertEqual(item.counter_state, "reported-drop-observed")
        self.assertEqual(item.ifrecv, 2)
        self.assertEqual(item.ifdrop, 3)
        self.assertEqual(item.filteraccept, 2)
        self.assertEqual(item.osdrop, 1)
        self.assertEqual(item.usrdeliv, 2)
        self.assertTrue(item.block_timestamp_present)
        self.assertTrue(item.start_time_present)
        self.assertTrue(item.end_time_present)
        self.assertFalse(item.absolute_timestamps_serialized)
        self.assertFalse(item.capture_loss_excluded)
        self.assertFalse(item.root_cause_confirmed)

        report = classify_capture_capabilities(structure)
        self.assertTrue(
            any("Interface Statistics" in value for value in report.available_checks)
        )
        self.assertTrue(any("드롭 카운터" in value for value in report.cautions))

    def test_zero_drop_counters_do_not_prove_loss_exclusion(self):
        options = counter_option(5, 0) + counter_option(7, 0)
        item = self.inspect(shb() + idb() + isb(options=options)).interface_statistics[0]

        self.assertEqual(item.counter_state, "zero-reported-drop-counters")
        self.assertEqual(item.ifdrop, 0)
        self.assertEqual(item.osdrop, 0)
        self.assertFalse(item.capture_loss_excluded)

    def test_statistics_without_drop_options_are_distinct(self):
        item = self.inspect(
            shb() + idb() + isb(options=counter_option(4, 10))
        ).interface_statistics[0]

        self.assertEqual(item.counter_state, "statistics-without-drop-counters")
        self.assertEqual(item.ifrecv, 10)
        self.assertIsNone(item.ifdrop)
        self.assertIsNone(item.osdrop)

    def test_no_isb_is_explicit(self):
        structure = self.inspect(shb() + idb() + epb())

        self.assertEqual(
            structure.interface_statistics_state,
            "no-interface-statistics",
        )
        self.assertEqual(structure.interface_statistics, ())
        report = classify_capture_capabilities(structure)
        self.assertTrue(
            any("통계" in value and "없어" in value for value in report.cautions)
        )

    def test_multiple_isb_values_are_not_summed(self):
        structure = self.inspect(
            shb()
            + idb()
            + isb(options=counter_option(5, 1))
            + isb(options=counter_option(5, 2))
        )

        self.assertEqual(len(structure.interface_statistics), 2)
        self.assertEqual(
            [item.observation_index for item in structure.interface_statistics],
            [1, 2],
        )
        self.assertEqual(
            [item.ifdrop for item in structure.interface_statistics],
            [1, 2],
        )

    def test_sections_and_interfaces_receive_deterministic_aliases(self):
        structure = self.inspect(
            shb("<")
            + idb(endian="<")
            + isb(options=counter_option(5, 1, "<"), endian="<")
            + shb(">")
            + idb(endian=">")
            + isb(options=counter_option(5, 2, ">"), endian=">")
        )

        self.assertEqual(
            [item.interface_alias for item in structure.interface_statistics],
            ["IFACE-1", "IFACE-2"],
        )
        self.assertEqual(
            [item.section_index for item in structure.interface_statistics],
            [0, 1],
        )
        self.assertEqual(
            [item.ifdrop for item in structure.interface_statistics],
            [1, 2],
        )

    def test_undefined_interface_is_warned_and_not_linked(self):
        structure = self.inspect(
            shb() + idb() + isb(9, counter_option(5, 7))
        )

        self.assertEqual(structure.interface_statistics, ())
        self.assertTrue(
            any("정의되지 않은" in value for value in structure.warnings)
        )

    def test_invalid_counter_length_is_ignored_with_warning(self):
        malformed = option(5, struct.pack("<I", 3))
        structure = self.inspect(shb() + idb() + isb(options=malformed))
        item = structure.interface_statistics[0]

        self.assertEqual(item.counter_state, "statistics-without-drop-counters")
        self.assertIsNone(item.ifdrop)
        self.assertTrue(any("8바이트" in value for value in structure.warnings))

    def test_duplicate_supported_option_fails_closed(self):
        data = (
            shb()
            + idb()
            + isb(options=counter_option(5, 1) + counter_option(5, 2))
        )
        with self.assertRaises(CaptureStructureError):
            self.inspect(data)

    def test_invalid_end_option_fails_closed(self):
        bad_end = struct.pack("<HHI", 0, 4, 1)
        body = struct.pack("<III", 0, 0, 0) + bad_end
        with self.assertRaises(CaptureStructureError):
            self.inspect(shb() + idb() + block(5, body))

    def test_scan_limit_does_not_read_statistics_beyond_checked_range(self):
        structure = self.inspect(
            shb() + idb() + epb() + isb(options=counter_option(5, 3)),
            max_records=3,
        )

        self.assertFalse(structure.scan_complete)
        self.assertEqual(structure.interface_statistics, ())

    def test_serialization_is_deterministic_and_has_no_absolute_time(self):
        structure = self.inspect(
            shb()
            + idb()
            + isb(
                options=option(2, struct.pack("<Q", 0x0102030405060708))
                + option(3, struct.pack("<Q", 0x1112131415161718))
                + counter_option(5, 3)
            )
        )
        first = structure.to_dict()
        second = structure.to_dict()
        rendered = json.dumps(first, ensure_ascii=False).casefold()

        self.assertEqual(first, second)
        self.assertIn("iface-1", rendered)
        self.assertIn("reported-drop-observed", rendered)
        self.assertNotIn("0102030405060708", rendered)
        self.assertNotIn("1112131415161718", rendered)
        self.assertNotIn("interface name", rendered)
        self.assertFalse(
            first["interface_statistics"][0]["absolute_timestamps_serialized"]
        )


if __name__ == "__main__":
    unittest.main()
