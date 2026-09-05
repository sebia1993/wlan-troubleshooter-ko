import json
import struct
import tempfile
import threading
import unittest
from pathlib import Path

from wlan_troubleshooter_ko.analysis.pcapng_interface_statistics import (
    PcapngInterfaceStatisticsError,
    inspect_pcapng_interface_statistics,
)
from wlan_troubleshooter_ko.core.capture import validate_capture


SHB = 0x0A0D0D0A
IDB = 0x00000001
ISB = 0x00000005
UNKNOWN = 0x00000BAD


def pad(value: bytes) -> bytes:
    return value + bytes((-len(value)) % 4)


def option(endian: str, code: int, value: bytes) -> bytes:
    return struct.pack(endian + "HH", code, len(value)) + pad(value)


def end_options(endian: str) -> bytes:
    return struct.pack(endian + "HH", 0, 0)


def block(endian: str, block_type: int, body: bytes) -> bytes:
    if len(body) % 4:
        raise ValueError("test block body must be aligned")
    total = 12 + len(body)
    return (
        struct.pack(endian + "II", block_type, total)
        + body
        + struct.pack(endian + "I", total)
    )


def section(endian: str, private_comment: bytes = b"") -> bytes:
    body = struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1)
    if private_comment:
        body += option(endian, 1, private_comment)
        body += end_options(endian)
    return block(endian, SHB, body)


def interface(endian: str, private_name: bytes = b"") -> bytes:
    body = struct.pack(endian + "HHI", 1, 0, 65535)
    if private_name:
        body += option(endian, 2, private_name)
        body += end_options(endian)
    return block(endian, IDB, body)


def counter(endian: str, code: int, value: int) -> bytes:
    return option(endian, code, struct.pack(endian + "Q", value))


def statistics(
    endian: str,
    interface_id: int,
    counters=(),
    *,
    private_comment: bytes = b"",
    duplicate=None,
) -> bytes:
    body = struct.pack(endian + "III", interface_id, 0x01020304, 0x05060708)
    if private_comment:
        body += option(endian, 1, private_comment)
    for code, value in counters:
        raw = struct.pack(endian + "Q", value) if isinstance(value, int) else value
        body += option(endian, code, raw)
    if duplicate is not None:
        code, value = duplicate
        body += counter(endian, code, value)
    body += end_options(endian)
    return block(endian, ISB, body)


def unknown(endian: str, value: bytes = b"ignored") -> bytes:
    return block(endian, UNKNOWN, pad(value))


def minimal_pcap() -> bytes:
    return bytes.fromhex("d4c3b2a1") + struct.pack(
        "<HHiIII", 2, 4, 0, 0, 65535, 1
    )


class PcapngInterfaceStatisticsTests(unittest.TestCase):
    def inspect(self, raw: bytes):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name).resolve() / "private-statistics.pcapng"
        path.write_bytes(raw)
        return inspect_pcapng_interface_statistics(validate_capture(path))

    @staticmethod
    def counter_map(interface_value):
        return {item.name: item for item in interface_value.counters}

    def test_little_endian_two_snapshots_report_drops_without_summing(self):
        raw = b"".join(
            (
                section("<", b"private-section-comment"),
                interface("<", b"private-interface-name"),
                statistics(
                    "<",
                    0,
                    ((4, 2), (5, 0), (6, 2), (7, 0), (8, 2)),
                    private_comment=b"private-statistics-comment",
                ),
                unknown("<", b"private-unknown-block"),
                statistics(
                    "<",
                    0,
                    ((4, 4), (5, 3), (6, 4), (7, 1), (8, 4)),
                ),
            )
        )
        report = self.inspect(raw)
        item = report.interfaces[0]
        counters = self.counter_map(item)

        self.assertTrue(report.supported_capture_format)
        self.assertTrue(report.complete)
        self.assertEqual(report.state, "reported-drop-observed")
        self.assertEqual(report.sections_observed, 1)
        self.assertEqual(report.interfaces_defined, 1)
        self.assertEqual(report.statistics_blocks_observed, 2)
        self.assertEqual(report.interfaces_with_statistics, 1)
        self.assertEqual(item.interface_alias, "IFACE-1")
        self.assertEqual(item.section_index, 0)
        self.assertEqual(item.interface_id, 0)
        self.assertEqual(item.statistics_blocks, 2)
        self.assertEqual(item.state, "reported-drop-observed")

        self.assertEqual(counters["ifrecv"].observations, 2)
        self.assertEqual(counters["ifrecv"].first_value, 2)
        self.assertEqual(counters["ifrecv"].last_value, 4)
        self.assertEqual(
            counters["ifrecv"].progression,
            "counter-increase-observed",
        )
        self.assertEqual(counters["ifdrop"].first_value, 0)
        self.assertEqual(counters["ifdrop"].last_value, 3)
        self.assertEqual(counters["osdrop"].last_value, 1)

        self.assertFalse(report.raw_interface_identifiers_serialized)
        self.assertFalse(report.absolute_timestamps_serialized)
        self.assertFalse(report.capture_loss_excluded)
        self.assertFalse(report.specific_packet_loss_confirmed)
        self.assertFalse(report.root_cause_confirmed)
        self.assertFalse(item.raw_interface_identifiers_serialized)
        self.assertFalse(item.absolute_timestamps_serialized)
        self.assertFalse(item.specific_packet_loss_confirmed)
        self.assertFalse(item.root_cause_confirmed)

        rendered = json.dumps(report.to_dict(), ensure_ascii=False)
        for forbidden in (
            "private-section-comment",
            "private-interface-name",
            "private-statistics-comment",
            "private-unknown-block",
            "private-statistics.pcapng",
            "0102030405060708",
        ):
            self.assertNotIn(forbidden, rendered)

    def test_big_endian_zero_drop_counters_do_not_exclude_loss(self):
        report = self.inspect(
            section(">")
            + interface(">")
            + statistics(">", 0, ((4, 10), (5, 0), (7, 0)))
        )
        item = report.interfaces[0]
        counters = self.counter_map(item)

        self.assertEqual(report.state, "zero-reported-drop-counters")
        self.assertEqual(item.state, "zero-reported-drop-counters")
        self.assertEqual(counters["ifdrop"].last_value, 0)
        self.assertEqual(counters["osdrop"].last_value, 0)
        self.assertFalse(report.capture_loss_excluded)

    def test_statistics_without_drop_options_are_not_reported_as_zero(self):
        report = self.inspect(
            section("<")
            + interface("<")
            + statistics("<", 0, ((4, 12), (6, 9), (8, 8)))
        )
        item = report.interfaces[0]
        counters = self.counter_map(item)

        self.assertEqual(report.state, "statistics-without-drop-counters")
        self.assertEqual(item.state, "statistics-without-drop-counters")
        self.assertEqual(counters["ifdrop"].observations, 0)
        self.assertIsNone(counters["ifdrop"].first_value)
        self.assertEqual(counters["ifdrop"].progression, "not-reported")
        self.assertEqual(counters["osdrop"].observations, 0)

    def test_no_isb_is_explicit_for_each_declared_interface(self):
        report = self.inspect(section("<") + interface("<") + interface("<"))

        self.assertEqual(report.state, "no-interface-statistics")
        self.assertEqual(report.statistics_blocks_observed, 0)
        self.assertEqual(report.interfaces_defined, 2)
        self.assertEqual(
            tuple(item.interface_alias for item in report.interfaces),
            ("IFACE-1", "IFACE-2"),
        )
        self.assertTrue(
            all(
                item.state == "no-interface-statistics"
                for item in report.interfaces
            )
        )
        self.assertFalse(report.capture_loss_excluded)

    def test_multiple_sections_restart_interface_ids_and_keep_alias_order(self):
        report = self.inspect(
            section("<")
            + interface("<")
            + statistics("<", 0, ((5, 0),))
            + section(">")
            + interface(">")
            + statistics(">", 0, ((5, 2),))
        )

        self.assertEqual(report.sections_observed, 2)
        self.assertEqual(report.interfaces_defined, 2)
        self.assertEqual(
            tuple(item.interface_alias for item in report.interfaces),
            ("IFACE-1", "IFACE-2"),
        )
        self.assertEqual(
            tuple(item.section_index for item in report.interfaces),
            (0, 1),
        )
        self.assertEqual(
            tuple(item.interface_id for item in report.interfaces),
            (0, 0),
        )
        self.assertEqual(report.state, "reported-drop-observed")

    def test_counter_decrease_is_observed_without_reset_or_wrap_claim(self):
        report = self.inspect(
            section("<")
            + interface("<")
            + statistics("<", 0, ((4, 100), (5, 5)))
            + statistics("<", 0, ((4, 20), (5, 1)))
        )
        counters = self.counter_map(report.interfaces[0])

        self.assertEqual(
            counters["ifrecv"].progression,
            "counter-decrease-observed",
        )
        self.assertEqual(
            counters["ifdrop"].progression,
            "counter-decrease-observed",
        )
        self.assertFalse(report.root_cause_confirmed)

    def test_single_counter_value_and_unchanged_progression_are_distinct(self):
        single = self.inspect(
            section("<")
            + interface("<")
            + statistics("<", 0, ((4, 7),))
        )
        unchanged = self.inspect(
            section("<")
            + interface("<")
            + statistics("<", 0, ((4, 7),))
            + statistics("<", 0, ((4, 7),))
        )

        self.assertEqual(
            self.counter_map(single.interfaces[0])["ifrecv"].progression,
            "single-value-observed",
        )
        self.assertEqual(
            self.counter_map(unchanged.interfaces[0])["ifrecv"].progression,
            "counter-unchanged-observed",
        )

    def test_classic_pcap_is_unsupported_but_never_loss_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "private.pcap"
            path.write_bytes(minimal_pcap())
            report = inspect_pcapng_interface_statistics(validate_capture(path))

        self.assertFalse(report.supported_capture_format)
        self.assertTrue(report.complete)
        self.assertEqual(report.state, "unsupported-capture-format")
        self.assertEqual(report.interfaces, ())
        self.assertFalse(report.capture_loss_excluded)
        self.assertFalse(report.specific_packet_loss_confirmed)
        self.assertFalse(report.root_cause_confirmed)

    def test_undefined_interface_duplicate_counter_and_wrong_length_fail_closed(self):
        cases = (
            section("<")
            + interface("<")
            + statistics("<", 1, ((5, 1),)),
            section("<")
            + interface("<")
            + statistics("<", 0, ((5, 1),), duplicate=(5, 2)),
            section("<")
            + interface("<")
            + statistics("<", 0, ((5, b"\x01\x02\x03\x04"),)),
        )
        for raw in cases:
            with self.subTest(size=len(raw)):
                with self.assertRaises(PcapngInterfaceStatisticsError):
                    self.inspect(raw)

    def test_mismatched_trailing_length_and_nonzero_option_padding_fail_closed(self):
        mismatched = bytearray(
            section("<")
            + interface("<")
            + statistics("<", 0, ((5, 1),))
        )
        struct.pack_into("<I", mismatched, len(mismatched) - 4, 999)

        bad_padding_option = struct.pack("<HH", 2988, 1) + b"x\x01\x00\x00"
        body = struct.pack("<III", 0, 0, 0) + bad_padding_option + end_options("<")
        bad_padding = section("<") + interface("<") + block("<", ISB, body)

        for raw in (bytes(mismatched), bad_padding):
            with self.subTest(size=len(raw)):
                with self.assertRaises(PcapngInterfaceStatisticsError):
                    self.inspect(raw)

    def test_cancellation_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "cancel.pcapng"
            path.write_bytes(section("<") + interface("<"))
            capture = validate_capture(path)
            cancelled = threading.Event()
            cancelled.set()
            with self.assertRaises(PcapngInterfaceStatisticsError):
                inspect_pcapng_interface_statistics(
                    capture,
                    cancel_event=cancelled,
                )


if __name__ == "__main__":
    unittest.main()
