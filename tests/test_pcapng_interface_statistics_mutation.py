import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from wlan_troubleshooter_ko.analysis.pcapng_interface_statistics import (
    PcapngInterfaceStatisticsError,
    inspect_pcapng_interface_statistics,
)
from wlan_troubleshooter_ko.core.capture import CaptureInfo, validate_capture


def block(block_type: int, body: bytes) -> bytes:
    total = 12 + len(body)
    return (
        struct.pack("<II", block_type, total)
        + body
        + struct.pack("<I", total)
    )


def minimal_pcapng() -> bytes:
    section_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    interface_body = struct.pack("<HHI", 1, 0, 65535)
    return block(0x0A0D0D0A, section_body) + block(1, interface_body)


class PcapngInterfaceStatisticsMutationTests(unittest.TestCase):
    def test_changed_capture_after_scan_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "private.pcapng"
            path.write_bytes(minimal_pcapng())
            expected = validate_capture(path)
            changed = CaptureInfo(
                path=expected.path,
                capture_format=expected.capture_format,
                size_bytes=expected.size_bytes,
                sha256="f" * 64,
            )

            with mock.patch(
                "wlan_troubleshooter_ko.analysis.pcapng_interface_statistics.validate_capture",
                side_effect=(expected, changed),
            ):
                with self.assertRaises(PcapngInterfaceStatisticsError):
                    inspect_pcapng_interface_statistics(expected)

    def test_changed_capture_before_scan_is_rejected_without_reading_statistics(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "private.pcapng"
            path.write_bytes(minimal_pcapng())
            expected = validate_capture(path)
            changed = CaptureInfo(
                path=expected.path,
                capture_format=expected.capture_format,
                size_bytes=expected.size_bytes + 4,
                sha256=expected.sha256,
            )

            with mock.patch(
                "wlan_troubleshooter_ko.analysis.pcapng_interface_statistics.validate_capture",
                return_value=changed,
            ):
                with self.assertRaises(PcapngInterfaceStatisticsError):
                    inspect_pcapng_interface_statistics(expected)


if __name__ == "__main__":
    unittest.main()
