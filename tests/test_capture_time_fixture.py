import importlib.util
import struct
import unittest
from pathlib import Path


class CaptureTimeFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = (
            Path(__file__).resolve().parents[1]
            / "tests"
            / "portable_build"
            / "generate_capture_time_fixture.py"
        )
        specification = importlib.util.spec_from_file_location(
            "capture_time_fixture",
            path,
        )
        if specification is None or specification.loader is None:
            raise RuntimeError("capture-time fixture module could not be loaded")
        cls.fixture = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(cls.fixture)

    def test_fixture_is_deterministic_little_endian_pcapng(self):
        first = self.fixture.build_pcapng()
        second = self.fixture.build_pcapng()

        self.assertEqual(first, second)
        self.assertGreater(len(first), 500)
        self.assertEqual(first[:4], bytes.fromhex("0a0d0d0a"))
        self.assertEqual(first[8:12], bytes.fromhex("4d3c2b1a"))

    def test_fixture_has_one_interface_and_four_enhanced_packets(self):
        raw = self.fixture.build_pcapng()
        offset = 0
        block_types = []
        timestamps = []
        while offset < len(raw):
            block_type, total_length = struct.unpack_from("<II", raw, offset)
            self.assertGreaterEqual(total_length, 12)
            self.assertEqual(total_length % 4, 0)
            trailing = struct.unpack_from(
                "<I",
                raw,
                offset + total_length - 4,
            )[0]
            self.assertEqual(trailing, total_length)
            block_types.append(block_type)
            if block_type == self.fixture.EPB:
                high, low = struct.unpack_from("<II", raw, offset + 12)
                timestamps.append((high << 32) | low)
            offset += total_length

        self.assertEqual(offset, len(raw))
        self.assertEqual(
            block_types,
            [
                self.fixture.SHB,
                self.fixture.IDB,
                self.fixture.EPB,
                self.fixture.EPB,
                self.fixture.EPB,
                self.fixture.EPB,
            ],
        )
        self.assertEqual(
            [value - timestamps[0] for value in timestamps],
            [0, 250_000, 1_500_000, 3_000_000],
        )

    def test_sensitive_metadata_and_absolute_time_canaries_are_present(self):
        raw = self.fixture.build_pcapng()
        source = self.fixture._source_module()

        for value in (
            self.fixture.PRIVATE_SECTION_COMMENT,
            self.fixture.PRIVATE_HARDWARE,
            self.fixture.PRIVATE_OPERATING_SYSTEM,
            self.fixture.PRIVATE_APPLICATION,
            self.fixture.PRIVATE_INTERFACE_NAME,
            self.fixture.PRIVATE_INTERFACE_DESCRIPTION,
            self.fixture.PRIVATE_PACKET_COMMENT,
            source._CLIENT_MAC,
            source._GATEWAY_MAC,
            source._DNS_MAC,
            source._CLIENT_IP,
            source._GATEWAY_IP,
            source._DNS_IP,
            struct.pack("<Q", self.fixture.BASE_TIMESTAMP_TICKS),
        ):
            self.assertIn(value, raw)

    def test_no_capture_file_is_committed(self):
        root = Path(__file__).resolve().parents[1]
        self.assertFalse(any(root.rglob("*.pcap")))
        self.assertFalse(any(root.rglob("*.pcapng")))


if __name__ == "__main__":
    unittest.main()
