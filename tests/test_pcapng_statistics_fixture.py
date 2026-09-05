import importlib.util
import struct
import unittest
from pathlib import Path


class PcapngStatisticsFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = (
            Path(__file__).resolve().parents[1]
            / "tests"
            / "portable_build"
            / "generate_pcapng_statistics_fixture.py"
        )
        specification = importlib.util.spec_from_file_location(
            "pcapng_statistics_fixture",
            path,
        )
        if specification is None or specification.loader is None:
            raise RuntimeError("fixture module could not be loaded")
        cls.fixture = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(cls.fixture)

    def test_fixture_is_deterministic_little_endian_pcapng(self):
        first = self.fixture.build_pcapng()
        second = self.fixture.build_pcapng()

        self.assertEqual(first, second)
        self.assertGreater(len(first), 500)
        self.assertEqual(first[:4], bytes.fromhex("0a0d0d0a"))
        self.assertEqual(first[8:12], bytes.fromhex("4d3c2b1a"))

    def test_fixture_contains_two_epbs_and_two_isbs(self):
        raw = self.fixture.build_pcapng()
        offset = 0
        block_types = []
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
            offset += total_length

        self.assertEqual(offset, len(raw))
        self.assertEqual(
            block_types,
            [
                self.fixture.SHB,
                self.fixture.IDB,
                self.fixture.EPB,
                self.fixture.ISB,
                self.fixture.EPB,
                self.fixture.ISB,
            ],
        )

    def test_sensitive_metadata_strings_are_present_only_for_leak_testing(self):
        raw = self.fixture.build_pcapng()
        for value in (
            self.fixture.PRIVATE_SECTION_COMMENT,
            self.fixture.PRIVATE_HARDWARE,
            self.fixture.PRIVATE_OS,
            self.fixture.PRIVATE_APPLICATION,
            self.fixture.PRIVATE_INTERFACE_NAME,
            self.fixture.PRIVATE_INTERFACE_DESCRIPTION,
            self.fixture.PRIVATE_PACKET_COMMENT,
            self.fixture.PRIVATE_STATISTICS_COMMENT,
        ):
            self.assertIn(value, raw)
        self.assertIn(self.fixture.CLIENT_MAC, raw)
        self.assertIn(self.fixture.GATEWAY_MAC, raw)
        self.assertIn(self.fixture.CLIENT_IP, raw)
        self.assertIn(self.fixture.GATEWAY_IP, raw)


if __name__ == "__main__":
    unittest.main()
