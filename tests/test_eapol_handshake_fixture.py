import importlib.util
import struct
import unittest
from pathlib import Path


class EapolHandshakeFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = (
            Path(__file__).resolve().parents[1]
            / "tests"
            / "portable_build"
            / "generate_eapol_handshake_fixture.py"
        )
        specification = importlib.util.spec_from_file_location(
            "eapol_handshake_fixture",
            path,
        )
        if specification is None or specification.loader is None:
            raise RuntimeError("fixture module could not be loaded")
        cls.fixture = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(cls.fixture)

    def test_fixture_is_deterministic_pcap_with_radiotap_link_type(self):
        first = self.fixture.build_pcap()
        second = self.fixture.build_pcap()

        self.assertEqual(first, second)
        self.assertGreater(len(first), 700)
        self.assertEqual(first[:4], bytes.fromhex("d4c3b2a1"))
        self.assertEqual(struct.unpack_from("<I", first, 20)[0], 127)

    def test_message_pattern_and_retry_bit_are_explicit(self):
        frames = tuple(self.fixture.frames())
        self.assertEqual(len(frames), 9)
        self.assertEqual([timestamp for timestamp, _frame in frames], list(range(1, 10)))

        key_frames = frames[4:]
        self.assertEqual(len(key_frames), 5)
        retry_frame_control = struct.unpack_from("<H", key_frames[3][1], 0)[0]
        self.assertTrue(retry_frame_control & 0x0800)
        for index, (_timestamp, frame) in enumerate(key_frames):
            if index != 3:
                frame_control = struct.unpack_from("<H", frame, 0)[0]
                self.assertFalse(frame_control & 0x0800)

    def test_all_addresses_and_key_bytes_are_synthetic_constants(self):
        self.assertEqual(self.fixture.STATION, bytes.fromhex("0200000000c1"))
        self.assertEqual(self.fixture.ACCESS_POINT, bytes.fromhex("0200000000d1"))
        self.assertNotEqual(self.fixture.STATION, self.fixture.ACCESS_POINT)
        for message in (1, 2, 3, 4):
            descriptor = self.fixture._key_descriptor(message, message)
            self.assertEqual(len(descriptor), 95)


if __name__ == "__main__":
    unittest.main()
