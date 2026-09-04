import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path

from wlan_troubleshooter_ko.analysis.preflight import inspect_capture_structure
from wlan_troubleshooter_ko.core.capture import validate_capture


class PortableEventFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        support = Path(__file__).resolve().parents[1] / "tests" / "portable_build"
        cls.ethernet = cls._load_module(
            "portable_event_fixture",
            support / "generate_event_fixture.py",
        )
        cls.wireless = cls._load_module(
            "portable_wireless_event_fixture",
            support / "generate_wireless_event_fixture.py",
        )

    @staticmethod
    def _load_module(name, path):
        specification = importlib.util.spec_from_file_location(name, path)
        if specification is None or specification.loader is None:
            raise RuntimeError("event fixture module could not be loaded")
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        return module

    def _inspect(self, data, name):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / name
            path.write_bytes(data)
            capture = validate_capture(path)
            structure = inspect_capture_structure(capture)
        return capture, structure

    def test_generated_ethernet_fixture_is_valid_and_complete(self):
        capture, structure = self._inspect(
            self.ethernet.build_pcap(),
            "event-fixture.pcap",
        )

        self.assertEqual(capture.capture_format, "pcap")
        self.assertEqual(structure.interfaces[0].link_type, 1)
        self.assertEqual(structure.packets_scanned, 16)
        self.assertEqual(structure.truncated_packets_observed, 0)
        self.assertTrue(structure.scan_complete)

    def test_generated_wireless_fixture_is_valid_and_complete(self):
        raw = self.wireless.build_pcap()
        capture, structure = self._inspect(raw, "wireless-event-fixture.pcap")

        self.assertEqual(capture.capture_format, "pcap")
        self.assertEqual(structure.interfaces[0].link_type, 127)
        self.assertEqual(structure.packets_scanned, 8)
        self.assertEqual(structure.truncated_packets_observed, 0)
        self.assertTrue(structure.scan_complete)

        first_record_offset = 24
        _seconds, _micros, captured_length, original_length = struct.unpack_from(
            "<IIII",
            raw,
            first_record_offset,
        )
        self.assertEqual(captured_length, original_length)
        radiotap = raw[first_record_offset + 16 : first_record_offset + 24]
        self.assertEqual(radiotap, struct.pack("<BBHI", 0, 0, 8, 0))

    def test_fixtures_are_deterministic_and_nonempty(self):
        for module in (self.ethernet, self.wireless):
            first = module.build_pcap()
            second = module.build_pcap()
            self.assertEqual(first, second)
            self.assertGreater(len(first), 200)


if __name__ == "__main__":
    unittest.main()
