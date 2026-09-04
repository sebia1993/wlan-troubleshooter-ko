import importlib.util
import tempfile
import unittest
from pathlib import Path

from wlan_troubleshooter_ko.analysis.preflight import inspect_capture_structure
from wlan_troubleshooter_ko.core.capture import validate_capture


class PortableEventFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = (
            Path(__file__).resolve().parents[1]
            / "tests"
            / "portable_build"
            / "generate_event_fixture.py"
        )
        specification = importlib.util.spec_from_file_location(
            "portable_event_fixture",
            path,
        )
        if specification is None or specification.loader is None:
            raise RuntimeError("event fixture module could not be loaded")
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        cls.module = module

    def test_generated_fixture_is_valid_complete_ethernet_pcap(self):
        data = self.module.build_pcap()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "event-fixture.pcap"
            path.write_bytes(data)
            capture = validate_capture(path)
            structure = inspect_capture_structure(capture)

        self.assertEqual(capture.capture_format, "pcap")
        self.assertEqual(structure.interfaces[0].link_type, 1)
        self.assertEqual(structure.packets_scanned, 16)
        self.assertEqual(structure.truncated_packets_observed, 0)
        self.assertTrue(structure.scan_complete)

    def test_fixture_is_deterministic_and_contains_no_external_dependency(self):
        first = self.module.build_pcap()
        second = self.module.build_pcap()
        self.assertEqual(first, second)
        self.assertGreater(len(first), 1000)


if __name__ == "__main__":
    unittest.main()
