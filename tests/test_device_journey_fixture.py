import importlib.util
import unittest
from pathlib import Path


class DeviceJourneyFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        support = Path(__file__).resolve().parents[1] / "tests" / "portable_build"
        cls.shared = cls._load("shared_event_fixture", support / "generate_event_fixture.py")
        cls.journey = cls._load(
            "device_journey_fixture",
            support / "generate_device_journey_fixture.py",
        )

    @staticmethod
    def _load(name, path):
        specification = importlib.util.spec_from_file_location(name, path)
        if specification is None or specification.loader is None:
            raise RuntimeError("fixture module could not be loaded")
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        return module

    def test_only_radius_ethernet_headers_use_distinct_nad(self):
        shared = dict(self.shared.frames())
        journey = dict(self.journey.frames())

        self.assertEqual(set(shared), set(journey))
        for number in shared:
            with self.subTest(frame=number):
                if number not in {6, 7}:
                    self.assertEqual(journey[number], shared[number])

        nad = self.journey.NAD_MAC
        self.assertEqual(journey[6][6:12], nad)
        self.assertEqual(journey[7][0:6], nad)
        self.assertNotEqual(journey[6][6:12], self.shared.CLIENT_MAC)
        self.assertNotEqual(journey[7][0:6], self.shared.CLIENT_MAC)
        self.assertEqual(journey[6][12:], shared[6][12:])
        self.assertEqual(journey[7][12:], shared[7][12:])

    def test_fixture_is_deterministic_and_contains_no_real_capture(self):
        first = self.journey.build_pcap()
        second = self.journey.build_pcap()
        self.assertEqual(first, second)
        self.assertGreater(len(first), 500)


if __name__ == "__main__":
    unittest.main()
