import inspect
import unittest

from wlan_troubleshooter_ko.analysis.device_sessions import (
    DeviceSessionError,
    _normalize_mac,
    build_device_sessions,
)


class DeviceNonUnicastAddressTests(unittest.TestCase):
    def test_zero_broadcast_and_multicast_addresses_are_ignored(self):
        values = (
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
            "FF-FF-FF-FF-FF-FF",
            "ffff.ffff.ffff",
            "01:00:5e:00:00:fb",
            "33:33:00:00:00:01",
        )
        for value in values:
            with self.subTest(value=value):
                self.assertIsNone(_normalize_mac(value, "L2 주소"))

    def test_valid_unicast_is_normalized_without_serialization_side_effects(self):
        expected = bytes.fromhex("020000000010")
        for value in (
            "02:00:00:00:00:10",
            "02-00-00-00-00-10",
            "0200.0000.0010",
            "020000000010",
        ):
            with self.subTest(value=value):
                self.assertEqual(_normalize_mac(value, "L2 주소"), expected)

    def test_malformed_address_still_fails_closed(self):
        for value in ("not-a-mac", "02:00:00:00:00", "02:00:00:00:00:gg"):
            with self.subTest(value=value):
                with self.assertRaises(DeviceSessionError):
                    _normalize_mac(value, "L2 주소")

    def test_device_session_builder_has_one_explicit_public_boundary(self):
        signature = inspect.signature(build_device_sessions)
        self.assertEqual(
            tuple(signature.parameters),
            ("text", "profile", "transaction_sessions", "expected_frames"),
        )
        self.assertEqual(
            signature.parameters["expected_frames"].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )


if __name__ == "__main__":
    unittest.main()
