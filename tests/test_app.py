import struct
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from wlan_troubleshooter_ko.app import self_check
from wlan_troubleshooter_ko.ui.main_window import CaptureViewModel, MainWindow


def minimal_pcap():
    return bytes.fromhex("d4c3b2a1") + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)


class AppSmokeTests(unittest.TestCase):
    def test_self_check_without_window_or_network(self):
        result = self_check()
        self.assertEqual(result["phase"], "2B")
        self.assertEqual(result["runtime_dependencies"], "0")
        self.assertEqual(result["network_features"], "없음")
        self.assertEqual(result["field_profile_version"], "0.2.0")
        self.assertEqual(result["inventory_field_count"], "5")
        self.assertEqual(result["protocol_group_count"], "12")
        self.assertIn("프로토콜 인벤토리", result["analysis_features"])

    def test_view_model_does_not_need_tk_root(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory).resolve() / "synthetic.pcap"
            capture.write_bytes(minimal_pcap())
            view_model = CaptureViewModel()

            state = view_model.select_capture(str(capture))

            self.assertTrue(state.valid)
            self.assertIn("캡처 유형 추정", state.detail)
            self.assertIn("프로토콜 존재 인벤토리", state.detail)
            self.assertNotIn(str(capture), state.detail)
            self.assertIsNotNone(view_model.structure)
            self.assertIsNotNone(view_model.capabilities)

    @mock.patch("wlan_troubleshooter_ko.ui.main_window.validate_capture")
    def test_unexpected_file_error_is_safely_hidden(self, validate_mock):
        validate_mock.side_effect = OSError("/private/customer/capture.pcap")
        state = CaptureViewModel().select_capture("ignored.pcap")
        self.assertFalse(state.valid)
        self.assertNotIn("customer", state.detail)

    def test_window_close_cancels_once_and_destroys_root(self):
        window = object.__new__(MainWindow)
        window._closed = False
        window._selection_generation = 3
        window._validation_cancel = threading.Event()
        window._root = mock.Mock()

        window._close()
        window._close()

        self.assertTrue(window._validation_cancel.is_set())
        self.assertEqual(window._selection_generation, 4)
        window._root.destroy.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
