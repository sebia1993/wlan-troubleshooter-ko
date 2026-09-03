import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from wlan_troubleshooter_ko.app import self_check
from wlan_troubleshooter_ko.ui.main_window import CaptureViewModel, MainWindow


PCAP_HEADER = bytes.fromhex("d4c3b2a1") + bytes(20)


class AppSmokeTests(unittest.TestCase):
    def test_self_check_without_window_or_network(self):
        result = self_check()
        self.assertEqual(result["phase"], "0-1")
        self.assertEqual(result["runtime_dependencies"], "0")
        self.assertEqual(result["network_features"], "없음")

    def test_view_model_does_not_need_tk_root(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory).resolve() / "synthetic.pcap"
            capture.write_bytes(PCAP_HEADER)
            view_model = CaptureViewModel()

            state = view_model.select_capture(str(capture))

            self.assertTrue(state.valid)
            self.assertIn("Phase 2", state.detail)
            self.assertNotIn(str(capture), state.detail)

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
