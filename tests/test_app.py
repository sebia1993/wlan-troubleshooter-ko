import json
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from wlan_troubleshooter_ko.app import main, self_check
from wlan_troubleshooter_ko.ui.main_window import CaptureViewModel, MainWindow


def minimal_pcap():
    return bytes.fromhex("d4c3b2a1") + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)


class AppSmokeTests(unittest.TestCase):
    def test_self_check_without_window_or_network(self):
        result = self_check()
        self.assertEqual(result["phase"], "4D")
        self.assertEqual(result["runtime_dependencies"], "0")
        self.assertEqual(result["network_features"], "없음")
        self.assertEqual(result["ruleset_version"], "0.2.0")
        self.assertEqual(result["rule_count"], "11")
        self.assertEqual(result["field_profile_version"], "0.4.0")
        self.assertEqual(result["inventory_field_count"], "5")
        self.assertEqual(result["event_field_count"], "32")
        self.assertEqual(result["transaction_session_schema_version"], "1")
        self.assertEqual(result["protocol_group_count"], "12")
        self.assertEqual(result["python_external_required"], "true")
        self.assertEqual(result["tshark_external_required"], "true")
        self.assertIn("거래 시도", result["analysis_features"])

    def test_self_check_can_write_new_local_json_for_windowed_exe(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / "self-check.json"
            result = main(["--self-check-output=" + str(output)])
            self.assertEqual(result, 0)
            value = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(value["network_features"], "없음")
            self.assertEqual(value["python_external_required"], "true")
            self.assertEqual(value["phase"], "4D")
            self.assertEqual(value["transaction_session_schema_version"], "1")
            with self.assertRaises(FileExistsError):
                main(["--self-check-output=" + str(output)])

    def test_self_check_rejects_non_local_output(self):
        with self.assertRaises(ValueError):
            main(["--self-check-output=https://example.invalid/output.json"])

    def test_noninteractive_analysis_writes_path_free_result(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory).resolve() / "private-capture.pcap"
            output = Path(directory).resolve() / "analysis.json"
            capture.write_bytes(minimal_pcap())

            exit_code = main(
                [
                    "--analyze-capture=" + str(capture),
                    "--analysis-output=" + str(output),
                ]
            )
            value = json.loads(output.read_text(encoding="utf-8"))
            rendered = json.dumps(value, ensure_ascii=False)

            self.assertEqual(exit_code, 2)
            self.assertEqual(value["schema_version"], 2)
            self.assertEqual(value["protocol_inventory_state"], "unavailable")
            self.assertNotIn(str(capture), rendered)
            self.assertNotIn(capture.name, rendered)

    def test_noninteractive_analysis_requires_both_paths(self):
        with self.assertRaises(ValueError):
            main(["--analyze-capture=C:/capture.pcap"])
        with self.assertRaises(ValueError):
            main(["--analysis-output=C:/analysis.json"])

    def test_view_model_does_not_need_tk_root(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory).resolve() / "synthetic.pcap"
            capture.write_bytes(minimal_pcap())
            view_model = CaptureViewModel()

            state = view_model.select_capture(str(capture))

            self.assertTrue(state.valid)
            self.assertIn("캡처 유형 추정", state.detail)
            self.assertIn("프로토콜·접속 단계·이벤트·거래 시도 분석", state.detail)
            self.assertIn("거래 시도", state.detail)
            self.assertNotIn(str(capture), state.detail)
            self.assertIsNotNone(view_model.structure)
            self.assertIsNotNone(view_model.capabilities)
            self.assertIsNotNone(view_model.analysis_result)

    @mock.patch("wlan_troubleshooter_ko.ui.main_window.analyze_capture")
    def test_unexpected_file_error_is_safely_hidden(self, analyze_mock):
        analyze_mock.side_effect = OSError("/private/customer/capture.pcap")
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
