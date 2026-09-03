import hashlib
import threading
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from wlan_troubleshooter_ko.core import capture as capture_module
from wlan_troubleshooter_ko.core.capture import CaptureValidationError, validate_capture


PCAP_HEADER = bytes.fromhex("d4c3b2a1") + bytes(20)
PCAPNG_HEADER = (
    bytes.fromhex("0a0d0d0a")
    + bytes.fromhex("1c000000")
    + bytes.fromhex("4d3c2b1a")
    + bytes.fromhex("01000000")
    + bytes.fromhex("ffffffffffffffff")
    + bytes.fromhex("1c000000")
)
PCAPNG_HEADER_WITH_OPTION = (
    bytes.fromhex("0a0d0d0a")
    + bytes.fromhex("20000000")
    + bytes.fromhex("4d3c2b1a")
    + bytes.fromhex("01000000")
    + bytes.fromhex("ffffffffffffffff")
    + bytes.fromhex("00000000")
    + bytes.fromhex("20000000")
)


class CaptureValidationTests(unittest.TestCase):
    def test_valid_pcap_is_identified_and_hashed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "synthetic.pcap"
            path.write_bytes(PCAP_HEADER)

            result = validate_capture(path)

            self.assertEqual(result.capture_format, "pcap")
            self.assertEqual(result.size_bytes, len(PCAP_HEADER))
            self.assertEqual(result.sha256, hashlib.sha256(PCAP_HEADER).hexdigest())

    def test_valid_pcapng_is_identified(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "synthetic.pcapng"
            path.write_bytes(PCAPNG_HEADER)

            self.assertEqual(validate_capture(path).capture_format, "pcapng")

    def test_extended_pcapng_header_is_valid_and_declared_truncation_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            valid = root / "extended.pcapng"
            valid.write_bytes(PCAPNG_HEADER_WITH_OPTION)
            self.assertEqual(validate_capture(valid).capture_format, "pcapng")

            truncated = root / "truncated.pcapng"
            truncated.write_bytes(PCAPNG_HEADER_WITH_OPTION[:28])
            with self.assertRaises(CaptureValidationError):
                validate_capture(truncated)

    def test_extension_only_is_not_trusted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "not-a-capture.pcap"
            path.write_text("plain text", encoding="utf-8")

            with self.assertRaises(CaptureValidationError):
                validate_capture(path)

    def test_truncated_header_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "truncated.pcap"
            path.write_bytes(PCAP_HEADER[:8])

            with self.assertRaises(CaptureValidationError):
                validate_capture(path)

    def test_extension_mismatch_and_remote_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            mismatch = Path(directory).resolve() / "capture.pcapng"
            mismatch.write_bytes(PCAP_HEADER)
            with self.assertRaises(CaptureValidationError):
                validate_capture(mismatch)

        with self.assertRaises(CaptureValidationError):
            validate_capture("rpcap://capture.pcap")
        with self.assertRaises(CaptureValidationError):
            validate_capture(r"\\server\share\capture.pcap")
        with self.assertRaises(CaptureValidationError):
            validate_capture("//server/share/capture.pcap")

    def test_parent_symlink_and_pre_cancelled_validation_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            real = root / "real"
            real.mkdir()
            capture = real / "capture.pcap"
            capture.write_bytes(PCAP_HEADER)
            alias = root / "alias"
            try:
                alias.symlink_to(real, target_is_directory=True)
            except OSError:
                self.skipTest("symlink creation is unavailable on this runner")
            with self.assertRaises(CaptureValidationError):
                validate_capture(alias / "capture.pcap")

            cancelled = threading.Event()
            cancelled.set()
            with self.assertRaises(CaptureValidationError):
                validate_capture(capture, cancel_event=cancelled)

    def test_same_size_in_place_change_during_hash_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "changing.pcap"
            path.write_bytes(PCAP_HEADER)
            original_hash = capture_module._sha256_handle

            def hash_then_change(handle, cancel_event, chunk_size):
                digest = original_hash(handle, cancel_event, chunk_size)
                try:
                    path.write_bytes(bytes.fromhex("a1b2c3d4") + bytes(20))
                except OSError:
                    raise unittest.SkipTest("in-place replacement is unavailable")
                return digest

            with mock.patch.object(
                capture_module,
                "_sha256_handle",
                side_effect=hash_then_change,
            ):
                with self.assertRaises(CaptureValidationError):
                    validate_capture(path)


if __name__ == "__main__":
    unittest.main()
