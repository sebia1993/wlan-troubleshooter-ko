import hashlib
import stat
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


def windows_fast_lstat_without_file_identity(original_lstat):
    """Windows 경로 fast-path처럼 일반 파일의 비보장 ID 필드를 비운다."""

    def incomplete_lstat(path):
        file_stat = original_lstat(path)
        if not stat.S_ISREG(file_stat.st_mode):
            return file_stat
        return mock.Mock(
            st_dev=0,
            st_ino=0,
            st_mode=file_stat.st_mode,
            st_nlink=0,
            st_size=file_stat.st_size,
            st_mtime=file_stat.st_mtime,
            st_ctime=file_stat.st_ctime,
            st_mtime_ns=file_stat.st_mtime_ns,
            st_ctime_ns=file_stat.st_ctime_ns,
            st_file_attributes=getattr(file_stat, "st_file_attributes", 0) or 0,
        )

    return incomplete_lstat


def windows_fast_path_stat_without_file_identity(original_stat):
    """Path.stat 결과만 Windows fast-path 형태로 만드는 회귀용 래퍼."""

    def incomplete_stat(path, *args, **kwargs):
        file_stat = original_stat(path, *args, **kwargs)
        if not stat.S_ISREG(file_stat.st_mode):
            return file_stat
        return mock.Mock(
            st_dev=0,
            st_ino=0,
            st_mode=file_stat.st_mode,
            st_nlink=0,
            st_size=file_stat.st_size,
            st_mtime=file_stat.st_mtime,
            st_ctime=file_stat.st_ctime,
            st_mtime_ns=file_stat.st_mtime_ns,
            st_ctime_ns=file_stat.st_ctime_ns,
            st_file_attributes=getattr(file_stat, "st_file_attributes", 0) or 0,
        )

    return incomplete_stat


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

    def test_windows_incomplete_path_stat_uses_reopened_handle_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "synthetic.pcap"
            path.write_bytes(PCAP_HEADER)
            original_lstat = capture_module.os.lstat

            with mock.patch.object(
                capture_module.os,
                "lstat",
                side_effect=windows_fast_lstat_without_file_identity(original_lstat),
            ):
                result = validate_capture(path)

            self.assertEqual(result.capture_format, "pcap")
            self.assertEqual(result.sha256, hashlib.sha256(PCAP_HEADER).hexdigest())

    def test_windows_incomplete_path_stat_is_not_compared_with_fstat(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "fast-path.pcap"
            path.write_bytes(PCAP_HEADER)
            original_stat = Path.stat

            with mock.patch.object(
                Path,
                "stat",
                new=windows_fast_path_stat_without_file_identity(original_stat),
            ):
                result = validate_capture(path)

            self.assertEqual(result.capture_format, "pcap")
            self.assertEqual(result.size_bytes, len(PCAP_HEADER))

    def test_path_replacement_during_hash_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "replaced.pcap"
            path.write_bytes(PCAP_HEADER)
            original_hash = capture_module._sha256_handle

            def hash_then_replace(handle, cancel_event, chunk_size):
                digest = original_hash(handle, cancel_event, chunk_size)
                try:
                    path.unlink()
                    path.write_bytes(PCAP_HEADER)
                except OSError:
                    raise unittest.SkipTest("open-file replacement is unavailable")
                return digest

            with mock.patch.object(
                capture_module,
                "_sha256_handle",
                side_effect=hash_then_replace,
            ):
                with self.assertRaises(CaptureValidationError):
                    validate_capture(path)

    def test_path_replacement_after_primary_handle_close_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "late-replacement.pcap"
            path.write_bytes(PCAP_HEADER)
            replacement = bytes.fromhex("a1b2c3d4") + bytes(20)
            original_open = capture_module._open_regular_readonly
            open_count = 0

            def replace_before_final_path_open(candidate):
                nonlocal open_count
                open_count += 1
                if open_count == 4:
                    try:
                        path.unlink()
                        path.write_bytes(replacement)
                    except OSError:
                        raise unittest.SkipTest("late file replacement is unavailable")
                return original_open(candidate)

            with mock.patch.object(
                capture_module,
                "_open_regular_readonly",
                side_effect=replace_before_final_path_open,
            ):
                with self.assertRaises(CaptureValidationError):
                    validate_capture(path)

            self.assertEqual(path.read_bytes(), replacement)

    def test_reopened_handle_with_different_identity_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "reopened.pcap"
            path.write_bytes(PCAP_HEADER)
            with path.open("rb") as handle:
                original = capture_module.os.fstat(handle.fileno())
                replaced = mock.Mock(
                    st_dev=original.st_dev,
                    st_ino=original.st_ino + 1,
                    st_mode=original.st_mode,
                    st_nlink=original.st_nlink,
                    st_size=original.st_size,
                    st_mtime=original.st_mtime,
                    st_ctime=original.st_ctime,
                    st_mtime_ns=original.st_mtime_ns,
                    st_ctime_ns=original.st_ctime_ns,
                    st_file_attributes=0,
                )
                with mock.patch.object(
                    capture_module.os,
                    "fstat",
                    side_effect=(original, replaced),
                ):
                    with self.assertRaises(CaptureValidationError):
                        capture_module._stable_file_stats(path, handle)

    def test_windows_reparse_attribute_on_capture_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "reparse.pcap"
            path.write_bytes(PCAP_HEADER)
            original_lstat = capture_module.os.lstat

            def reparse_lstat(candidate):
                file_stat = original_lstat(candidate)
                if Path(candidate) != path:
                    return file_stat
                return mock.Mock(
                    st_mode=file_stat.st_mode,
                    st_file_attributes=0x400,
                )

            with mock.patch.object(
                capture_module.os,
                "lstat",
                side_effect=reparse_lstat,
            ):
                with self.assertRaises(CaptureValidationError):
                    validate_capture(path)

    def test_path_metadata_error_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "metadata-error.pcap"
            path.write_bytes(PCAP_HEADER)

            with mock.patch.object(
                capture_module.os,
                "lstat",
                side_effect=OSError("synthetic metadata failure"),
            ):
                with self.assertRaises(CaptureValidationError):
                    validate_capture(path)


if __name__ == "__main__":
    unittest.main()
