import hashlib
import json
import os
import stat
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from wlan_troubleshooter_ko.tshark import manifest as manifest_module
from wlan_troubleshooter_ko.tshark import runner as runner_module
from wlan_troubleshooter_ko.tshark.manifest import (
    BundleVerificationError,
    verify_bundle,
)
from wlan_troubleshooter_ko.tshark.policy import (
    TSharkPolicyError,
    assert_safe_argv,
    build_analysis_argv,
)
from wlan_troubleshooter_ko.tshark.runner import (
    TSharkExecutionError,
    build_isolated_environment,
    prepare_fields_invocation,
    probe_bundle_runtime,
)
from wlan_troubleshooter_ko.tshark.status import inspect_bundle


PCAP_HEADER = bytes.fromhex("d4c3b2a1") + bytes(20)


def write_bundle(root: Path, executable_content=b"binary"):
    executable = root / "tshark.exe"
    copying = root / "COPYING"
    executable.write_bytes(executable_content)
    copying.write_text("license", encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "version": "1.2.3-internal",
        "approval_reference": "APPROVAL-TEST",
        "executable": "tshark.exe",
        "files": [
            {
                "path": "tshark.exe",
                "sha256": hashlib.sha256(executable_content).hexdigest(),
                "size_bytes": len(executable_content),
            },
            {
                "path": "COPYING",
                "sha256": hashlib.sha256(b"license").hexdigest(),
                "size_bytes": len(b"license"),
            },
        ],
    }
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def windows_fast_lstat_without_file_identity(original_lstat):
    """Windows 경로 fast-path처럼 일반 파일의 비보장 필드를 0으로 만든다."""

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


class TSharkPolicyTests(unittest.TestCase):
    def test_manifest_and_analysis_arguments_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            vendor = root / "vendor"
            vendor.mkdir()
            write_bundle(vendor)
            bundle = verify_bundle(vendor)
            capture = root / "capture;not-a-command.pcap"
            capture.write_bytes(PCAP_HEADER)

            arguments = build_analysis_argv(
                bundle,
                capture,
                "capture-overview",
                ("frame.number", "frame.protocols"),
            )

            self.assertEqual(arguments.count("-n"), 1)
            self.assertEqual(arguments.count("-r"), 1)
            self.assertIn(str(capture.resolve()), arguments)
            self.assertNotIn("shell", arguments)

    def test_unknown_filter_field_and_live_capture_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            vendor = root / "vendor"
            vendor.mkdir()
            write_bundle(vendor)
            bundle = verify_bundle(vendor)
            capture = root / "capture.pcap"
            capture.write_bytes(PCAP_HEADER)
            with self.assertRaises(TSharkPolicyError):
                build_analysis_argv(bundle, capture, "user-filter", ("frame.number",))
            with self.assertRaises(TSharkPolicyError):
                build_analysis_argv(bundle, capture, "capture-overview", ("tcp.payload",))
            with self.assertRaises(TSharkPolicyError):
                assert_safe_argv(
                    [
                        str(bundle.executable),
                        "-n",
                        "-2",
                        "-r",
                        str(capture.resolve()),
                        "-T",
                        "fields",
                        "-Y",
                        "frame.number >= 1",
                        "-e",
                        "frame.number",
                        "-i",
                        "1",
                    ]
                )
            safe_arguments = build_analysis_argv(
                bundle,
                capture,
                "capture-overview",
                ("frame.number", "frame.protocols"),
            )
            wrong_output_order = list(safe_arguments)
            wrong_output_order[5:8] = ["-Y", "fields", "-T"]
            with self.assertRaises(TSharkPolicyError):
                assert_safe_argv(wrong_output_order)
            duplicate_field = list(safe_arguments) + ["-e", "frame.number"]
            with self.assertRaises(TSharkPolicyError):
                assert_safe_argv(duplicate_field)
            non_string = list(safe_arguments)
            non_string[-1] = 1
            with self.assertRaises(TSharkPolicyError):
                assert_safe_argv(non_string)

    def test_hash_mismatch_and_unlisted_file_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_bundle(root)
            (root / "tshark.exe").write_bytes(b"tampered")
            with self.assertRaises(BundleVerificationError):
                verify_bundle(root)

    def test_size_wrong_executable_and_case_collisions_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_bundle(root)
            manifest_path = root / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"][0]["size_bytes"] += 1
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(BundleVerificationError):
                verify_bundle(root)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_bundle(root)
            manifest_path = root / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["executable"] = "COPYING"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(BundleVerificationError):
                verify_bundle(root)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_bundle(root)
            duplicate = root / "copying"
            duplicate.write_bytes(b"duplicate")
            manifest_path = root / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"].append(
                {
                    "path": "copying",
                    "sha256": hashlib.sha256(b"duplicate").hexdigest(),
                    "size_bytes": len(b"duplicate"),
                }
            )
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(BundleVerificationError):
                verify_bundle(root)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_bundle(root)
            (root / "unknown.dll").write_bytes(b"unknown")
            with self.assertRaises(BundleVerificationError):
                verify_bundle(root)

    def test_child_environment_drops_user_security_hooks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            isolation = root / "isolation"
            env = build_isolated_environment(
                isolation,
                {
                    "SYSTEMROOT": r"C:\\Windows",
                    "SSLKEYLOGFILE": "secret.log",
                    "WIRESHARK_CONFIG_DIR": "user-config",
                    "TEMP": "outside-temp",
                    "UNRELATED_SECRET": "secret",
                },
            )

            self.assertEqual(env["SYSTEMROOT"], r"C:\\Windows")
            self.assertNotIn("SSLKEYLOGFILE", env)
            self.assertNotIn("UNRELATED_SECRET", env)
            self.assertNotEqual(env["WIRESHARK_CONFIG_DIR"], "user-config")
            self.assertNotEqual(env["TEMP"], "outside-temp")
            self.assertEqual(env["LANG"], "C")
            for key in (
                "WIRESHARK_CONFIG_DIR",
                "WIRESHARK_PLUGIN_DIR",
                "WIRESHARK_EXTCAP_DIR",
                "WIRESHARK_DATA_DIR",
            ):
                self.assertTrue(Path(env[key]).is_dir())
                self.assertEqual(list(Path(env[key]).iterdir()), [])

    def test_isolation_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            real = base / "real"
            real.mkdir()
            link = base / "link"
            try:
                link.symlink_to(real, target_is_directory=True)
            except OSError:
                self.skipTest("symlink creation is unavailable on this runner")
            with self.assertRaises(TSharkExecutionError):
                build_isolated_environment(link)

    def test_bundle_and_isolation_reject_symlinked_parent_component(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            real_parent = base / "real"
            vendor = real_parent / "vendor"
            isolation = real_parent / "isolation"
            vendor.mkdir(parents=True)
            write_bundle(vendor)
            linked_parent = base / "linked-parent"
            try:
                linked_parent.symlink_to(real_parent, target_is_directory=True)
            except OSError:
                self.skipTest("symlink creation is unavailable on this runner")

            with self.assertRaises(BundleVerificationError):
                verify_bundle(linked_parent / "vendor")
            with self.assertRaises(TSharkExecutionError):
                build_isolated_environment(linked_parent / "isolation")

    def test_existing_or_prepopulated_isolation_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            isolation = base / "isolation"
            isolation.mkdir()
            with self.assertRaises(TSharkExecutionError):
                build_isolated_environment(isolation)

            plugins = isolation / "plugins"
            plugins.mkdir()
            (plugins / "evil.lua").write_text("print('evil')", encoding="utf-8")
            with self.assertRaises(TSharkExecutionError):
                build_isolated_environment(isolation)

    def test_prepared_isolation_rejects_replaced_child_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            isolation = base / "isolation"
            outside = base / "outside"
            outside.mkdir()
            prepared = runner_module._prepare_isolated_environment(isolation, {})
            config = isolation / "config"
            config.rmdir()
            try:
                config.symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest("symlink creation is unavailable on this runner")

            with self.assertRaises(TSharkExecutionError):
                runner_module._validate_prepared_isolation(prepared)

    def test_windows_reparse_attribute_is_treated_as_link(self):
        reparse_stat = mock.Mock(
            st_mode=stat.S_IFDIR | 0o700,
            st_file_attributes=0x400,
        )
        regular_stat = mock.Mock(
            st_mode=stat.S_IFDIR | 0o700,
            st_file_attributes=None,
        )

        self.assertTrue(manifest_module._stat_is_link_or_reparse(reparse_stat))
        self.assertTrue(runner_module._stat_is_link_or_reparse(reparse_stat))
        self.assertFalse(manifest_module._stat_is_link_or_reparse(regular_stat))
        self.assertFalse(runner_module._stat_is_link_or_reparse(regular_stat))

    def test_windows_incomplete_path_stat_uses_handle_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_bundle(root)
            original_lstat = manifest_module.os.lstat
            with mock.patch.object(
                manifest_module.os,
                "lstat",
                side_effect=windows_fast_lstat_without_file_identity(original_lstat),
            ):
                bundle = verify_bundle(root)
                manifest_module.revalidate_bundle_snapshot(bundle)

            self.assertEqual(bundle.manifest_snapshot[3], 1)
            self.assertTrue(
                all(snapshot[3] == 1 for _path, snapshot in bundle.file_snapshots)
            )

    def test_windows_incomplete_path_stat_still_rejects_hardlink(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "vendor"
            root.mkdir()
            write_bundle(root)
            try:
                os.link(root / "tshark.exe", base / "outside-alias.exe")
            except (OSError, NotImplementedError):
                self.skipTest("hardlink creation is unavailable on this runner")
            original_lstat = manifest_module.os.lstat
            with mock.patch.object(
                manifest_module.os,
                "lstat",
                side_effect=windows_fast_lstat_without_file_identity(original_lstat),
            ):
                with self.assertRaises(BundleVerificationError):
                    verify_bundle(root)

    def test_hash_rejects_file_state_change_between_handle_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve() / "payload.bin"
            target.write_bytes(b"approved")
            original = target.stat()
            changed = mock.Mock(
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
                manifest_module.os,
                "fstat",
                side_effect=(original, original, changed, changed),
            ):
                with self.assertRaises(BundleVerificationError):
                    manifest_module._hash_regular_file_stably(target, original.st_size)

    def test_manifest_rejects_first_file_changed_while_later_file_is_hashed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_bundle(root, b"AAAAAA")
            original_hash = manifest_module._hash_regular_file_stably
            changed = False

            def hash_and_change_first_file(path, expected_size):
                nonlocal changed
                result = original_hash(path, expected_size)
                if path.name == "tshark.exe" and not changed:
                    path.write_bytes(b"BBBBBB")
                    changed = True
                return result

            with mock.patch.object(
                manifest_module,
                "_hash_regular_file_stably",
                side_effect=hash_and_change_first_file,
            ):
                with self.assertRaises(BundleVerificationError):
                    verify_bundle(root)
            self.assertEqual((root / "tshark.exe").read_bytes(), b"BBBBBB")

    def test_bundle_identity_contains_manifest_and_declared_content_digests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            write_bundle(root, b"AAAAAA")
            approved = verify_bundle(root)

            replacement = b"BBBBBB"
            (root / "tshark.exe").write_bytes(replacement)
            manifest_path = root / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"][0]["sha256"] = hashlib.sha256(replacement).hexdigest()
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            replaced = verify_bundle(root)

            self.assertEqual(approved.version, replaced.version)
            self.assertEqual(approved.executable, replaced.executable)
            self.assertEqual(approved.files, replaced.files)
            self.assertNotEqual(approved.manifest_sha256, replaced.manifest_sha256)
            self.assertNotEqual(approved.declared_files, replaced.declared_files)
            self.assertNotEqual(approved, replaced)

    def test_hardlinked_bundle_payload_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            vendor = base / "vendor"
            vendor.mkdir()
            write_bundle(vendor)
            try:
                os.link(vendor / "tshark.exe", base / "outside-alias.exe")
            except (OSError, NotImplementedError):
                self.skipTest("hardlink creation is unavailable on this runner")

            with self.assertRaises(BundleVerificationError):
                verify_bundle(vendor)

    def test_phase_one_prepares_but_does_not_execute_invocation(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            vendor = base / "vendor"
            isolation = base / "isolation"
            vendor.mkdir()
            write_bundle(vendor)
            capture = base / "capture.pcap"
            capture.write_bytes(PCAP_HEADER)

            prepared = prepare_fields_invocation(vendor, capture, isolation)

            self.assertIsInstance(prepared.arguments, tuple)
            self.assertEqual(prepared.arguments.count("-r"), 1)
            self.assertEqual(prepared.environment["LANG"], "C")

    @mock.patch("wlan_troubleshooter_ko.tshark.runner.subprocess.Popen")
    def test_runtime_probe_uses_only_fixed_no_capture_arguments(self, popen_mock):
        process = mock.Mock()
        process.wait.return_value = 0
        popen_mock.return_value = process
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            vendor = root / "vendor"
            isolation = root / "isolation"
            vendor.mkdir()
            write_bundle(vendor)

            version = probe_bundle_runtime(vendor, isolation)

        self.assertEqual(version, "1.2.3-internal")
        positional, keywords = popen_mock.call_args
        self.assertEqual(positional[0][1:], ["-n", "-v"])
        self.assertNotIn("-r", positional[0])
        self.assertIs(keywords["shell"], False)
        self.assertEqual(keywords["stdout"], subprocess.DEVNULL)

    @mock.patch("wlan_troubleshooter_ko.tshark.runner.subprocess.Popen")
    def test_runtime_probe_cancellation_terminates_child(self, popen_mock):
        cancel_event = threading.Event()

        class ProbeProcess:
            def __init__(self):
                self.wait_count = 0
                self.terminated = False

            def wait(self, timeout):
                self.wait_count += 1
                if self.wait_count == 1:
                    cancel_event.set()
                    raise subprocess.TimeoutExpired([], timeout)
                return -15

            def poll(self):
                return None if not self.terminated else -15

            def terminate(self):
                self.terminated = True

            def kill(self):
                self.terminated = True

        process = ProbeProcess()
        popen_mock.return_value = process
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            vendor = root / "vendor"
            isolation = root / "isolation"
            vendor.mkdir()
            write_bundle(vendor)
            with self.assertRaises(TSharkExecutionError):
                probe_bundle_runtime(vendor, isolation, cancel_event=cancel_event)

        self.assertTrue(process.terminated)

    @mock.patch("wlan_troubleshooter_ko.tshark.runner.subprocess.Popen")
    def test_runtime_probe_revalidates_bundle_before_process_start(self, popen_mock):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            vendor = root / "vendor"
            isolation = root / "isolation"
            vendor.mkdir()
            write_bundle(vendor)
            initial_bundle = verify_bundle(vendor)
            with mock.patch.object(
                runner_module,
                "verify_bundle",
                side_effect=(
                    initial_bundle,
                    BundleVerificationError("changed"),
                ),
            ) as verify_mock:
                with self.assertRaises(BundleVerificationError):
                    probe_bundle_runtime(vendor, isolation)

        self.assertEqual(verify_mock.call_count, 2)
        popen_mock.assert_not_called()

    @mock.patch("wlan_troubleshooter_ko.tshark.runner.subprocess.Popen")
    def test_runtime_probe_does_not_start_if_cancelled_during_validation(self, popen_mock):
        cancel_event = threading.Event()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            vendor = root / "vendor"
            isolation = root / "isolation"
            vendor.mkdir()
            write_bundle(vendor)
            bundle = verify_bundle(vendor)
            verify_count = 0

            def verify_and_cancel(_vendor_root):
                nonlocal verify_count
                verify_count += 1
                if verify_count == 2:
                    cancel_event.set()
                return bundle

            with mock.patch.object(
                runner_module,
                "verify_bundle",
                side_effect=verify_and_cancel,
            ):
                with self.assertRaises(TSharkExecutionError):
                    probe_bundle_runtime(vendor, isolation, cancel_event=cancel_event)

        popen_mock.assert_not_called()

    @mock.patch("wlan_troubleshooter_ko.tshark.runner.subprocess.Popen")
    def test_runtime_probe_deadline_includes_prelaunch_validation(self, popen_mock):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            vendor = root / "vendor"
            isolation = root / "isolation"
            vendor.mkdir()
            write_bundle(vendor)
            with mock.patch.object(
                runner_module.time,
                "monotonic",
                side_effect=(100.0, 111.0),
            ):
                with self.assertRaises(TSharkExecutionError):
                    probe_bundle_runtime(vendor, isolation, timeout_seconds=10)

        popen_mock.assert_not_called()

    @mock.patch("wlan_troubleshooter_ko.tshark.runner.subprocess.Popen")
    def test_runtime_probe_rejects_lua_injected_after_isolation_creation(self, popen_mock):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            vendor = root / "vendor"
            isolation = root / "isolation"
            vendor.mkdir()
            write_bundle(vendor)
            bundle = verify_bundle(vendor)
            verify_count = 0

            def verify_and_inject(_vendor_root):
                nonlocal verify_count
                verify_count += 1
                if verify_count == 2:
                    (isolation / "plugins" / "evil.lua").write_text(
                        "print('evil')",
                        encoding="utf-8",
                    )
                return bundle

            with mock.patch.object(
                runner_module,
                "verify_bundle",
                side_effect=verify_and_inject,
            ):
                with self.assertRaises(TSharkExecutionError):
                    probe_bundle_runtime(vendor, isolation)

        popen_mock.assert_not_called()

    @mock.patch("wlan_troubleshooter_ko.tshark.runner.subprocess.Popen")
    def test_runtime_probe_rejects_same_version_replacement_bundle(self, popen_mock):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            vendor = root / "vendor"
            isolation = root / "isolation"
            vendor.mkdir()
            write_bundle(vendor, b"AAAAAA")
            approved = verify_bundle(vendor)
            replacement = b"BBBBBB"
            (vendor / "tshark.exe").write_bytes(replacement)
            manifest_path = vendor / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"][0]["sha256"] = hashlib.sha256(replacement).hexdigest()
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            replaced = verify_bundle(vendor)

            with mock.patch.object(
                runner_module,
                "verify_bundle",
                side_effect=(approved, replaced),
            ):
                with self.assertRaises(TSharkExecutionError):
                    probe_bundle_runtime(vendor, isolation)

        popen_mock.assert_not_called()

    @mock.patch("wlan_troubleshooter_ko.tshark.runner.subprocess.Popen")
    def test_runtime_probe_rechecks_file_snapshot_immediately_before_start(self, popen_mock):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            vendor = root / "vendor"
            isolation = root / "isolation"
            vendor.mkdir()
            write_bundle(vendor, b"AAAAAA")
            original_validate = runner_module._validate_prepared_isolation

            def validate_then_change_bundle(prepared):
                original_validate(prepared)
                (vendor / "tshark.exe").write_bytes(b"BBBBBB")

            with mock.patch.object(
                runner_module,
                "_validate_prepared_isolation",
                side_effect=validate_then_change_bundle,
            ):
                with self.assertRaises(BundleVerificationError):
                    probe_bundle_runtime(vendor, isolation)

        popen_mock.assert_not_called()

    def test_bundle_status_distinguishes_missing_invalid_and_integrity_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self.assertEqual(inspect_bundle(root).code, "not_provisioned")
            (root / "manifest.json").write_text("{}", encoding="utf-8")
            self.assertEqual(inspect_bundle(root).code, "integrity_error")
            for child in tuple(root.iterdir()):
                child.unlink()
            write_bundle(root)
            verified = inspect_bundle(root)
            self.assertEqual(verified.code, "integrity_verified")
            self.assertIn("실행 준비 확인 전", verified.message)

    def test_field_order_is_canonical_even_for_unordered_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            vendor = root / "vendor"
            vendor.mkdir()
            write_bundle(vendor)
            bundle = verify_bundle(vendor)
            capture = root / "capture.pcap"
            capture.write_bytes(PCAP_HEADER)
            arguments = build_analysis_argv(
                bundle,
                capture,
                "capture-overview",
                {"frame.protocols", "frame.number"},
            )
            fields = [arguments[index + 1] for index, item in enumerate(arguments) if item == "-e"]
            self.assertEqual(fields, ["frame.number", "frame.protocols"])


if __name__ == "__main__":
    unittest.main()
