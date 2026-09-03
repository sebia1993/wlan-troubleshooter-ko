import gzip
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import audit_repository


class RepositoryAuditTests(unittest.TestCase):
    def _git(self, root: Path, *arguments: str) -> None:
        subprocess.run(
            ["git", "-C", str(root)] + list(arguments),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            shell=False,
        )

    def _init_repository(self, root: Path) -> None:
        self._git(root, "init", "--quiet")

    def test_non_git_tree_detects_capture_extension_case_insensitively(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "Nested").mkdir()
            (root / "Nested" / "Evidence.PCAPNG").write_bytes(b"not capture data")
            report = audit_repository.audit_repository(root)
        self.assertEqual("filesystem", report.mode)
        self.assertIn("CAPTURE_EXTENSION", {finding.code for finding in report.findings})

    def test_renamed_capture_magic_is_detected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            magic = bytes.fromhex("d4c3b2a1")
            (root / "innocent.bin").write_bytes(magic + bytes(32))
            report = audit_repository.audit_repository(root)
        self.assertIn("CAPTURE_MAGIC", {finding.code for finding in report.findings})

    def test_gzip_wrapped_capture_magic_is_detected_when_renamed(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            magic = bytes.fromhex("0a0d0d0a")
            with gzip.open(str(root / "archive.bin"), "wb") as handle:
                handle.write(magic + bytes(32))
            report = audit_repository.audit_repository(root)
        self.assertIn("CAPTURE_MAGIC", {finding.code for finding in report.findings})

    def test_private_profile_path_is_detected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "profiles" / "local" / "office.json"
            target.parent.mkdir(parents=True)
            target.write_text("{}", encoding="utf-8")
            report = audit_repository.audit_repository(root)
        self.assertIn("PRIVATE_PROFILE_PATH", {finding.code for finding in report.findings})

    def test_private_profile_filename_is_detected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "profiles" / "private.json"
            target.parent.mkdir(parents=True)
            target.write_text("{}", encoding="utf-8")
            report = audit_repository.audit_repository(root)
        self.assertIn("PRIVATE_PROFILE_PATH", {finding.code for finding in report.findings})

    def test_synthetic_example_profile_is_allowed(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "profiles" / "site-default.example.json"
            target.parent.mkdir(parents=True)
            target.write_text(
                '{"schema_version":1,"profile_version":"test",'
                '"profile_id":"SYNTHETIC-EXAMPLE",'
                '"display_name":"문서용 예시 사이트","synthetic":true,'
                '"radius_servers":[],"dhcp_servers":[],"dns_servers":[],"vlans":[]}',
                encoding="utf-8",
            )
            report = audit_repository.audit_repository(root)
        self.assertEqual((), report.findings)

    def test_non_example_or_unmarked_profile_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "profiles" / "site-default.json"
            target.parent.mkdir(parents=True)
            target.write_text('{"synthetic": true}', encoding="utf-8")
            report = audit_repository.audit_repository(root)
        self.assertIn("PRIVATE_PROFILE_PATH", {finding.code for finding in report.findings})

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "profiles" / "site-default.example.json"
            target.parent.mkdir(parents=True)
            target.write_text('{"synthetic": false}', encoding="utf-8")
            report = audit_repository.audit_repository(root)
        self.assertIn(
            "PROFILE_EXAMPLE_NOT_SYNTHETIC",
            {finding.code for finding in report.findings},
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "profiles" / "unsafe.example.json"
            target.parent.mkdir(parents=True)
            target.write_text(
                '{"synthetic":true,"radius_servers":["10.20.30.40"],'
                '"user_id":"employee"}',
                encoding="utf-8",
            )
            report = audit_repository.audit_repository(root)
        self.assertIn(
            "PROFILE_EXAMPLE_NOT_SYNTHETIC",
            {finding.code for finding in report.findings},
        )

    def test_git_mode_scans_tracked_files_and_ignores_untracked_files(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._init_repository(root)
            (root / "README.md").write_text("clean", encoding="utf-8")
            self._git(root, "add", "README.md")
            (root / "untracked.pcap").write_bytes(bytes.fromhex("d4c3b2a1") + bytes(8))

            report = audit_repository.audit_repository(root)

        self.assertEqual("git-tracked", report.mode)
        self.assertEqual(1, report.scanned_files)
        self.assertEqual((), report.findings)

    def test_git_mode_rejects_tracked_capture(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._init_repository(root)
            target = root / "renamed.bin"
            target.write_bytes(bytes.fromhex("a1b2c3d4") + bytes(8))
            self._git(root, "add", "renamed.bin")

            report = audit_repository.audit_repository(root)

        self.assertEqual("git-tracked", report.mode)
        self.assertIn("CAPTURE_MAGIC", {finding.code for finding in report.findings})

    def test_git_mode_reads_the_staged_blob_not_worktree_content(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._init_repository(root)
            target = root / "renamed.bin"
            target.write_bytes(bytes.fromhex("a1b2c3d4") + bytes(8))
            self._git(root, "add", "renamed.bin")
            target.write_text("clean worktree replacement", encoding="utf-8")

            report = audit_repository.audit_repository(root)

        self.assertIn("CAPTURE_MAGIC", {finding.code for finding in report.findings})

    def test_git_mode_reads_staged_profile_marker(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._init_repository(root)
            target = root / "profiles" / "site-default.example.json"
            target.parent.mkdir(parents=True)
            target.write_text('{"synthetic": false}', encoding="utf-8")
            self._git(root, "add", target.relative_to(root).as_posix())
            target.write_text('{"synthetic": true}', encoding="utf-8")

            report = audit_repository.audit_repository(root)

        self.assertIn(
            "PROFILE_EXAMPLE_NOT_SYNTHETIC",
            {finding.code for finding in report.findings},
        )

    def test_generated_output_and_vendor_payload_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._init_repository(root)
            targets = (
                root / "logs" / "application.log",
                root / "reports" / "report.html",
                root / "extracted" / "events.json",
                root / "vendor" / "wireshark" / "tshark.exe",
            )
            for target in targets:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"synthetic-test-data")
                self._git(root, "add", "--force", target.relative_to(root).as_posix())

            report = audit_repository.audit_repository(root)

        codes = {finding.code for finding in report.findings}
        self.assertIn("GENERATED_OUTPUT", codes)
        self.assertIn("VENDOR_PAYLOAD", codes)

    def test_output_filenames_are_rejected_at_root_and_arbitrary_locations(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._init_repository(root)
            targets = (
                root / "session.log",
                root / "case" / "incident-report.html",
                root / "case" / "raw" / "events.json",
                root / "nested" / "application.log.2",
            )
            for target in targets:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("synthetic-test-data", encoding="utf-8")
                self._git(root, "add", target.relative_to(root).as_posix())

            report = audit_repository.audit_repository(root)

        named_outputs = {
            finding.path
            for finding in report.findings
            if finding.code == "GENERATED_OUTPUT_NAME"
        }
        self.assertEqual(
            {
                "session.log",
                "case/incident-report.html",
                "case/raw/events.json",
                "nested/application.log.2",
            },
            named_outputs,
        )

    def test_binary_payloads_and_device_configurations_are_rejected_anywhere(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._init_repository(root)
            targets = (
                root / "unapproved.exe",
                root / "tools" / "extension.DLL",
                root / "backups" / "switch-backup.cfg",
                root / "switch-backup.CONF",
            )
            for target in targets:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"synthetic-test-data")
                self._git(root, "add", target.relative_to(root).as_posix())

            report = audit_repository.audit_repository(root)

        findings_by_code = {
            code: {finding.path for finding in report.findings if finding.code == code}
            for code in ("BINARY_PAYLOAD", "DEVICE_CONFIGURATION")
        }
        self.assertEqual(
            {"unapproved.exe", "tools/extension.DLL"},
            findings_by_code["BINARY_PAYLOAD"],
        )
        self.assertEqual(
            {"backups/switch-backup.cfg", "switch-backup.CONF"},
            findings_by_code["DEVICE_CONFIGURATION"],
        )

    def test_archives_and_renamed_binary_magic_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._init_repository(root)
            files = {
                "evidence.zip": b"synthetic archive name",
                "renamed-pe.txt": b"MZ" + bytes(30),
                "renamed-elf.txt": b"\x7fELF" + bytes(30),
                "renamed-archive.txt": b"PK\x03\x04" + bytes(30),
                "renamed-report.txt": b"%PDF-1.7\nsynthetic",
                "renamed-database.txt": b"SQLite format 3\x00" + bytes(20),
            }
            for relative, content in files.items():
                target = root / relative
                target.write_bytes(content)
                self._git(root, "add", relative)

            report = audit_repository.audit_repository(root)

        findings_by_path = {
            finding.path: {item.code for item in report.findings if item.path == finding.path}
            for finding in report.findings
        }
        self.assertIn("ARCHIVE_PAYLOAD", findings_by_path["evidence.zip"])
        self.assertIn("EXECUTABLE_MAGIC", findings_by_path["renamed-pe.txt"])
        self.assertIn("EXECUTABLE_MAGIC", findings_by_path["renamed-elf.txt"])
        self.assertIn("ARCHIVE_MAGIC", findings_by_path["renamed-archive.txt"])
        self.assertIn("REPORT_MAGIC", findings_by_path["renamed-report.txt"])
        self.assertIn("DATABASE_MAGIC", findings_by_path["renamed-database.txt"])

    def test_legitimate_metadata_sources_and_policy_tests_are_allowed(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._init_repository(root)
            files = {
                ".github/workflows/windows-ci.yml": "name: Windows CI\n",
                "pyproject.toml": "[project]\nname = 'example'\n",
                "LICENSE": "Synthetic license text\n",
                "src/example/policy.json": '{"kind":"html-policy"}\n',
                "tests/test_json_policy.py": "# JSON policy test\n",
                "tests/test_html_policy.py": "# HTML policy test\n",
                "vendor/wireshark/README.md": "Metadata only.\n",
                "vendor/wireshark/manifest.example.json": "{}\n",
            }
            for relative, content in files.items():
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
                self._git(root, "add", relative)

            report = audit_repository.audit_repository(root)

        self.assertEqual("git-tracked", report.mode)
        self.assertEqual(len(files), report.scanned_files)
        self.assertEqual((), report.findings)

    def test_sensitive_files_are_rejected_outside_profiles(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._init_repository(root)
            for name in (".env", "credentials.json", "device-config.txt"):
                target = root / name
                target.write_text("synthetic-secret-canary", encoding="utf-8")
                self._git(root, "add", "--force", name)

            report = audit_repository.audit_repository(root)

        self.assertIn("SENSITIVE_FILE", {finding.code for finding in report.findings})

    def test_empty_git_index_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._init_repository(root)

            report = audit_repository.audit_repository(root)

        self.assertIn("EMPTY_INDEX", {finding.code for finding in report.findings})

    def test_git_probe_failure_does_not_fall_back_to_worktree_scan(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / ".git").mkdir()
            (root / "README.md").write_text("clean worktree", encoding="utf-8")
            failed_probe = subprocess.CompletedProcess(
                args=["git"],
                returncode=128,
                stdout=b"",
                stderr=b"synthetic git failure",
            )
            with mock.patch.object(
                audit_repository,
                "_run_git",
                return_value=failed_probe,
            ):
                report = audit_repository.audit_repository(root)

        self.assertEqual("git", report.mode)
        self.assertEqual(0, report.scanned_files)
        self.assertIn("GIT_ERROR", {finding.code for finding in report.findings})


if __name__ == "__main__":
    unittest.main()
