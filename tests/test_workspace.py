import tempfile
import unittest
from pathlib import Path
from unittest import mock

from wlan_troubleshooter_ko.core import workspace as workspace_module
from wlan_troubleshooter_ko.core.workspace import AnalysisWorkspace, WorkspaceError


class WorkspaceTests(unittest.TestCase):
    def test_cleanup_after_success(self):
        with tempfile.TemporaryDirectory() as base:
            with AnalysisWorkspace(base) as workspace:
                root = workspace.root
                workspace.allocate("normalized/events.json").write_text("{}", encoding="utf-8")
                self.assertTrue(root.exists())
            self.assertFalse(root.exists())

    def test_cleanup_after_error_or_cancel(self):
        class Cancelled(Exception):
            pass

        with tempfile.TemporaryDirectory() as base:
            root = None
            with self.assertRaises(Cancelled):
                with AnalysisWorkspace(base) as workspace:
                    root = workspace.root
                    workspace.allocate("partial.tmp").write_bytes(b"partial")
                    raise Cancelled()
            self.assertIsNotNone(root)
            self.assertFalse(root.exists())

    def test_path_escape_is_rejected(self):
        with AnalysisWorkspace() as workspace:
            for candidate in ("../outside", "/absolute", "nested/../../outside"):
                with self.subTest(candidate=candidate):
                    with self.assertRaises(WorkspaceError):
                        workspace.allocate(candidate)

    def test_windows_unsafe_names_are_rejected_on_every_platform(self):
        with AnalysisWorkspace() as workspace:
            for candidate in (
                "NUL.txt",
                "folder/name. ",
                "folder/name.",
                "data:stream",
                r"a\b",
                "bad?.json",
                "bad*.json",
                "bad|name.json",
                'bad"name.json',
                "COM¹.txt",
                "CONIN$.txt",
            ):
                with self.subTest(candidate=candidate):
                    with self.assertRaises(WorkspaceError):
                        workspace.allocate(candidate)

    def test_existing_internal_symlink_is_rejected(self):
        with AnalysisWorkspace() as workspace:
            real = workspace.root / "real"
            real.mkdir()
            link = workspace.root / "alias"
            try:
                link.symlink_to(real, target_is_directory=True)
            except OSError:
                self.skipTest("symlink creation is unavailable on this runner")
            with self.assertRaises(WorkspaceError):
                workspace.allocate("alias/output.json")

    def test_existing_output_and_reparse_component_are_rejected(self):
        with AnalysisWorkspace() as workspace:
            existing = workspace.root / "existing.json"
            existing.write_text("sentinel", encoding="utf-8")
            with self.assertRaises(WorkspaceError):
                workspace.allocate("existing.json")
            self.assertEqual(existing.read_text(encoding="utf-8"), "sentinel")

            junction = workspace.root / "junction"
            junction.mkdir()
            original = workspace_module._is_link_or_reparse

            def detect_test_reparse(path):
                return path == junction or original(path)

            with mock.patch.object(
                workspace_module,
                "_is_link_or_reparse",
                side_effect=detect_test_reparse,
            ):
                with self.assertRaises(WorkspaceError):
                    workspace.allocate("junction/output.json")


if __name__ == "__main__":
    unittest.main()
