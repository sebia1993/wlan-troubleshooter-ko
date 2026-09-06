import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from wlan_troubleshooter_ko.core.capture import CaptureInfo
from wlan_troubleshooter_ko.tshark.runner import TSharkExecutionError
from wlan_troubleshooter_ko.tshark.time_analysis import (
    run_capture_time_boundary_analysis,
)


class CaptureTimeAnalysisTests(unittest.TestCase):
    def capture(self, root, digest="b" * 64):
        path = root / "capture.pcap"
        path.write_bytes(b"pcap")
        return CaptureInfo(
            path=path,
            capture_format="pcap",
            size_bytes=4,
            sha256=digest,
        )

    def report(self):
        return SimpleNamespace(to_dict=lambda: {"schema_version": 1})

    @mock.patch(
        "wlan_troubleshooter_ko.tshark.time_analysis.build_capture_time_boundaries"
    )
    @mock.patch(
        "wlan_troubleshooter_ko.tshark.time_analysis.build_capture_time_index"
    )
    @mock.patch(
        "wlan_troubleshooter_ko.tshark.time_analysis.resolve_profile"
    )
    @mock.patch(
        "wlan_troubleshooter_ko.tshark.time_analysis.parse_field_catalog"
    )
    @mock.patch(
        "wlan_troubleshooter_ko.tshark.time_analysis.load_field_profiles"
    )
    @mock.patch(
        "wlan_troubleshooter_ko.tshark.time_analysis.run_profile_fields_text"
    )
    @mock.patch(
        "wlan_troubleshooter_ko.tshark.time_analysis.run_field_catalog_text"
    )
    def test_same_capture_and_bundle_return_relative_report(
        self,
        catalog_run,
        fields_run,
        load_profiles,
        parse_catalog,
        resolve_profile,
        build_index,
        build_report,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            capture = self.capture(root)
            workspace = root / "workspace"
            workspace.mkdir()
            manifest = "a" * 64
            catalog_run.return_value = SimpleNamespace(
                bundle_version="4.6.8",
                manifest_sha256=manifest,
                text="catalog",
            )
            profile = SimpleNamespace(
                profile_id="capture-time-boundaries"
            )
            resolve_profile.return_value = profile
            fields_run.return_value = SimpleNamespace(
                bundle_version="4.6.8",
                manifest_sha256=manifest,
                text="fields",
                capture=capture,
            )
            index = object()
            report = self.report()
            build_index.return_value = index
            build_report.return_value = report
            transactions = object()

            result = run_capture_time_boundary_analysis(
                root / "vendor",
                capture.path,
                workspace,
                root / "profiles.json",
                transactions,
                expected_capture=capture,
                expected_bundle_version="4.6.8",
                expected_manifest_sha256=manifest,
                expected_frames=4,
            )

        self.assertIs(result, report)
        resolve_profile.assert_called_once_with(
            load_profiles.return_value,
            parse_catalog.return_value,
            "capture-time-boundaries",
        )
        fields_run.assert_called_once()
        self.assertIs(
            fields_run.call_args.kwargs["expected_capture"],
            capture,
        )
        build_index.assert_called_once_with(
            "fields",
            profile,
            expected_frames=4,
        )
        build_report.assert_called_once_with(index, transactions)

    @mock.patch(
        "wlan_troubleshooter_ko.tshark.time_analysis.run_profile_fields_text"
    )
    @mock.patch(
        "wlan_troubleshooter_ko.tshark.time_analysis.run_field_catalog_text"
    )
    @mock.patch(
        "wlan_troubleshooter_ko.tshark.time_analysis.load_field_profiles"
    )
    def test_changed_bundle_is_rejected_before_timestamp_profile(
        self,
        load_profiles,
        catalog_run,
        fields_run,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            capture = self.capture(root)
            workspace = root / "workspace"
            workspace.mkdir()
            catalog_run.return_value = SimpleNamespace(
                bundle_version="4.6.9",
                manifest_sha256="c" * 64,
                text="catalog",
            )

            with self.assertRaises(TSharkExecutionError):
                run_capture_time_boundary_analysis(
                    root / "vendor",
                    capture.path,
                    workspace,
                    root / "profiles.json",
                    object(),
                    expected_capture=capture,
                    expected_bundle_version="4.6.8",
                    expected_manifest_sha256="a" * 64,
                    expected_frames=1,
                )

        fields_run.assert_not_called()

    @mock.patch(
        "wlan_troubleshooter_ko.tshark.time_analysis.build_capture_time_index"
    )
    @mock.patch(
        "wlan_troubleshooter_ko.tshark.time_analysis.resolve_profile"
    )
    @mock.patch(
        "wlan_troubleshooter_ko.tshark.time_analysis.parse_field_catalog"
    )
    @mock.patch(
        "wlan_troubleshooter_ko.tshark.time_analysis.load_field_profiles"
    )
    @mock.patch(
        "wlan_troubleshooter_ko.tshark.time_analysis.run_profile_fields_text"
    )
    @mock.patch(
        "wlan_troubleshooter_ko.tshark.time_analysis.run_field_catalog_text"
    )
    def test_changed_capture_fingerprint_is_rejected_before_parsing(
        self,
        catalog_run,
        fields_run,
        load_profiles,
        parse_catalog,
        resolve_profile,
        build_index,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            capture = self.capture(root)
            changed = CaptureInfo(
                path=capture.path,
                capture_format=capture.capture_format,
                size_bytes=capture.size_bytes,
                sha256="d" * 64,
            )
            workspace = root / "workspace"
            workspace.mkdir()
            manifest = "a" * 64
            catalog_run.return_value = SimpleNamespace(
                bundle_version="4.6.8",
                manifest_sha256=manifest,
                text="catalog",
            )
            resolve_profile.return_value = SimpleNamespace(
                profile_id="capture-time-boundaries"
            )
            fields_run.return_value = SimpleNamespace(
                bundle_version="4.6.8",
                manifest_sha256=manifest,
                text="fields",
                capture=changed,
            )

            with self.assertRaises(TSharkExecutionError):
                run_capture_time_boundary_analysis(
                    root / "vendor",
                    capture.path,
                    workspace,
                    root / "profiles.json",
                    object(),
                    expected_capture=capture,
                    expected_bundle_version="4.6.8",
                    expected_manifest_sha256=manifest,
                    expected_frames=1,
                )

        build_index.assert_not_called()

    def test_invalid_workspace_or_input_metadata_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            capture = self.capture(root)
            missing_workspace = root / "missing"
            with self.assertRaises(TSharkExecutionError):
                run_capture_time_boundary_analysis(
                    root / "vendor",
                    capture.path,
                    missing_workspace,
                    root / "profiles.json",
                    object(),
                    expected_capture=capture,
                    expected_bundle_version="4.6.8",
                    expected_manifest_sha256="a" * 64,
                    expected_frames=1,
                )

            workspace = root / "workspace"
            workspace.mkdir()
            other = root / "other.pcap"
            other.write_bytes(b"pcap")
            with self.assertRaises(TSharkExecutionError):
                run_capture_time_boundary_analysis(
                    root / "vendor",
                    other,
                    workspace,
                    root / "profiles.json",
                    object(),
                    expected_capture=capture,
                    expected_bundle_version="",
                    expected_manifest_sha256="short",
                    expected_frames=1,
                )


if __name__ == "__main__":
    unittest.main()
