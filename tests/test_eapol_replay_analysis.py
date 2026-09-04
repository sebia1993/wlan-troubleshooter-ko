import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from wlan_troubleshooter_ko.core.capture import CaptureInfo
from wlan_troubleshooter_ko.tshark.replay_analysis import (
    run_eapol_replay_relation_analysis,
)
from wlan_troubleshooter_ko.tshark.runner import TSharkExecutionError


class EapolReplayAnalysisTests(unittest.TestCase):
    def capture(self, root: Path, digest="a" * 64):
        path = root / "capture.pcap"
        path.write_bytes(b"pcap")
        return CaptureInfo(
            path=path,
            capture_format="pcap",
            size_bytes=4,
            sha256=digest,
        )

    @mock.patch(
        "wlan_troubleshooter_ko.tshark.replay_analysis.build_eapol_replay_relations"
    )
    @mock.patch("wlan_troubleshooter_ko.tshark.replay_analysis.resolve_profile")
    @mock.patch("wlan_troubleshooter_ko.tshark.replay_analysis.load_field_profiles")
    @mock.patch("wlan_troubleshooter_ko.tshark.replay_analysis.parse_field_catalog")
    @mock.patch("wlan_troubleshooter_ko.tshark.replay_analysis.run_profile_fields_text")
    @mock.patch("wlan_troubleshooter_ko.tshark.replay_analysis.run_field_catalog_text")
    def test_same_capture_and_bundle_return_relationship_report(
        self,
        catalog_run,
        fields_run,
        parse_catalog,
        load_profiles,
        resolve_profile,
        build_relations,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            capture = self.capture(root)
            workspace = root / "workspace"
            workspace.mkdir()
            catalog_run.return_value = SimpleNamespace(
                bundle_version="4.6.8",
                manifest_sha256="m" * 64,
                text="catalog",
            )
            profile = SimpleNamespace(profile_id="eapol-replay-relations")
            resolve_profile.return_value = profile
            fields_run.return_value = SimpleNamespace(
                bundle_version="4.6.8",
                manifest_sha256="m" * 64,
                text="raw-counter-text",
                capture=capture,
            )
            expected_report = SimpleNamespace(to_dict=lambda: {"safe": True})
            build_relations.return_value = expected_report
            handshake_report = object()

            result = run_eapol_replay_relation_analysis(
                root / "vendor",
                capture.path,
                workspace,
                root / "profiles.json",
                handshake_report,
                expected_capture=capture,
                expected_bundle_version="4.6.8",
                expected_manifest_sha256="m" * 64,
            )

        self.assertIs(result, expected_report)
        fields_run.assert_called_once()
        self.assertIs(fields_run.call_args.kwargs["expected_capture"], capture)
        build_relations.assert_called_once_with(
            "raw-counter-text",
            profile,
            handshake_report,
        )
        resolve_profile.assert_called_once_with(
            load_profiles.return_value,
            parse_catalog.return_value,
            "eapol-replay-relations",
        )

    @mock.patch("wlan_troubleshooter_ko.tshark.replay_analysis.run_field_catalog_text")
    def test_changed_bundle_is_rejected_before_counter_profile_execution(self, catalog_run):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            capture = self.capture(root)
            workspace = root / "workspace"
            workspace.mkdir()
            catalog_run.return_value = SimpleNamespace(
                bundle_version="4.6.9",
                manifest_sha256="n" * 64,
                text="catalog",
            )

            with self.assertRaises(TSharkExecutionError):
                run_eapol_replay_relation_analysis(
                    root / "vendor",
                    capture.path,
                    workspace,
                    root / "profiles.json",
                    object(),
                    expected_capture=capture,
                    expected_bundle_version="4.6.8",
                    expected_manifest_sha256="m" * 64,
                )

    @mock.patch(
        "wlan_troubleshooter_ko.tshark.replay_analysis.build_eapol_replay_relations"
    )
    @mock.patch("wlan_troubleshooter_ko.tshark.replay_analysis.resolve_profile")
    @mock.patch("wlan_troubleshooter_ko.tshark.replay_analysis.load_field_profiles")
    @mock.patch("wlan_troubleshooter_ko.tshark.replay_analysis.parse_field_catalog")
    @mock.patch("wlan_troubleshooter_ko.tshark.replay_analysis.run_profile_fields_text")
    @mock.patch("wlan_troubleshooter_ko.tshark.replay_analysis.run_field_catalog_text")
    def test_missing_capture_fingerprint_is_rejected(
        self,
        catalog_run,
        fields_run,
        parse_catalog,
        load_profiles,
        resolve_profile,
        build_relations,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            capture = self.capture(root)
            workspace = root / "workspace"
            workspace.mkdir()
            catalog_run.return_value = SimpleNamespace(
                bundle_version="4.6.8",
                manifest_sha256="m" * 64,
                text="catalog",
            )
            fields_run.return_value = SimpleNamespace(
                bundle_version="4.6.8",
                manifest_sha256="m" * 64,
                text="raw-counter-text",
                capture=None,
            )

            with self.assertRaises(TSharkExecutionError):
                run_eapol_replay_relation_analysis(
                    root / "vendor",
                    capture.path,
                    workspace,
                    root / "profiles.json",
                    object(),
                    expected_capture=capture,
                    expected_bundle_version="4.6.8",
                    expected_manifest_sha256="m" * 64,
                )

        build_relations.assert_not_called()


if __name__ == "__main__":
    unittest.main()
