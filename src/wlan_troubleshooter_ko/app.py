"""GUI와 오프라인 자체 점검 진입점."""

import argparse
import tkinter
from pathlib import Path
from typing import Dict, Optional, Sequence

from wlan_troubleshooter_ko.core.canonical_json import dumps
from wlan_troubleshooter_ko.core.config import load_example_profile, load_messages, load_ruleset
from wlan_troubleshooter_ko.tshark.manifest import verify_bundle


def package_root() -> Path:
    return Path(__file__).resolve().parent


def self_check() -> Dict[str, str]:
    resources = package_root() / "resources"
    rules = load_ruleset(resources / "rules" / "v1" / "rules.json")
    messages = load_messages(resources / "messages" / "ko.json")
    profile = load_example_profile(resources / "profiles" / "site-default.example.json")
    tkinter.Tcl()

    vendor_root = package_root().parents[1] / "vendor" / "wireshark"
    vendor_manifest = vendor_root / "manifest.json"
    tshark_status = "승인 번들 미제공(예상 상태)"
    if vendor_manifest.exists():
        verified = verify_bundle(vendor_root)
        tshark_status = "무결성 검증됨: " + verified.version
    return {
        "phase": "0-1",
        "runtime_dependencies": "0",
        "ruleset_version": rules["ruleset_version"],
        "message_locale": messages["locale"],
        "profile": profile["profile_id"],
        "tkinter": "사용 가능",
        "portable_tshark": tshark_status,
        "network_features": "없음",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="완전 오프라인 무선 장애 분석기")
    parser.add_argument(
        "--self-check",
        "--self-test",
        dest="self_check",
        action="store_true",
        help="창을 열지 않고 Phase 0·1 리소스와 Tkinter를 검사합니다.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    arguments = build_parser().parse_args(argv)
    if arguments.self_check:
        print(dumps(self_check()), end="")
        return 0

    from wlan_troubleshooter_ko.ui.main_window import launch

    launch()
    return 0
