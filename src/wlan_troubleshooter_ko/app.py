"""GUI, 자체 점검과 비대화형 로컬 분석 진입점."""

import argparse
import tkinter
from pathlib import Path
from typing import Dict, Optional, Sequence

from wlan_troubleshooter_ko.analysis.service import (
    CaptureAnalysisError,
    analyze_capture,
)
from wlan_troubleshooter_ko.core.canonical_json import dumps
from wlan_troubleshooter_ko.core.config import load_example_profile, load_messages, load_ruleset
from wlan_troubleshooter_ko.tshark.manifest import verify_bundle
from wlan_troubleshooter_ko.tshark.profiles import load_field_profiles


def package_root() -> Path:
    return Path(__file__).resolve().parent


def distribution_root() -> Path:
    """소스 실행에서는 저장소, PyInstaller onedir에서는 EXE 폴더를 반환한다."""

    return package_root().parents[1]


def _external_python_required() -> bool:
    """PyInstaller 배포 루트에 제품 EXE가 있는지 보수적으로 확인한다."""

    executable = distribution_root() / "WlanTroubleshooterKO.exe"
    return not executable.is_file()


def self_check() -> Dict[str, str]:
    resources = package_root() / "resources"
    rules = load_ruleset(resources / "rules" / "v1" / "rules.json")
    messages = load_messages(resources / "messages" / "ko.json")
    profile = load_example_profile(resources / "profiles" / "site-default.example.json")
    field_registry = load_field_profiles(resources / "tshark" / "field-profiles.v1.json")
    inventory_profile = field_registry.get_profile("protocol-inventory")
    event_profile = field_registry.get_profile("connection-events")
    tkinter.Tcl()

    vendor_root = distribution_root() / "vendor" / "wireshark"
    vendor_manifest = vendor_root / "manifest.json"
    tshark_status = "프로젝트 고정 TShark 미포함"
    tshark_external_required = "true"
    analysis_execution = "비활성 · 프로젝트 고정 Portable TShark 대기"
    if vendor_manifest.exists():
        verified = verify_bundle(vendor_root)
        tshark_status = "무결성 검증됨: " + verified.version
        tshark_external_required = "false"
        analysis_execution = "활성 · 프로토콜 인벤토리와 접속 단계 Finding"
    return {
        "phase": "4B",
        "runtime_dependencies": "0",
        "ruleset_version": rules["ruleset_version"],
        "rule_count": str(len(rules["rules"])),
        "message_locale": messages["locale"],
        "profile": profile["profile_id"],
        "field_profile_version": field_registry.profile_version,
        "inventory_field_count": str(len(inventory_profile.fields)),
        "event_field_count": str(len(event_profile.fields)),
        "protocol_group_count": str(len(field_registry.protocol_groups)),
        "tkinter": "사용 가능",
        "python_external_required": "true" if _external_python_required() else "false",
        "tshark_external_required": tshark_external_required,
        "portable_tshark": tshark_status,
        "protocol_inventory_execution": analysis_execution,
        "analysis_features": (
            "캡처 구조 점검 + 프로토콜 존재 인벤토리 + "
            "접속 단계 상관분석·근거 기반 Finding"
        ),
        "network_features": "없음",
    }


def _write_new_local_json(raw_path: str, value: Dict[str, object], label: str) -> None:
    if (
        not raw_path
        or "\x00" in raw_path
        or "://" in raw_path
        or raw_path.startswith(("\\\\", "//"))
    ):
        raise ValueError(label + "은 로컬 절대경로여야 합니다.")
    path = Path(raw_path)
    if not path.is_absolute() or not path.parent.is_dir() or path.is_symlink():
        raise ValueError(label + " 경로를 사용할 수 없습니다.")
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(dumps(value))


def _write_self_check_output(raw_path: str, value: Dict[str, str]) -> None:
    _write_new_local_json(raw_path, value, "자체 점검 출력")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="완전 오프라인 무선 장애 분석기")
    parser.add_argument(
        "--self-check",
        "--self-test",
        dest="self_check",
        action="store_true",
        help="창을 열지 않고 리소스와 Tkinter를 검사합니다.",
    )
    parser.add_argument(
        "--self-check-output",
        help="창과 콘솔 없이 자체 점검 JSON을 새 로컬 파일에 기록합니다.",
    )
    parser.add_argument(
        "--analyze-capture",
        help="저장된 로컬 PCAP 또는 PCAPNG를 비대화형으로 분석합니다.",
    )
    parser.add_argument(
        "--analysis-output",
        help="비대화형 분석 결과를 새 로컬 JSON 파일에 기록합니다.",
    )
    return parser


def _run_noninteractive_analysis(capture_path: str, output_path: str) -> int:
    resources = package_root() / "resources"
    vendor_root = distribution_root() / "vendor" / "wireshark"
    profile_path = resources / "tshark" / "field-profiles.v1.json"
    rules_path = resources / "rules" / "v1" / "rules.json"
    try:
        result = analyze_capture(
            capture_path,
            vendor_root,
            profile_path,
            rules_path=rules_path,
        )
        payload = result.to_dict()
        exit_code = 0 if result.inventory_state == "completed" else 2
    except CaptureAnalysisError as exc:
        payload = {
            "schema_version": 2,
            "protocol_inventory_state": "failed",
            "protocol_inventory_message": str(exc),
        }
        exit_code = 2
    except Exception:
        payload = {
            "schema_version": 2,
            "protocol_inventory_state": "failed",
            "protocol_inventory_message": "캡처 분석을 안전하게 완료하지 못했습니다.",
        }
        exit_code = 2
    _write_new_local_json(output_path, payload, "분석 결과 출력")
    return exit_code


def main(argv: Optional[Sequence[str]] = None) -> int:
    arguments = build_parser().parse_args(argv)
    if arguments.self_check or arguments.self_check_output:
        result = self_check()
        if arguments.self_check_output:
            _write_self_check_output(arguments.self_check_output, result)
        else:
            print(dumps(result), end="")
        return 0

    if bool(arguments.analyze_capture) != bool(arguments.analysis_output):
        raise ValueError("비대화형 분석에는 입력 캡처와 결과 출력 경로가 모두 필요합니다.")
    if arguments.analyze_capture and arguments.analysis_output:
        return _run_noninteractive_analysis(
            arguments.analyze_capture,
            arguments.analysis_output,
        )

    from wlan_troubleshooter_ko.ui.main_window import launch

    launch()
    return 0
