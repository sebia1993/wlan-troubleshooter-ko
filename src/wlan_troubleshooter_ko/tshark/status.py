"""Portable TShark 준비 상태를 경로 노출 없이 분류한다."""

from dataclasses import dataclass
from pathlib import Path

from wlan_troubleshooter_ko.tshark.manifest import BundleVerificationError, verify_bundle


@dataclass(frozen=True)
class BundleStatus:
    code: str
    message: str


def inspect_bundle(vendor_root: Path) -> BundleStatus:
    """미준비, 무결성 오류, 실행 미확인 상태를 안전한 문구로 반환한다."""

    manifest_path = vendor_root / "manifest.json"
    if not manifest_path.is_file():
        return BundleStatus(
            "not_provisioned",
            "Portable TShark 미준비 · 승인 번들이 제공되지 않았습니다.",
        )
    try:
        bundle = verify_bundle(vendor_root)
    except BundleVerificationError:
        return BundleStatus(
            "integrity_error",
            "Portable TShark 무결성 오류 · 번들을 실행할 수 없습니다.",
        )
    return BundleStatus(
        "integrity_verified",
        "Portable TShark 무결성 확인됨 · 실행 준비 확인 전 ({0})".format(bundle.version),
    )
