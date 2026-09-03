"""Phase 2B 프로토콜 인벤토리의 실행 전 준비 경계."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Tuple

from wlan_troubleshooter_ko.tshark.catalog import FieldCatalog
from wlan_troubleshooter_ko.tshark.manifest import verify_bundle
from wlan_troubleshooter_ko.tshark.policy import (
    build_field_catalog_argv,
    build_profile_argv,
)
from wlan_troubleshooter_ko.tshark.profiles import (
    ResolvedProfile,
    load_field_profiles,
    resolve_profile,
)
from wlan_troubleshooter_ko.tshark.runner import build_isolated_environment


@dataclass(frozen=True)
class PreparedCatalogInvocation:
    bundle_version: str
    manifest_sha256: str
    arguments: Tuple[str, ...]
    environment: Mapping[str, str]


@dataclass(frozen=True)
class PreparedProtocolInventoryInvocation:
    bundle_version: str
    manifest_sha256: str
    resolved_profile: ResolvedProfile
    arguments: Tuple[str, ...]
    environment: Mapping[str, str]


def prepare_field_catalog_invocation(
    vendor_root: Path,
    isolation_root: Path,
) -> PreparedCatalogInvocation:
    """승인 TShark의 고정 `-n -G fields` 호출을 실행 없이 준비한다."""

    bundle = verify_bundle(vendor_root)
    arguments = build_field_catalog_argv(bundle)
    environment = build_isolated_environment(isolation_root)
    return PreparedCatalogInvocation(
        bundle_version=bundle.version,
        manifest_sha256=bundle.manifest_sha256,
        arguments=tuple(arguments),
        environment=environment,
    )


def prepare_protocol_inventory_invocation(
    vendor_root: Path,
    capture_path: Path,
    isolation_root: Path,
    profile_path: Path,
    catalog: FieldCatalog,
    profile_id: str = "protocol-inventory",
) -> PreparedProtocolInventoryInvocation:
    """카탈로그 호환성을 확인한 고정 fields 호출을 실행 없이 준비한다."""

    registry = load_field_profiles(profile_path)
    resolved_profile = resolve_profile(registry, catalog, profile_id)
    bundle = verify_bundle(vendor_root)
    arguments = build_profile_argv(bundle, capture_path, resolved_profile)
    environment = build_isolated_environment(isolation_root)
    return PreparedProtocolInventoryInvocation(
        bundle_version=bundle.version,
        manifest_sha256=bundle.manifest_sha256,
        resolved_profile=resolved_profile,
        arguments=tuple(arguments),
        environment=environment,
    )
