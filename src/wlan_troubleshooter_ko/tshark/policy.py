"""TShark argument allowlists for stored-capture analysis."""

from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from wlan_troubleshooter_ko.core.capture import validate_capture
from wlan_troubleshooter_ko.tshark.manifest import VerifiedBundle
from wlan_troubleshooter_ko.tshark.profiles import ResolvedProfile


APPROVED_DISPLAY_FILTERS = {
    "capture-overview": "frame.number >= 1",
}

# These fields are safe for ordinary inventory, Finding and event outputs.
APPROVED_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "frame.interface_id",
    "frame.cap_len",
    "frame.len",
    "frame.protocols",
    "wlan.fc.type_subtype",
    "wlan.fc.retry",
    "wlan.fixed.status_code",
    "wlan.fixed.reason_code",
    "wlan.fixed.auth.alg",
    "wlan.fixed.auth_seq",
    "eapol.type",
    "wlan_rsna_eapol.keydes.msgnr",
    "eap.code",
    "eap.id",
    "eap.type",
    "radius.code",
    "radius.id",
    "dhcp.id",
    "bootp.id",
    "dhcp.option.dhcp",
    "bootp.option.dhcp",
    "dns.id",
    "dns.flags.response",
    "dns.flags.rcode",
    "udp.stream",
    "arp.opcode",
    "tcp.stream",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.reset",
    "tcp.analysis.retransmission",
    "tls.handshake.type",
)

# These raw L2 identifiers may appear only in the dedicated transient profile.
# They must never be added to the ordinary event profile or serialized output.
TRANSIENT_IDENTITY_FIELDS = (
    "eth.src",
    "eth.dst",
    "wlan.sa",
    "wlan.da",
    "wlan.bssid",
)

_PROFILE_REQUIRED_FIELDS = {
    "protocol-inventory": {
        "frame.number",
        "frame.cap_len",
        "frame.len",
        "frame.protocols",
    },
    "connection-events": {
        "frame.number",
        "frame.time_epoch",
        "frame.cap_len",
        "frame.len",
        "frame.protocols",
    },
    "device-identities": {
        "frame.number",
        "frame.time_epoch",
        "frame.protocols",
    },
}

_DEVICE_IDENTITY_FIELD_ORDER = (
    "frame.number",
    "frame.time_epoch",
    "frame.protocols",
    "wlan.fc.type_subtype",
    "wlan.fixed.auth_seq",
    "eapol.type",
    "eap.code",
    "dhcp.option.dhcp",
    "bootp.option.dhcp",
    *TRANSIENT_IDENTITY_FIELDS,
)

_PROFILE_FIELD_ORDER = {
    "protocol-inventory": APPROVED_FIELDS,
    "connection-events": APPROVED_FIELDS,
    "device-identities": _DEVICE_IDENTITY_FIELD_ORDER,
}

_FIELD_OUTPUT_PREFIX = [
    "-T",
    "fields",
    "-E",
    "header=y",
    "-E",
    "separator=/t",
    "-E",
    "occurrence=f",
    "-E",
    "quote=d",
    "-E",
    "escape=y",
]


class TSharkPolicyError(ValueError):
    """The stored-file TShark request violates the reviewed policy."""


def _assert_executable(value: str) -> None:
    executable = Path(value)
    if (
        "\x00" in value
        or value.startswith(("\\\\", "//"))
        or "://" in value
        or not executable.is_absolute()
        or executable.name.casefold() != "tshark.exe"
    ):
        raise TSharkPolicyError("승인된 절대 tshark.exe 경로가 필요합니다.")


def _assert_capture_path(value: str) -> None:
    lowered = value.casefold()
    if (
        not Path(value).is_absolute()
        or "\x00" in value
        or value.startswith(("\\\\", "//"))
        or lowered.startswith("rpcap")
        or lowered.startswith("tcp@")
        or "://" in lowered
    ):
        raise TSharkPolicyError("검증된 로컬 절대 캡처 경로가 필요합니다.")


def _field_values(arguments: List[str], start: int) -> List[str]:
    if (len(arguments) - start) % 2:
        raise TSharkPolicyError("TShark 필드 인자 쌍이 올바르지 않습니다.")
    values = []
    for index in range(start, len(arguments), 2):
        if arguments[index] != "-e" or not isinstance(arguments[index + 1], str):
            raise TSharkPolicyError("승인되지 않은 TShark 필드 인자입니다.")
        values.append(arguments[index + 1])
    return values


def _canonical_fields(field_values: List[str], profile_id: str) -> List[str]:
    try:
        field_order = _PROFILE_FIELD_ORDER[profile_id]
    except KeyError as exc:
        raise TSharkPolicyError("승인되지 않은 추출 프로파일입니다.") from exc
    if not field_values or any(field not in field_order for field in field_values):
        raise TSharkPolicyError("승인되지 않은 TShark 필드입니다.")
    if len(field_values) != len(set(field_values)):
        raise TSharkPolicyError("중복 TShark 필드를 사용할 수 없습니다.")
    return [field for field in field_order if field in field_values]


def _canonical_legacy_fields(field_values: List[str]) -> List[str]:
    if not field_values or any(field not in APPROVED_FIELDS for field in field_values):
        raise TSharkPolicyError("승인되지 않은 TShark 필드입니다.")
    if len(field_values) != len(set(field_values)):
        raise TSharkPolicyError("중복 TShark 필드를 사용할 수 없습니다.")
    return [field for field in APPROVED_FIELDS if field in field_values]


def assert_safe_argv(arguments: List[str]) -> None:
    """Retain the Phase 1 compatibility check without transient identifiers."""

    if (
        not isinstance(arguments, list)
        or not all(isinstance(argument, str) for argument in arguments)
        or len(arguments) < 11
        or (len(arguments) - 9) % 2
    ):
        raise TSharkPolicyError("TShark 인자 개수와 고정 구조가 올바르지 않습니다.")
    _assert_executable(arguments[0])
    if arguments[1:4] != ["-n", "-2", "-r"]:
        raise TSharkPolicyError("이름 해석 차단과 저장 파일 옵션 순서가 고정돼야 합니다.")
    _assert_capture_path(arguments[4])
    if arguments[5:8] != ["-T", "fields", "-Y"]:
        raise TSharkPolicyError("승인된 fields 출력 순서만 사용할 수 있습니다.")
    if arguments[8] not in APPROVED_DISPLAY_FILTERS.values():
        raise TSharkPolicyError("승인되지 않은 Display Filter입니다.")
    values = _field_values(arguments, 9)
    if values != _canonical_legacy_fields(values):
        raise TSharkPolicyError("TShark 필드는 중복 없이 고정 순서여야 합니다.")


def build_analysis_argv(
    bundle: VerifiedBundle,
    capture_path: Path,
    display_filter_name: str,
    fields: Iterable[str],
) -> List[str]:
    """Build the legacy simple fields command from internal registries only."""

    capture = validate_capture(capture_path)
    try:
        display_filter = APPROVED_DISPLAY_FILTERS[display_filter_name]
    except KeyError as exc:
        raise TSharkPolicyError("승인되지 않은 Display Filter입니다.") from exc
    selected_fields = _canonical_legacy_fields(list(fields))

    arguments = [
        str(bundle.executable),
        "-n",
        "-2",
        "-r",
        str(capture.path),
        "-T",
        "fields",
        "-Y",
        display_filter,
    ]
    for field in selected_fields:
        arguments.extend(("-e", field))
    assert_safe_argv(arguments)
    return arguments


def assert_safe_field_catalog_argv(arguments: List[str]) -> None:
    if (
        not isinstance(arguments, list)
        or not all(isinstance(argument, str) for argument in arguments)
        or len(arguments) != 4
    ):
        raise TSharkPolicyError("필드 카탈로그 인자 구조가 올바르지 않습니다.")
    _assert_executable(arguments[0])
    if arguments[1:] != ["-n", "-G", "fields"]:
        raise TSharkPolicyError("승인된 필드 카탈로그 명령만 사용할 수 있습니다.")


def build_field_catalog_argv(bundle: VerifiedBundle) -> List[str]:
    arguments = [str(bundle.executable), "-n", "-G", "fields"]
    assert_safe_field_catalog_argv(arguments)
    return arguments


def _infer_non_identity_profile(fields: Sequence[str]) -> str:
    if any(field in TRANSIENT_IDENTITY_FIELDS for field in fields):
        raise TSharkPolicyError(
            "가명화 필드는 명시적인 device-identities 프로파일에서만 사용할 수 있습니다."
        )
    return "connection-events" if "frame.time_epoch" in fields else "protocol-inventory"


def assert_safe_profile_argv(
    arguments: List[str],
    profile_id: Optional[str] = None,
) -> None:
    if (
        not isinstance(arguments, list)
        or not all(isinstance(argument, str) for argument in arguments)
        or len(arguments) < 23
        or (len(arguments) - 21) % 2
    ):
        raise TSharkPolicyError("프로파일 TShark 인자 구조가 올바르지 않습니다.")
    _assert_executable(arguments[0])
    if arguments[1:4] != ["-n", "-2", "-r"]:
        raise TSharkPolicyError("이름 해석 차단과 저장 파일 옵션 순서가 고정돼야 합니다.")
    _assert_capture_path(arguments[4])
    if (
        arguments[5] != "-c"
        or not arguments[6].isascii()
        or not arguments[6].isdecimal()
    ):
        raise TSharkPolicyError("고정 패킷 상한이 필요합니다.")
    packet_limit = int(arguments[6], 10)
    if str(packet_limit) != arguments[6] or not 1 <= packet_limit <= 500_000:
        raise TSharkPolicyError("패킷 상한이 허용 범위를 벗어났습니다.")
    if arguments[7:19] != _FIELD_OUTPUT_PREFIX:
        raise TSharkPolicyError("fields 출력 옵션이 승인된 고정 형식과 다릅니다.")
    if (
        arguments[19] != "-Y"
        or arguments[20] not in APPROVED_DISPLAY_FILTERS.values()
    ):
        raise TSharkPolicyError("승인되지 않은 Display Filter입니다.")

    values = _field_values(arguments, 21)
    selected_profile = (
        _infer_non_identity_profile(values) if profile_id is None else profile_id
    )
    canonical = _canonical_fields(values, selected_profile)
    if values != canonical:
        raise TSharkPolicyError("TShark 필드는 중복 없이 고정 순서여야 합니다.")
    required_fields = _PROFILE_REQUIRED_FIELDS[selected_profile]
    if not required_fields.issubset(values):
        raise TSharkPolicyError("추출 프로파일 필수 필드가 누락됐습니다.")


def build_profile_argv(
    bundle: VerifiedBundle,
    capture_path: Path,
    profile: ResolvedProfile,
) -> List[str]:
    """Build deterministic fields argv only from a resolved internal profile."""

    capture = validate_capture(capture_path)
    try:
        display_filter = APPROVED_DISPLAY_FILTERS[profile.display_filter_name]
        required_fields = _PROFILE_REQUIRED_FIELDS[profile.profile_id]
    except KeyError as exc:
        raise TSharkPolicyError("승인되지 않은 추출 프로파일입니다.") from exc
    selected_fields = _canonical_fields(list(profile.headers()), profile.profile_id)
    if not required_fields.issubset(selected_fields):
        raise TSharkPolicyError("추출 프로파일 필수 필드가 누락됐습니다.")

    arguments = [
        str(bundle.executable),
        "-n",
        "-2",
        "-r",
        str(capture.path),
        "-c",
        str(profile.max_packets),
        *_FIELD_OUTPUT_PREFIX,
        "-Y",
        display_filter,
    ]
    for field in selected_fields:
        arguments.extend(("-e", field))
    assert_safe_profile_argv(arguments, profile.profile_id)
    return arguments
