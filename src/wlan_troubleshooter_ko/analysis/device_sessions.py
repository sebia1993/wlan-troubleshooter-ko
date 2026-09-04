"""Transient L2 identifiers are converted to per-analysis device and AP aliases.

Raw addresses are accepted only from the dedicated ``device-identities`` TShark
profile. They are normalized, keyed with an analysis-scoped HMAC secret and
discarded. Only ``DEVICE-N`` / ``AP-N`` aliases and packet evidence are
serializable.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from wlan_troubleshooter_ko.tshark.fields_output import iter_fields_rows
from wlan_troubleshooter_ko.tshark.profiles import ResolvedProfile


_DEVICE_ALIAS_PATTERN = re.compile(r"^DEVICE-[1-9][0-9]{0,5}$")
_AP_ALIAS_PATTERN = re.compile(r"^AP-[1-9][0-9]{0,5}$")
_EVENT_ATTEMPT_PATTERN = re.compile(
    r"^(?:EAP|RADIUS|DHCP|DNS|TCP)-[1-9][0-9]{0,5}-A[1-9][0-9]{0,5}$"
)
_PROTOCOL_TOKEN_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
_MAX_INTEGER = 2**63 - 1
_MAX_DEVICES = 20_000
_MAX_APS = 20_000
_MAX_EVIDENCE_FRAMES = 64
_MAX_ATTEMPT_LINKS = 50_000

_SAFE_PROTOCOLS = {
    "wlan": "wlan",
    "wlan_radio": "wlan",
    "eapol": "eapol",
    "wlan_rsna_eapol": "eapol",
    "eap": "eap",
    "radius": "radius",
    "dhcp": "dhcp",
    "bootp": "dhcp",
    "dns": "dns",
    "arp": "arp",
    "tcp": "tcp",
    "tls": "tls",
    "ssl": "tls",
}

_CLIENT_DHCP_TYPES = {1, 3, 4, 7, 8}
_WLAN_REQUEST_SUBTYPES = {0, 2}
_WLAN_RESPONSE_SUBTYPES = {1, 3}
_WLAN_DISCONNECT_SUBTYPES = {10, 12}


class DeviceSessionError(ValueError):
    """Transient identifier metadata does not satisfy the safety boundary."""


@dataclass(frozen=True)
class DeviceAttemptLink:
    attempt_id: str
    state: str
    device_alias: Optional[str]
    evidence_frames: Tuple[int, ...]

    def to_dict(self) -> Dict[str, object]:
        return {
            "attempt_id": self.attempt_id,
            "state": self.state,
            "device_alias": self.device_alias,
            "evidence_frames": list(self.evidence_frames),
        }


@dataclass(frozen=True)
class DeviceSession:
    alias: str
    first_frame: int
    last_frame: int
    duration_ms: int
    frame_count: int
    evidence_frames: Tuple[int, ...]
    evidence_frames_omitted: int
    evidence_types: Tuple[str, ...]
    protocols_observed: Tuple[str, ...]
    ap_aliases: Tuple[str, ...]
    linked_attempt_ids: Tuple[str, ...]
    device_identity_confirmed: bool
    cross_protocol_session_confirmed: bool

    def to_dict(self) -> Dict[str, object]:
        return {
            "alias": self.alias,
            "first_frame": self.first_frame,
            "last_frame": self.last_frame,
            "duration_ms": self.duration_ms,
            "frame_count": self.frame_count,
            "evidence_frames": list(self.evidence_frames),
            "evidence_frames_omitted": self.evidence_frames_omitted,
            "evidence_types": list(self.evidence_types),
            "protocols_observed": list(self.protocols_observed),
            "ap_aliases": list(self.ap_aliases),
            "linked_attempt_ids": list(self.linked_attempt_ids),
            "device_identity_confirmed": self.device_identity_confirmed,
            "cross_protocol_session_confirmed": self.cross_protocol_session_confirmed,
        }


@dataclass(frozen=True)
class DeviceSessionReport:
    profile_id: str
    profile_version: str
    frames_observed: int
    expected_frames: Optional[int]
    complete: bool
    devices: Tuple[DeviceSession, ...]
    attempt_links: Tuple[DeviceAttemptLink, ...]
    frames_unassigned: int
    frames_ambiguous: int
    attempts_unassigned: int
    attempts_ambiguous: int
    missing_optional_fields: Tuple[str, ...]
    raw_identifiers_serialized: bool
    alias_secret_persisted: bool
    aliases_stable_across_runs: bool
    cautions: Tuple[str, ...]

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema_version": 1,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "frames_observed": self.frames_observed,
            "expected_frames": self.expected_frames,
            "complete": self.complete,
            "devices_total": len(self.devices),
            "devices": [item.to_dict() for item in self.devices],
            "attempt_links": [item.to_dict() for item in self.attempt_links],
            "frames_unassigned": self.frames_unassigned,
            "frames_ambiguous": self.frames_ambiguous,
            "attempts_unassigned": self.attempts_unassigned,
            "attempts_ambiguous": self.attempts_ambiguous,
            "missing_optional_fields": list(self.missing_optional_fields),
            "raw_identifiers_serialized": self.raw_identifiers_serialized,
            "alias_secret_persisted": self.alias_secret_persisted,
            "aliases_stable_across_runs": self.aliases_stable_across_runs,
            "cautions": list(self.cautions),
        }


@dataclass(frozen=True)
class _FrameIdentity:
    frame_number: int
    relative_time_ms: int
    protocols: Tuple[str, ...]
    address_keys: Tuple[bytes, ...]
    bssid_key: Optional[bytes]
    direct_keys: Tuple[Tuple[bytes, str], ...]


class _AliasRegistry:
    """Store only keyed digests, never normalized raw address values."""

    def __init__(self, prefix: str, secret: bytes, domain: bytes, maximum: int) -> None:
        self._prefix = prefix
        self._secret = secret
        self._domain = domain
        self._maximum = maximum
        self._aliases: Dict[bytes, str] = {}

    def key(self, normalized_address: bytes) -> bytes:
        return hmac.new(
            self._secret,
            self._domain + b"\x00" + normalized_address,
            hashlib.sha256,
        ).digest()

    def ensure_key(self, key: bytes) -> str:
        existing = self._aliases.get(key)
        if existing is not None:
            return existing
        if len(self._aliases) >= self._maximum:
            raise DeviceSessionError("가명화 대상 수가 안전 제한을 초과했습니다.")
        alias = self._prefix + "-" + str(len(self._aliases) + 1)
        self._aliases[key] = alias
        return alias

    def lookup_key(self, key: bytes) -> Optional[str]:
        return self._aliases.get(key)


class _DeviceAccumulator:
    def __init__(self, alias: str, frame_number: int, relative_time_ms: int) -> None:
        self.alias = alias
        self.first_frame = frame_number
        self.last_frame = frame_number
        self.first_time_ms = relative_time_ms
        self.last_time_ms = relative_time_ms
        self.frames: List[int] = []
        self._frame_set: Set[int] = set()
        self.evidence_types: Set[str] = set()
        self.protocols: Set[str] = set()
        self.ap_aliases: Set[str] = set()
        self.attempt_ids: Set[str] = set()

    def add_frame(
        self,
        frame_number: int,
        relative_time_ms: int,
        protocols: Iterable[str],
        evidence_types: Iterable[str],
        ap_alias: Optional[str],
    ) -> None:
        if frame_number not in self._frame_set:
            self._frame_set.add(frame_number)
            self.frames.append(frame_number)
        self.first_frame = min(self.first_frame, frame_number)
        self.last_frame = max(self.last_frame, frame_number)
        self.first_time_ms = min(self.first_time_ms, relative_time_ms)
        self.last_time_ms = max(self.last_time_ms, relative_time_ms)
        self.protocols.update(protocols)
        self.evidence_types.update(evidence_types)
        if ap_alias is not None:
            self.ap_aliases.add(ap_alias)

    def freeze(self) -> DeviceSession:
        frames = tuple(sorted(self.frames))
        evidence = frames[:_MAX_EVIDENCE_FRAMES]
        return DeviceSession(
            alias=self.alias,
            first_frame=self.first_frame,
            last_frame=self.last_frame,
            duration_ms=self.last_time_ms - self.first_time_ms,
            frame_count=len(frames),
            evidence_frames=evidence,
            evidence_frames_omitted=max(0, len(frames) - len(evidence)),
            evidence_types=tuple(sorted(self.evidence_types)),
            protocols_observed=tuple(sorted(self.protocols)),
            ap_aliases=tuple(sorted(self.ap_aliases, key=_numeric_alias_key)),
            linked_attempt_ids=tuple(sorted(self.attempt_ids)),
            device_identity_confirmed=False,
            cross_protocol_session_confirmed=False,
        )


def _numeric_alias_key(value: str) -> Tuple[str, int]:
    prefix, separator, number = value.rpartition("-")
    if not separator or not number.isdecimal():
        raise DeviceSessionError("가명 형식이 올바르지 않습니다.")
    return prefix, int(number, 10)


def _parse_uint(value: str, label: str) -> Optional[int]:
    raw = value.strip()
    if not raw:
        return None
    try:
        if raw.casefold().startswith("0x"):
            parsed = int(raw[2:], 16)
        elif raw.isascii() and raw.isdecimal():
            parsed = int(raw, 10)
        else:
            raise ValueError
    except ValueError:
        raise DeviceSessionError(label + " 값이 지원하는 정수 형식이 아닙니다.") from None
    if parsed < 0 or parsed > _MAX_INTEGER:
        raise DeviceSessionError(label + " 값이 허용 범위를 벗어났습니다.")
    return parsed


def _parse_epoch_microseconds(value: str) -> int:
    raw = value.strip()
    if not raw or raw.startswith(("+", "-")):
        raise DeviceSessionError("프레임 시간이 올바른 양수 epoch 형식이 아닙니다.")
    whole, separator, fraction = raw.partition(".")
    if not whole.isascii() or not whole.isdecimal():
        raise DeviceSessionError("프레임 시간이 올바른 epoch 형식이 아닙니다.")
    if separator and (not fraction or not fraction.isascii() or not fraction.isdecimal()):
        raise DeviceSessionError("프레임 시간의 소수부가 올바르지 않습니다.")
    if len(whole) > 15 or len(fraction) > 18:
        raise DeviceSessionError("프레임 시간이 안전 범위를 벗어났습니다.")
    value_us = int(whole, 10) * 1_000_000
    value_us += int((fraction + "000000")[:6] or "0", 10)
    if value_us > _MAX_INTEGER:
        raise DeviceSessionError("프레임 시간이 허용 범위를 벗어났습니다.")
    return value_us


def _normalize_mac(value: str, label: str) -> Optional[bytes]:
    raw = value.strip()
    if not raw:
        return None
    if len(raw) > 64 or any(ord(character) == 0 for character in raw):
        raise DeviceSessionError(label + " 값이 안전 제한을 벗어났습니다.")
    compact = raw.replace(":", "").replace("-", "").replace(".", "")
    if len(compact) != 12 or any(
        character not in "0123456789abcdefABCDEF" for character in compact
    ):
        raise DeviceSessionError(label + " 형식이 올바르지 않습니다.")
    decoded = bytes.fromhex(compact)
    if decoded == bytes(6) or decoded == bytes.fromhex("ffffffffffff"):
        return None
    if decoded[0] & 1:
        return None
    return decoded


def _protocols(value: str) -> Tuple[str, ...]:
    raw = value.strip().casefold()
    if not raw:
        return ()
    result = set()
    for token in raw.split(":"):
        if not token or _PROTOCOL_TOKEN_PATTERN.fullmatch(token) is None:
            raise DeviceSessionError("프로토콜 계층 값이 올바르지 않습니다.")
        normalized = _SAFE_PROTOCOLS.get(token)
        if normalized is not None:
            result.add(normalized)
    return tuple(sorted(result))


def _row_value(
    row: Tuple[str, ...],
    positions: Mapping[str, int],
    key: str,
) -> str:
    position = positions.get(key)
    return "" if position is None else row[position]


def _unique_addresses(values: Iterable[Optional[bytes]]) -> Tuple[bytes, ...]:
    result: List[bytes] = []
    seen = set()
    for value in values:
        if value is None or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return tuple(result)


def _direct_station_addresses(
    protocols: Sequence[str],
    subtype: Optional[int],
    auth_sequence: Optional[int],
    eapol_type: Optional[int],
    eap_code: Optional[int],
    dhcp_type: Optional[int],
    eth_source: Optional[bytes],
    eth_destination: Optional[bytes],
    wlan_source: Optional[bytes],
    wlan_destination: Optional[bytes],
    wlan_bssid: Optional[bytes],
) -> Tuple[Tuple[bytes, str], ...]:
    direct: List[Tuple[bytes, str]] = []

    def add(value: Optional[bytes], reason: str) -> None:
        if value is None or value == wlan_bssid:
            return
        pair = (value, reason)
        if pair not in direct:
            direct.append(pair)

    protocol_set = set(protocols)
    if "wlan" in protocol_set:
        if subtype in _WLAN_REQUEST_SUBTYPES:
            add(wlan_source, "wlan-management-request")
        elif subtype in _WLAN_RESPONSE_SUBTYPES:
            add(wlan_destination, "wlan-management-response")
        elif subtype == 11:
            if auth_sequence in {1, 3}:
                add(wlan_source, "wlan-authentication-request")
            elif auth_sequence in {2, 4}:
                add(wlan_destination, "wlan-authentication-response")
            else:
                candidates = _unique_addresses((wlan_source, wlan_destination))
                candidates = tuple(item for item in candidates if item != wlan_bssid)
                if len(candidates) == 1:
                    add(candidates[0], "wlan-authentication-frame")
        elif subtype in _WLAN_DISCONNECT_SUBTYPES:
            candidates = _unique_addresses((wlan_source, wlan_destination))
            candidates = tuple(item for item in candidates if item != wlan_bssid)
            if len(candidates) == 1:
                add(candidates[0], "wlan-disconnect-frame")

        if "eapol" in protocol_set or "eap" in protocol_set:
            candidates = _unique_addresses((wlan_source, wlan_destination))
            candidates = tuple(item for item in candidates if item != wlan_bssid)
            if len(candidates) == 1:
                add(candidates[0], "wlan-eap-supplicant")

    # EAP decoded inside RADIUS carries the NAD/server Ethernet addresses, not
    # the original supplicant L2 address. Only direct EAPOL/EAP frames may
    # establish an Ethernet device alias.
    if (
        "eap" in protocol_set
        and "eapol" in protocol_set
        and "radius" not in protocol_set
    ):
        if eap_code == 1:
            add(eth_destination, "ethernet-eap-request")
        elif eap_code == 2:
            add(eth_source, "ethernet-eap-response")
        elif eap_code in {3, 4}:
            add(eth_destination, "ethernet-eap-result")
    elif "eapol" in protocol_set and eapol_type in {1, 2}:
        add(eth_source, "ethernet-eapol-supplicant")

    if "dhcp" in protocol_set and dhcp_type in _CLIENT_DHCP_TYPES:
        add(eth_source, "dhcp-client")

    addresses = {item[0] for item in direct}
    if len(addresses) > 1:
        return ()
    return tuple(direct)


def _attempts(transaction_sessions: object) -> Tuple[object, ...]:
    try:
        values = getattr(transaction_sessions, "attempts")
    except (AttributeError, TypeError) as exc:
        raise DeviceSessionError("거래 시도 보고서 구조가 올바르지 않습니다.") from exc
    if not isinstance(values, (tuple, list)):
        raise DeviceSessionError("거래 시도 목록이 올바르지 않습니다.")
    if len(values) > _MAX_ATTEMPT_LINKS:
        raise DeviceSessionError("거래 시도 수가 안전 제한을 초과했습니다.")
    return tuple(values)


def _attempt_link(
    attempt: object,
    frame_devices: Mapping[int, str],
) -> DeviceAttemptLink:
    try:
        attempt_id = getattr(attempt, "attempt_id")
        evidence_frames = getattr(attempt, "evidence_frames")
    except (AttributeError, TypeError) as exc:
        raise DeviceSessionError("거래 시도 근거 구조가 올바르지 않습니다.") from exc
    if not isinstance(attempt_id, str) or _EVENT_ATTEMPT_PATTERN.fullmatch(attempt_id) is None:
        raise DeviceSessionError("거래 시도 ID가 올바르지 않습니다.")
    if not isinstance(evidence_frames, (tuple, list)):
        raise DeviceSessionError("거래 시도 근거 프레임이 올바르지 않습니다.")
    frames: List[int] = []
    aliases = set()
    for value in evidence_frames:
        if type(value) is not int or value <= 0:
            raise DeviceSessionError("거래 시도 근거 프레임 번호가 올바르지 않습니다.")
        if value not in frames:
            frames.append(value)
        alias = frame_devices.get(value)
        if alias is not None:
            aliases.add(alias)
    if len(aliases) == 1:
        return DeviceAttemptLink(attempt_id, "linked", next(iter(aliases)), tuple(frames))
    if len(aliases) > 1:
        return DeviceAttemptLink(attempt_id, "ambiguous", None, tuple(frames))
    return DeviceAttemptLink(attempt_id, "unassigned", None, tuple(frames))


def build_device_sessions(
    text: str,
    profile: ResolvedProfile,
    transaction_sessions: object,
    *,
    expected_frames: Optional[int],
) -> DeviceSessionReport:
    """Create per-analysis device aliases from transient L2 identifiers."""

    if profile.profile_id != "device-identities":
        raise DeviceSessionError("단말 가명화 전용 프로파일이 필요합니다.")
    if expected_frames is not None and (
        type(expected_frames) is not int or expected_frames < 0
    ):
        raise DeviceSessionError("예상 프레임 수가 올바르지 않습니다.")

    secret = os.urandom(32)
    if len(secret) != 32:
        raise DeviceSessionError("분석 전용 가명화 키를 만들 수 없습니다.")
    devices = _AliasRegistry("DEVICE", secret, b"device", _MAX_DEVICES)
    aps = _AliasRegistry("AP", secret, b"access-point", _MAX_APS)
    positions = {key: index for index, key in enumerate(profile.output_keys())}
    required = {"frame_number", "time_epoch", "protocols"}
    if not required.issubset(positions):
        raise DeviceSessionError("단말 가명화 필수 필드가 누락됐습니다.")

    rows: List[_FrameIdentity] = []
    first_time_us: Optional[int] = None
    previous_frame = 0
    previous_time_us = 0

    for raw_row in iter_fields_rows(text, profile):
        frame_number = _parse_uint(
            _row_value(raw_row, positions, "frame_number"),
            "프레임 번호",
        )
        if frame_number is None or frame_number <= previous_frame:
            raise DeviceSessionError("단말 가명화 프레임 순서가 올바르지 않습니다.")
        time_us = _parse_epoch_microseconds(
            _row_value(raw_row, positions, "time_epoch")
        )
        if first_time_us is None:
            first_time_us = time_us
        if time_us < previous_time_us:
            raise DeviceSessionError("단말 가명화 프레임 시간이 역순입니다.")
        previous_frame = frame_number
        previous_time_us = time_us

        protocols = _protocols(_row_value(raw_row, positions, "protocols"))
        eth_source = _normalize_mac(
            _row_value(raw_row, positions, "eth_source"),
            "Ethernet 송신 주소",
        )
        eth_destination = _normalize_mac(
            _row_value(raw_row, positions, "eth_destination"),
            "Ethernet 수신 주소",
        )
        wlan_source = _normalize_mac(
            _row_value(raw_row, positions, "wlan_source"),
            "802.11 송신 주소",
        )
        wlan_destination = _normalize_mac(
            _row_value(raw_row, positions, "wlan_destination"),
            "802.11 수신 주소",
        )
        wlan_bssid = _normalize_mac(
            _row_value(raw_row, positions, "wlan_bssid"),
            "802.11 BSSID",
        )

        subtype = _parse_uint(
            _row_value(raw_row, positions, "wlan_type_subtype"),
            "802.11 프레임 유형",
        )
        auth_sequence = _parse_uint(
            _row_value(raw_row, positions, "wlan_auth_sequence"),
            "802.11 인증 순번",
        )
        eapol_type = _parse_uint(
            _row_value(raw_row, positions, "eapol_type"),
            "EAPOL 유형",
        )
        eap_code = _parse_uint(
            _row_value(raw_row, positions, "eap_code"),
            "EAP 코드",
        )
        dhcp_type = _parse_uint(
            _row_value(raw_row, positions, "dhcp_message_type"),
            "DHCP 메시지 유형",
        )

        direct_raw = _direct_station_addresses(
            protocols,
            subtype,
            auth_sequence,
            eapol_type,
            eap_code,
            dhcp_type,
            eth_source,
            eth_destination,
            wlan_source,
            wlan_destination,
            wlan_bssid,
        )
        direct_keys: List[Tuple[bytes, str]] = []
        for address, reason in direct_raw:
            key = devices.key(address)
            devices.ensure_key(key)
            direct_keys.append((key, reason))

        address_keys = tuple(
            devices.key(address)
            for address in _unique_addresses(
                (eth_source, eth_destination, wlan_source, wlan_destination)
            )
        )
        bssid_key = None if wlan_bssid is None else aps.key(wlan_bssid)
        rows.append(
            _FrameIdentity(
                frame_number=frame_number,
                relative_time_ms=(time_us - first_time_us) // 1000,
                protocols=protocols,
                address_keys=address_keys,
                bssid_key=bssid_key,
                direct_keys=tuple(direct_keys),
            )
        )

    frames_observed = len(rows)
    if expected_frames is not None and frames_observed > expected_frames:
        raise DeviceSessionError("단말 가명화 프레임 수가 사전 점검보다 많습니다.")

    accumulators: Dict[str, _DeviceAccumulator] = {}
    frame_devices: Dict[int, str] = {}
    frames_unassigned = 0
    frames_ambiguous = 0

    for row in rows:
        aliases = {
            alias
            for key in row.address_keys
            for alias in (devices.lookup_key(key),)
            if alias is not None
        }
        aliases.update(
            devices.lookup_key(key)
            for key, _reason in row.direct_keys
            if devices.lookup_key(key) is not None
        )
        aliases.discard(None)
        if len(aliases) == 0:
            frames_unassigned += 1
            continue
        if len(aliases) > 1:
            frames_ambiguous += 1
            continue
        alias = next(iter(aliases))
        if _DEVICE_ALIAS_PATTERN.fullmatch(alias) is None:
            raise DeviceSessionError("단말 가명 형식이 올바르지 않습니다.")
        frame_devices[row.frame_number] = alias
        direct_reasons = {
            reason
            for key, reason in row.direct_keys
            if devices.lookup_key(key) == alias
        }
        if not direct_reasons:
            direct_reasons.add("known-l2-address")
        ap_alias = None
        if row.bssid_key is not None:
            ap_alias = aps.ensure_key(row.bssid_key)
            if _AP_ALIAS_PATTERN.fullmatch(ap_alias) is None:
                raise DeviceSessionError("AP 가명 형식이 올바르지 않습니다.")
        accumulator = accumulators.get(alias)
        if accumulator is None:
            accumulator = _DeviceAccumulator(
                alias,
                row.frame_number,
                row.relative_time_ms,
            )
            accumulators[alias] = accumulator
        accumulator.add_frame(
            row.frame_number,
            row.relative_time_ms,
            row.protocols,
            direct_reasons,
            ap_alias,
        )

    links: List[DeviceAttemptLink] = []
    attempts_unassigned = 0
    attempts_ambiguous = 0
    for attempt in _attempts(transaction_sessions):
        link = _attempt_link(attempt, frame_devices)
        links.append(link)
        if link.state == "linked":
            if link.device_alias is None:
                raise DeviceSessionError("연결된 거래에 단말 가명이 없습니다.")
            accumulator = accumulators.get(link.device_alias)
            if accumulator is None:
                raise DeviceSessionError("거래 연결 대상 단말이 없습니다.")
            accumulator.attempt_ids.add(link.attempt_id)
        elif link.state == "ambiguous":
            attempts_ambiguous += 1
        else:
            attempts_unassigned += 1

    device_values = tuple(
        accumulators[key].freeze()
        for key in sorted(accumulators, key=_numeric_alias_key)
    )
    complete = (
        expected_frames is not None
        and frames_observed == expected_frames
        and getattr(transaction_sessions, "complete", False) is True
    )
    cautions = [
        "DEVICE-N과 AP-N은 현재 분석 실행에서만 의미가 있는 순번이며 다음 실행에서 동일 대상을 보장하지 않습니다.",
        "원본 L2 주소는 전용 TShark 출력에서만 읽고 분석 전용 HMAC 키로 변환하며 결과·로그·파일에 기록하지 않습니다.",
        "서로 다른 프로토콜 거래가 같은 DEVICE-N에 연결돼도 하나의 사용자 접속 전체가 확정됐다는 뜻은 아닙니다.",
        "RADIUS 트래픽처럼 단말 L2 주소가 보이지 않는 거래는 단말에 연결하지 않습니다.",
        "프레임에 둘 이상의 알려진 단말 주소가 있으면 잘못된 결합을 피하기 위해 모호함으로 남깁니다.",
    ]
    if expected_frames is None or frames_observed != expected_frames:
        cautions.insert(
            0,
            "일부 프레임만 처리되어 단말별 프레임과 거래 연결은 부분 결과입니다.",
        )
    if getattr(transaction_sessions, "complete", False) is not True:
        cautions.insert(
            0,
            "거래 시도 보고서가 일부 결과라 단말별 거래 연결도 일부 결과입니다.",
        )
    if not device_values:
        cautions.insert(
            0,
            "802.11 관리·EAP·DHCP 클라이언트 근거에서 단말 가명을 만들지 못했습니다.",
        )

    return DeviceSessionReport(
        profile_id=profile.profile_id,
        profile_version=profile.profile_version,
        frames_observed=frames_observed,
        expected_frames=expected_frames,
        complete=complete,
        devices=device_values,
        attempt_links=tuple(links),
        frames_unassigned=frames_unassigned,
        frames_ambiguous=frames_ambiguous,
        attempts_unassigned=attempts_unassigned,
        attempts_ambiguous=attempts_ambiguous,
        missing_optional_fields=profile.missing_optional_fields,
        raw_identifiers_serialized=False,
        alias_secret_persisted=False,
        aliases_stable_across_runs=False,
        cautions=tuple(cautions),
    )
