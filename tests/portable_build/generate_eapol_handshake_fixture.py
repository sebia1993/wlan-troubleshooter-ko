#!/usr/bin/env python3
"""Generate a synthetic Radiotap/802.11 EAPOL-Key sequence.

The capture contains open-system authentication, association and the message
number pattern M1, M2, M3, retry-bit M3, M4. All addresses and key material are
reserved synthetic test values. The product output must never serialize any of
those raw values.
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path
from typing import Iterable, Sequence, Tuple


STATION = bytes.fromhex("0200000000c1")
ACCESS_POINT = bytes.fromhex("0200000000d1")

_KEY_DESCRIPTOR_VERSION_2 = 0x0002
_PAIRWISE_KEY = 0x0008
_INSTALL = 0x0040
_KEY_ACK = 0x0080
_KEY_MIC = 0x0100
_SECURE = 0x0200

_MESSAGE_KEY_INFO = {
    1: _KEY_DESCRIPTOR_VERSION_2 | _PAIRWISE_KEY | _KEY_ACK,
    2: _KEY_DESCRIPTOR_VERSION_2 | _PAIRWISE_KEY | _KEY_MIC,
    3: (
        _KEY_DESCRIPTOR_VERSION_2
        | _PAIRWISE_KEY
        | _INSTALL
        | _KEY_ACK
        | _KEY_MIC
        | _SECURE
    ),
    4: _KEY_DESCRIPTOR_VERSION_2 | _PAIRWISE_KEY | _KEY_MIC | _SECURE,
}


def _radiotap_header() -> bytes:
    return struct.pack("<BBHI", 0, 0, 8, 0)


def _management_header(
    subtype: int,
    destination: bytes,
    source: bytes,
    bssid: bytes,
    sequence: int,
) -> bytes:
    frame_control = (subtype & 0xF) << 4
    return (
        struct.pack("<HH", frame_control, 0)
        + destination
        + source
        + bssid
        + struct.pack("<H", (sequence & 0xFFF) << 4)
    )


def _authentication(request: bool, sequence: int) -> bytes:
    source = STATION if request else ACCESS_POINT
    destination = ACCESS_POINT if request else STATION
    transaction = 1 if request else 2
    header = _management_header(
        11,
        destination,
        source,
        ACCESS_POINT,
        sequence,
    )
    return header + struct.pack("<HHH", 0, transaction, 0)


def _association_request(sequence: int) -> bytes:
    header = _management_header(
        0,
        ACCESS_POINT,
        STATION,
        ACCESS_POINT,
        sequence,
    )
    body = struct.pack("<HH", 0x0431, 10)
    body += bytes((0, 0))
    body += bytes((1, 1, 0x82))
    return header + body


def _association_response(sequence: int) -> bytes:
    header = _management_header(
        1,
        STATION,
        ACCESS_POINT,
        ACCESS_POINT,
        sequence,
    )
    body = struct.pack("<HHH", 0x0431, 0, 0xC001)
    body += bytes((1, 1, 0x82))
    return header + body


def _qos_data_header(
    from_access_point: bool,
    sequence: int,
    *,
    retry: bool,
) -> bytes:
    qos_data = (8 << 4) | (2 << 2)
    direction = 0x0200 if from_access_point else 0x0100
    retry_flag = 0x0800 if retry else 0
    frame_control = qos_data | direction | retry_flag
    if from_access_point:
        destination, source = STATION, ACCESS_POINT
    else:
        destination, source = ACCESS_POINT, STATION
    return (
        struct.pack("<HH", frame_control, 0)
        + destination
        + source
        + ACCESS_POINT
        + struct.pack("<H", (sequence & 0xFFF) << 4)
        + struct.pack("<H", 0)
    )


def _key_descriptor(
    message_number: int,
    replay_counter: int,
) -> bytes:
    key_info = _MESSAGE_KEY_INFO[message_number]
    if message_number in {1, 3}:
        nonce = bytes((0xA0 + message_number,)) * 32
    elif message_number == 2:
        nonce = bytes((0xB2,)) * 32
    else:
        nonce = bytes(32)
    key_iv = bytes(16)
    key_rsc = bytes(8)
    key_id = bytes(8)
    key_mic = bytes((0xCC,)) * 16 if key_info & _KEY_MIC else bytes(16)
    key_data = b""
    return (
        struct.pack("!BHHQ", 2, key_info, 16, replay_counter)
        + nonce
        + key_iv
        + key_rsc
        + key_id
        + key_mic
        + struct.pack("!H", len(key_data))
        + key_data
    )


def _eapol_key(
    message_number: int,
    sequence: int,
    *,
    retry: bool = False,
) -> bytes:
    from_access_point = message_number in {1, 3}
    replay_counter = 1 if message_number in {1, 2} else 2
    descriptor = _key_descriptor(message_number, replay_counter)
    eapol = struct.pack("!BBH", 2, 3, len(descriptor)) + descriptor
    llc_snap = bytes.fromhex("aaaa03000000888e")
    return (
        _qos_data_header(
            from_access_point,
            sequence,
            retry=retry,
        )
        + llc_snap
        + eapol
    )


def frames() -> Iterable[Tuple[int, bytes]]:
    yield 1, _authentication(True, 1)
    yield 2, _authentication(False, 2)
    yield 3, _association_request(3)
    yield 4, _association_response(4)
    yield 5, _eapol_key(1, 5)
    yield 6, _eapol_key(2, 6)
    yield 7, _eapol_key(3, 7)
    yield 8, _eapol_key(3, 8, retry=True)
    yield 9, _eapol_key(4, 9)


def build_pcap() -> bytes:
    output = bytearray(bytes.fromhex("d4c3b2a1"))
    output += struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 127)
    radiotap = _radiotap_header()
    for timestamp, dot11_frame in frames():
        frame = radiotap + dot11_frame
        output += struct.pack(
            "<IIII",
            1_700_002_000 + timestamp,
            timestamp * 1000,
            len(frame),
            len(frame),
        )
        output += frame
    return bytes(output)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    output = arguments.output.resolve()
    if not output.parent.is_dir() or output.exists():
        raise ValueError("output must be a new file in an existing directory")
    with output.open("xb") as handle:
        handle.write(build_pcap())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
