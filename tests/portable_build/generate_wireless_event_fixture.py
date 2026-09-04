#!/usr/bin/env python3
"""Generate a synthetic Radiotap plus IEEE 802.11 PCAP for Portable tests."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path
from typing import Iterable, Sequence, Tuple


STATION = bytes.fromhex("0200000000a1")
ACCESS_POINT = bytes.fromhex("0200000000b1")


def _radiotap_header() -> bytes:
    """Return a valid minimal Radiotap header with no optional fields."""

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
    header = _management_header(11, destination, source, ACCESS_POINT, sequence)
    body = struct.pack("<HHH", 0, transaction, 0)
    return header + body


def _association_request(sequence: int) -> bytes:
    header = _management_header(0, ACCESS_POINT, STATION, ACCESS_POINT, sequence)
    body = struct.pack("<HH", 0x0431, 10)
    body += bytes((0, 0))
    body += bytes((1, 1, 0x82))
    return header + body


def _association_response(sequence: int) -> bytes:
    header = _management_header(1, STATION, ACCESS_POINT, ACCESS_POINT, sequence)
    body = struct.pack("<HHH", 0x0431, 0, 0xC001)
    body += bytes((1, 1, 0x82))
    return header + body


def _qos_data_header(from_access_point: bool, sequence: int) -> bytes:
    """Build an infrastructure-mode QoS Data header used by real EAPOL traffic."""

    qos_data = (8 << 4) | (2 << 2)
    direction = 0x0200 if from_access_point else 0x0100
    frame_control = qos_data | direction
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


def _eap_packet(
    code: int,
    identifier: int,
    eap_type: int | None = None,
    data: bytes = b"",
) -> bytes:
    if eap_type is None:
        if data:
            raise ValueError("EAP Success and Failure cannot contain type data")
        body = b""
    else:
        body = bytes((eap_type,)) + data
    return struct.pack("!BBH", code, identifier, 4 + len(body)) + body


def _eapol_data(
    request: bool,
    code: int,
    identifier: int,
    sequence: int,
    eap_type: int | None,
    data: bytes = b"",
) -> bytes:
    packet = _eap_packet(code, identifier, eap_type, data)
    version = 2 if request else 1
    eapol = struct.pack("!BBH", version, 0, len(packet)) + packet
    llc_snap = bytes.fromhex("aaaa03000000888e")
    return _qos_data_header(request, sequence) + llc_snap + eapol


def _deauthentication(sequence: int) -> bytes:
    header = _management_header(12, STATION, ACCESS_POINT, ACCESS_POINT, sequence)
    return header + struct.pack("<H", 3)


def frames() -> Iterable[Tuple[int, bytes]]:
    yield 1, _authentication(True, 1)
    yield 2, _authentication(False, 2)
    yield 3, _association_request(3)
    yield 4, _association_response(4)
    yield 5, _eapol_data(True, 1, 5, 5, 1)
    yield 6, _eapol_data(False, 2, 5, 6, 1, b"synthetic-user")
    yield 7, _eapol_data(True, 3, 5, 7, None)
    yield 8, _deauthentication(8)


def build_pcap() -> bytes:
    output = bytearray(bytes.fromhex("d4c3b2a1"))
    output += struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 127)
    radiotap = _radiotap_header()
    for timestamp, dot11_frame in frames():
        frame = radiotap + dot11_frame
        output += struct.pack(
            "<IIII",
            1_700_000_100 + timestamp,
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
