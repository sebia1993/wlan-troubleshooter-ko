#!/usr/bin/env python3
"""Generate a little-endian PCAPNG with Ethernet packets and two ISBs."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path
from typing import Sequence


SHB = 0x0A0D0D0A
IDB = 0x00000001
EPB = 0x00000006
ISB = 0x00000005

CLIENT_MAC = bytes.fromhex("0200000000e1")
GATEWAY_MAC = bytes.fromhex("0200000000e2")
CLIENT_IP = bytes((192, 0, 2, 81))
GATEWAY_IP = bytes((192, 0, 2, 1))

PRIVATE_SECTION_COMMENT = b"private-section-comment-phase4k"
PRIVATE_HARDWARE = b"private-hardware-phase4k"
PRIVATE_OS = b"private-operating-system-phase4k"
PRIVATE_APPLICATION = b"private-capture-application-phase4k"
PRIVATE_INTERFACE_NAME = b"private-interface-name-phase4k"
PRIVATE_INTERFACE_DESCRIPTION = b"private-interface-description-phase4k"
PRIVATE_PACKET_COMMENT = b"private-packet-comment-phase4k"
PRIVATE_STATISTICS_COMMENT = b"private-statistics-comment-phase4k"


def _pad(value: bytes) -> bytes:
    return value + bytes((-len(value)) % 4)


def _option(code: int, value: bytes) -> bytes:
    return struct.pack("<HH", code, len(value)) + _pad(value)


def _end_options() -> bytes:
    return struct.pack("<HH", 0, 0)


def _block(block_type: int, body: bytes) -> bytes:
    if len(body) % 4:
        raise ValueError("PCAPNG block body must be aligned")
    total_length = 12 + len(body)
    return (
        struct.pack("<II", block_type, total_length)
        + body
        + struct.pack("<I", total_length)
    )


def _section_header() -> bytes:
    body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    body += _option(1, PRIVATE_SECTION_COMMENT)
    body += _option(2, PRIVATE_HARDWARE)
    body += _option(3, PRIVATE_OS)
    body += _option(4, PRIVATE_APPLICATION)
    body += _end_options()
    return _block(SHB, body)


def _interface_description() -> bytes:
    body = struct.pack("<HHI", 1, 0, 65535)
    body += _option(2, PRIVATE_INTERFACE_NAME)
    body += _option(3, PRIVATE_INTERFACE_DESCRIPTION)
    body += _option(9, bytes((6,)))
    body += _end_options()
    return _block(IDB, body)


def _ethernet(source: bytes, destination: bytes, ethertype: int, payload: bytes) -> bytes:
    return destination + source + struct.pack("!H", ethertype) + payload


def _arp(
    operation: int,
    source_mac: bytes,
    source_ip: bytes,
    target_mac: bytes,
    target_ip: bytes,
    ethernet_destination: bytes,
) -> bytes:
    payload = struct.pack("!HHBBH", 1, 0x0800, 6, 4, operation)
    payload += source_mac + source_ip + target_mac + target_ip
    return _ethernet(source_mac, ethernet_destination, 0x0806, payload)


def _enhanced_packet(frame: bytes, timestamp: int) -> bytes:
    padded = _pad(frame)
    body = struct.pack(
        "<IIIII",
        0,
        (timestamp >> 32) & 0xFFFFFFFF,
        timestamp & 0xFFFFFFFF,
        len(frame),
        len(frame),
    )
    body += padded
    body += _option(1, PRIVATE_PACKET_COMMENT)
    body += _end_options()
    return _block(EPB, body)


def _interface_statistics(
    timestamp: int,
    *,
    ifrecv: int,
    ifdrop: int,
    filteraccept: int,
    osdrop: int,
    usrdeliv: int,
) -> bytes:
    body = struct.pack(
        "<III",
        0,
        (timestamp >> 32) & 0xFFFFFFFF,
        timestamp & 0xFFFFFFFF,
    )
    body += _option(1, PRIVATE_STATISTICS_COMMENT)
    body += _option(2, struct.pack("<Q", 1_700_004_000_000_000))
    body += _option(3, struct.pack("<Q", 1_700_004_005_000_000))
    for code, value in (
        (4, ifrecv),
        (5, ifdrop),
        (6, filteraccept),
        (7, osdrop),
        (8, usrdeliv),
    ):
        body += _option(code, struct.pack("<Q", value))
    body += _end_options()
    return _block(ISB, body)


def build_pcapng() -> bytes:
    request = _arp(
        1,
        CLIENT_MAC,
        CLIENT_IP,
        bytes(6),
        GATEWAY_IP,
        bytes.fromhex("ffffffffffff"),
    )
    reply = _arp(
        2,
        GATEWAY_MAC,
        GATEWAY_IP,
        CLIENT_MAC,
        CLIENT_IP,
        CLIENT_MAC,
    )
    return b"".join(
        (
            _section_header(),
            _interface_description(),
            _enhanced_packet(request, 1_000_000),
            _interface_statistics(
                1_500_000,
                ifrecv=2,
                ifdrop=0,
                filteraccept=2,
                osdrop=0,
                usrdeliv=2,
            ),
            _enhanced_packet(reply, 2_000_000),
            _interface_statistics(
                2_500_000,
                ifrecv=4,
                ifdrop=3,
                filteraccept=4,
                osdrop=1,
                usrdeliv=4,
            ),
        )
    )


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
        handle.write(build_pcapng())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
