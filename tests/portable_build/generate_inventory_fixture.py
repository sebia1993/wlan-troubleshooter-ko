#!/usr/bin/env python3
"""Generate a minimal ARP plus DNS PCAP for the Portable integration test."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path
from typing import Sequence


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(int.from_bytes(data[index : index + 2], "big") for index in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _arp_frame() -> bytes:
    destination = bytes.fromhex("ffffffffffff")
    source = bytes.fromhex("020000000001")
    ethernet = destination + source + struct.pack("!H", 0x0806)
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
    arp += source
    arp += bytes((192, 0, 2, 1))
    arp += bytes(6)
    arp += bytes((192, 0, 2, 2))
    return ethernet + arp


def _dns_frame() -> bytes:
    destination = bytes.fromhex("020000000002")
    source = bytes.fromhex("020000000001")
    ethernet = destination + source + struct.pack("!H", 0x0800)

    query_name = b"\x07example\x04test\x00"
    dns = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    dns += query_name + struct.pack("!HH", 1, 1)
    udp_length = 8 + len(dns)
    udp = struct.pack("!HHHH", 53000, 53, udp_length, 0)

    source_ip = bytes((192, 0, 2, 1))
    destination_ip = bytes((192, 0, 2, 53))
    total_length = 20 + udp_length
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0x1234,
        0x4000,
        64,
        17,
        0,
        source_ip,
        destination_ip,
    )
    checksum = _checksum(header)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0x1234,
        0x4000,
        64,
        17,
        checksum,
        source_ip,
        destination_ip,
    )
    return ethernet + header + udp + dns


def build_pcap() -> bytes:
    output = bytearray(bytes.fromhex("d4c3b2a1"))
    output += struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    for timestamp, frame in enumerate((_arp_frame(), _dns_frame()), start=1):
        output += struct.pack("<IIII", timestamp, 0, len(frame), len(frame))
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
