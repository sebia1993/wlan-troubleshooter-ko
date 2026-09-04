#!/usr/bin/env python3
"""Generate ARP and two unanswered DNS queries for observability tests."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path
from typing import Sequence


_CLIENT_MAC = bytes.fromhex("020000000010")
_GATEWAY_MAC = bytes.fromhex("020000000001")
_DNS_MAC = bytes.fromhex("020000000035")
_CLIENT_IP = bytes((192, 0, 2, 10))
_GATEWAY_IP = bytes((192, 0, 2, 1))
_DNS_IP = bytes((192, 0, 2, 53))


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(
        int.from_bytes(data[index : index + 2], "big")
        for index in range(0, len(data), 2)
    )
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ethernet(source: bytes, destination: bytes, ethertype: int, payload: bytes) -> bytes:
    return destination + source + struct.pack("!H", ethertype) + payload


def _ipv4(
    source: bytes,
    destination: bytes,
    protocol: int,
    payload: bytes,
    identification: int,
) -> bytes:
    total_length = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        identification,
        0x4000,
        64,
        protocol,
        0,
        source,
        destination,
    )
    header_checksum = _checksum(header)
    return (
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            total_length,
            identification,
            0x4000,
            64,
            protocol,
            header_checksum,
            source,
            destination,
        )
        + payload
    )


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


def _dns_query(identifier: int, source_port: int) -> bytes:
    query_name = b"\x0dobservability\x07invalid\x00"
    dns = struct.pack("!HHHHHH", identifier, 0x0100, 1, 0, 0, 0)
    dns += query_name + struct.pack("!HH", 1, 1)
    udp = struct.pack("!HHHH", source_port, 53, 8 + len(dns), 0) + dns
    ip = _ipv4(_CLIENT_IP, _DNS_IP, 17, udp, 0x3000 + identifier)
    return _ethernet(_CLIENT_MAC, _DNS_MAC, 0x0800, ip)


def build_pcap() -> bytes:
    frames = (
        _arp(
            1,
            _CLIENT_MAC,
            _CLIENT_IP,
            bytes(6),
            _GATEWAY_IP,
            bytes.fromhex("ffffffffffff"),
        ),
        _dns_query(0x2001, 53001),
        _arp(
            2,
            _GATEWAY_MAC,
            _GATEWAY_IP,
            _CLIENT_MAC,
            _CLIENT_IP,
            _CLIENT_MAC,
        ),
        _dns_query(0x2002, 53002),
    )
    output = bytearray(bytes.fromhex("d4c3b2a1"))
    output += struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    for index, frame in enumerate(frames, start=1):
        output += struct.pack(
            "<IIII",
            1_700_001_000 + index,
            index * 1000,
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
