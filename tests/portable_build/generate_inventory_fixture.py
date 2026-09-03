#!/usr/bin/env python3
"""Generate a minimal ARP, DNS NXDOMAIN, and TCP RST PCAP for integration."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path
from typing import Sequence


_CLIENT_MAC = bytes.fromhex("020000000001")
_DNS_MAC = bytes.fromhex("020000000035")
_SERVER_MAC = bytes.fromhex("020000000050")
_CLIENT_IP = bytes((192, 0, 2, 1))
_DNS_IP = bytes((192, 0, 2, 53))
_SERVER_IP = bytes((192, 0, 2, 80))


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
    checksum = _checksum(header)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        identification,
        0x4000,
        64,
        protocol,
        checksum,
        source,
        destination,
    )
    return header + payload


def _arp_request() -> bytes:
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
    arp += _CLIENT_MAC
    arp += _CLIENT_IP
    arp += bytes(6)
    arp += bytes((192, 0, 2, 2))
    return _ethernet(_CLIENT_MAC, bytes.fromhex("ffffffffffff"), 0x0806, arp)


def _dns_payload(flags: int) -> bytes:
    query_name = b"\x07example\x04test\x00"
    value = struct.pack("!HHHHHH", 0x1234, flags, 1, 0, 0, 0)
    return value + query_name + struct.pack("!HH", 1, 1)


def _udp(source_port: int, destination_port: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload


def _dns_query() -> bytes:
    udp = _udp(53000, 53, _dns_payload(0x0100))
    ip = _ipv4(_CLIENT_IP, _DNS_IP, 17, udp, 0x1234)
    return _ethernet(_CLIENT_MAC, _DNS_MAC, 0x0800, ip)


def _dns_nxdomain_response() -> bytes:
    udp = _udp(53, 53000, _dns_payload(0x8183))
    ip = _ipv4(_DNS_IP, _CLIENT_IP, 17, udp, 0x1235)
    return _ethernet(_DNS_MAC, _CLIENT_MAC, 0x0800, ip)


def _tcp_segment(
    source_ip: bytes,
    destination_ip: bytes,
    source_port: int,
    destination_port: int,
    sequence: int,
    acknowledgement: int,
    flags: int,
    window: int,
) -> bytes:
    segment = struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        sequence,
        acknowledgement,
        5 << 4,
        flags,
        window,
        0,
        0,
    )
    pseudo_header = (
        source_ip
        + destination_ip
        + bytes((0, 6))
        + struct.pack("!H", len(segment))
    )
    checksum = _checksum(pseudo_header + segment)
    return struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        sequence,
        acknowledgement,
        5 << 4,
        flags,
        window,
        checksum,
        0,
    )


def _tcp_syn() -> bytes:
    tcp = _tcp_segment(
        _CLIENT_IP,
        _SERVER_IP,
        50000,
        443,
        1000,
        0,
        0x02,
        64240,
    )
    ip = _ipv4(_CLIENT_IP, _SERVER_IP, 6, tcp, 0x2234)
    return _ethernet(_CLIENT_MAC, _SERVER_MAC, 0x0800, ip)


def _tcp_reset() -> bytes:
    tcp = _tcp_segment(
        _SERVER_IP,
        _CLIENT_IP,
        443,
        50000,
        0,
        1001,
        0x14,
        0,
    )
    ip = _ipv4(_SERVER_IP, _CLIENT_IP, 6, tcp, 0x2235)
    return _ethernet(_SERVER_MAC, _CLIENT_MAC, 0x0800, ip)


def build_pcap() -> bytes:
    output = bytearray(bytes.fromhex("d4c3b2a1"))
    output += struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    frames = (
        _arp_request(),
        _dns_query(),
        _dns_nxdomain_response(),
        _tcp_syn(),
        _tcp_reset(),
    )
    for timestamp, frame in enumerate(frames, start=1):
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
