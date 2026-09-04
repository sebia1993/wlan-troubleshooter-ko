#!/usr/bin/env python3
"""Generate a synthetic Ethernet PCAP with authentication and network events."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path
from typing import Iterable, Sequence, Tuple


CLIENT_MAC = bytes.fromhex("020000000010")
SERVER_MAC = bytes.fromhex("020000000020")
BROADCAST_MAC = bytes.fromhex("ffffffffffff")
CLIENT_IP = bytes((192, 0, 2, 10))
DHCP_SERVER_IP = bytes((192, 0, 2, 1))
DNS_SERVER_IP = bytes((192, 0, 2, 53))
RADIUS_SERVER_IP = bytes((198, 51, 100, 10))
WEB_SERVER_IP = bytes((198, 51, 100, 20))


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


def _ethernet(destination: bytes, source: bytes, ethertype: int, payload: bytes) -> bytes:
    return destination + source + struct.pack("!H", ethertype) + payload


def _ipv4(source: bytes, destination: bytes, protocol: int, payload: bytes, identification: int) -> bytes:
    total_length = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        identification & 0xFFFF,
        0x4000,
        64,
        protocol,
        0,
        source,
        destination,
    )
    checksum = _checksum(header)
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        identification & 0xFFFF,
        0x4000,
        64,
        protocol,
        checksum,
        source,
        destination,
    ) + payload


def _udp(source_port: int, destination_port: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload


def _udp_frame(
    source_mac: bytes,
    destination_mac: bytes,
    source_ip: bytes,
    destination_ip: bytes,
    source_port: int,
    destination_port: int,
    payload: bytes,
    identification: int,
) -> bytes:
    return _ethernet(
        destination_mac,
        source_mac,
        0x0800,
        _ipv4(
            source_ip,
            destination_ip,
            17,
            _udp(source_port, destination_port, payload),
            identification,
        ),
    )


def _arp(opcode: int, sender_mac: bytes, sender_ip: bytes, target_mac: bytes, target_ip: bytes) -> bytes:
    payload = struct.pack("!HHBBH", 1, 0x0800, 6, 4, opcode)
    payload += sender_mac + sender_ip + target_mac + target_ip
    destination = BROADCAST_MAC if opcode == 1 else target_mac
    return _ethernet(destination, sender_mac, 0x0806, payload)


def _eap_packet(code: int, identifier: int, eap_type: int | None = None) -> bytes:
    body = b"" if eap_type is None else bytes((eap_type,))
    return struct.pack("!BBH", code, identifier, 4 + len(body)) + body


def _eapol(eap_packet: bytes, source: bytes, destination: bytes) -> bytes:
    eapol_header = struct.pack("!BBH", 2, 0, len(eap_packet))
    return _ethernet(destination, source, 0x888E, eapol_header + eap_packet)


def _radius(code: int, identifier: int) -> bytes:
    return struct.pack("!BBH", code, identifier, 20) + bytes(16)


def _dhcp(message_type: int, transaction_id: int, reply: bool) -> bytes:
    operation = 2 if reply else 1
    your_ip = CLIENT_IP if reply else bytes(4)
    fixed = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        operation,
        1,
        6,
        0,
        transaction_id,
        0,
        0x8000,
        bytes(4),
        your_ip,
        DHCP_SERVER_IP if reply else bytes(4),
        bytes(4),
        CLIENT_MAC + bytes(10),
        bytes(64),
        bytes(128),
    )
    options = bytes.fromhex("63825363")
    options += bytes((53, 1, message_type))
    options += bytes((255,))
    return fixed + options


def _dns_query(identifier: int) -> bytes:
    query_name = b"\x07example\x04test\x00"
    header = struct.pack("!HHHHHH", identifier, 0x0100, 1, 0, 0, 0)
    return header + query_name + struct.pack("!HH", 1, 1)


def _dns_response(identifier: int) -> bytes:
    query = _dns_query(identifier)[12:]
    header = struct.pack("!HHHHHH", identifier, 0x8180, 1, 1, 0, 0)
    answer = struct.pack("!HHHLH4s", 0xC00C, 1, 1, 60, 4, bytes((203, 0, 113, 9)))
    return header + query + answer


def _tcp_segment(
    source_ip: bytes,
    destination_ip: bytes,
    source_port: int,
    destination_port: int,
    sequence: int,
    acknowledgement: int,
    flags: int,
) -> bytes:
    header = struct.pack(
        "!HHLLBBHHH",
        source_port,
        destination_port,
        sequence,
        acknowledgement,
        5 << 4,
        flags,
        64240,
        0,
        0,
    )
    pseudo_header = source_ip + destination_ip + struct.pack("!BBH", 0, 6, len(header))
    checksum = _checksum(pseudo_header + header)
    return struct.pack(
        "!HHLLBBHHH",
        source_port,
        destination_port,
        sequence,
        acknowledgement,
        5 << 4,
        flags,
        64240,
        checksum,
        0,
    )


def _tcp_frame(
    source_mac: bytes,
    destination_mac: bytes,
    source_ip: bytes,
    destination_ip: bytes,
    source_port: int,
    destination_port: int,
    sequence: int,
    acknowledgement: int,
    flags: int,
    identification: int,
) -> bytes:
    segment = _tcp_segment(
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        sequence,
        acknowledgement,
        flags,
    )
    return _ethernet(
        destination_mac,
        source_mac,
        0x0800,
        _ipv4(source_ip, destination_ip, 6, segment, identification),
    )


def frames() -> Iterable[Tuple[int, bytes]]:
    transaction_id = 0x01020304
    dns_identifier = 0x1234
    radius_identifier = 7

    yield 1, _arp(1, CLIENT_MAC, CLIENT_IP, bytes(6), DHCP_SERVER_IP)
    yield 2, _arp(2, SERVER_MAC, DHCP_SERVER_IP, CLIENT_MAC, CLIENT_IP)

    yield 3, _eapol(_eap_packet(1, 9, 1), SERVER_MAC, CLIENT_MAC)
    yield 4, _eapol(_eap_packet(2, 9, 1), CLIENT_MAC, SERVER_MAC)
    yield 5, _eapol(_eap_packet(3, 9), SERVER_MAC, CLIENT_MAC)

    yield 6, _udp_frame(
        CLIENT_MAC,
        SERVER_MAC,
        CLIENT_IP,
        RADIUS_SERVER_IP,
        40000,
        1812,
        _radius(1, radius_identifier),
        6,
    )
    yield 7, _udp_frame(
        SERVER_MAC,
        CLIENT_MAC,
        RADIUS_SERVER_IP,
        CLIENT_IP,
        1812,
        40000,
        _radius(2, radius_identifier),
        7,
    )

    yield 8, _udp_frame(
        CLIENT_MAC,
        BROADCAST_MAC,
        bytes(4),
        bytes((255, 255, 255, 255)),
        68,
        67,
        _dhcp(1, transaction_id, False),
        8,
    )
    yield 9, _udp_frame(
        SERVER_MAC,
        BROADCAST_MAC,
        DHCP_SERVER_IP,
        bytes((255, 255, 255, 255)),
        67,
        68,
        _dhcp(2, transaction_id, True),
        9,
    )
    yield 10, _udp_frame(
        CLIENT_MAC,
        BROADCAST_MAC,
        bytes(4),
        bytes((255, 255, 255, 255)),
        68,
        67,
        _dhcp(3, transaction_id, False),
        10,
    )
    yield 11, _udp_frame(
        SERVER_MAC,
        BROADCAST_MAC,
        DHCP_SERVER_IP,
        bytes((255, 255, 255, 255)),
        67,
        68,
        _dhcp(5, transaction_id, True),
        11,
    )

    yield 12, _udp_frame(
        CLIENT_MAC,
        SERVER_MAC,
        CLIENT_IP,
        DNS_SERVER_IP,
        53000,
        53,
        _dns_query(dns_identifier),
        12,
    )
    yield 13, _udp_frame(
        SERVER_MAC,
        CLIENT_MAC,
        DNS_SERVER_IP,
        CLIENT_IP,
        53,
        53000,
        _dns_response(dns_identifier),
        13,
    )

    yield 14, _tcp_frame(
        CLIENT_MAC,
        SERVER_MAC,
        CLIENT_IP,
        WEB_SERVER_IP,
        50000,
        443,
        1000,
        0,
        0x02,
        14,
    )
    yield 15, _tcp_frame(
        SERVER_MAC,
        CLIENT_MAC,
        WEB_SERVER_IP,
        CLIENT_IP,
        443,
        50000,
        2000,
        1001,
        0x12,
        15,
    )
    yield 16, _tcp_frame(
        CLIENT_MAC,
        SERVER_MAC,
        CLIENT_IP,
        WEB_SERVER_IP,
        50001,
        443,
        3000,
        0,
        0x04,
        16,
    )


def build_pcap() -> bytes:
    output = bytearray(bytes.fromhex("d4c3b2a1"))
    output += struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    for timestamp, frame in frames():
        output += struct.pack("<IIII", 1_700_000_000 + timestamp, timestamp * 1000, len(frame), len(frame))
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
