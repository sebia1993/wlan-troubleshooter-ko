#!/usr/bin/env python3
"""Generate a PCAPNG with two unanswered DNS queries at known offsets."""

from __future__ import annotations

import argparse
import importlib.util
import struct
from pathlib import Path
from typing import Sequence


SHB = 0x0A0D0D0A
IDB = 0x00000001
EPB = 0x00000006

BASE_TIMESTAMP_TICKS = 1_700_005_000_000_000
PRIVATE_SECTION_COMMENT = b"private-time-section-phase4l"
PRIVATE_HARDWARE = b"private-time-hardware-phase4l"
PRIVATE_OPERATING_SYSTEM = b"private-time-os-phase4l"
PRIVATE_APPLICATION = b"private-time-application-phase4l"
PRIVATE_INTERFACE_NAME = b"private-time-interface-phase4l"
PRIVATE_INTERFACE_DESCRIPTION = b"private-time-description-phase4l"
PRIVATE_PACKET_COMMENT = b"private-time-packet-phase4l"


def _source_module():
    source = Path(__file__).resolve().with_name(
        "generate_observability_fixture.py"
    )
    specification = importlib.util.spec_from_file_location(
        "observability_fixture_for_capture_time",
        source,
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("observability fixture could not be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


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
    body += _option(3, PRIVATE_OPERATING_SYSTEM)
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


def _enhanced_packet(relative_microseconds: int, frame: bytes) -> bytes:
    timestamp = BASE_TIMESTAMP_TICKS + relative_microseconds
    body = struct.pack(
        "<IIIII",
        0,
        (timestamp >> 32) & 0xFFFFFFFF,
        timestamp & 0xFFFFFFFF,
        len(frame),
        len(frame),
    )
    body += _pad(frame)
    body += _option(1, PRIVATE_PACKET_COMMENT)
    body += _end_options()
    return _block(EPB, body)


def frames() -> tuple[tuple[int, bytes], ...]:
    source = _source_module()
    return (
        (
            0,
            source._arp(
                1,
                source._CLIENT_MAC,
                source._CLIENT_IP,
                bytes(6),
                source._GATEWAY_IP,
                bytes.fromhex("ffffffffffff"),
            ),
        ),
        (250_000, source._dns_query(0x2001, 53001)),
        (
            1_500_000,
            source._arp(
                2,
                source._GATEWAY_MAC,
                source._GATEWAY_IP,
                source._CLIENT_MAC,
                source._CLIENT_IP,
                source._CLIENT_MAC,
            ),
        ),
        (3_000_000, source._dns_query(0x2002, 53002)),
    )


def build_pcapng() -> bytes:
    blocks = [_section_header(), _interface_description()]
    blocks.extend(
        _enhanced_packet(relative_microseconds, frame)
        for relative_microseconds, frame in frames()
    )
    return b"".join(blocks)


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
