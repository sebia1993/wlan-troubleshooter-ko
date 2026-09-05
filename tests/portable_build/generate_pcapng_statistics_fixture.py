#!/usr/bin/env python3
"""Generate a PCAPNG with two packets and one Interface Statistics Block."""

from __future__ import annotations

import argparse
import importlib.util
import struct
from pathlib import Path
from typing import Sequence


PRIVATE_INTERFACE_NAME = b"Corp-WLAN-Private-Adapter"
PRIVATE_INTERFACE_DESCRIPTION = b"Internal monitor path"
START_TIME = 0x0102030405060708
END_TIME = 0x1112131415161718
BLOCK_TIME = 0x2122232425262728


def _source_module():
    source = Path(__file__).resolve().with_name("generate_inventory_fixture.py")
    specification = importlib.util.spec_from_file_location(
        "inventory_fixture_for_pcapng_statistics",
        source,
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("inventory fixture could not be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _block(block_type: int, body: bytes) -> bytes:
    if len(body) % 4:
        raise ValueError("PCAPNG block body must be padded")
    total = 12 + len(body)
    return (
        struct.pack("<II", block_type, total)
        + body
        + struct.pack("<I", total)
    )


def _option(code: int, value: bytes) -> bytes:
    padding = b"\x00" * ((4 - len(value) % 4) % 4)
    return struct.pack("<HH", code, len(value)) + value + padding


def _counter_option(code: int, value: int) -> bytes:
    return _option(code, struct.pack("<Q", value))


def _section_header() -> bytes:
    body = bytes.fromhex("4d3c2b1a") + struct.pack("<HHq", 1, 0, -1)
    return _block(0x0A0D0D0A, body)


def _interface_description() -> bytes:
    options = (
        _option(2, PRIVATE_INTERFACE_NAME)
        + _option(3, PRIVATE_INTERFACE_DESCRIPTION)
        + _option(9, b"\x06")
        + struct.pack("<HH", 0, 0)
    )
    return _block(1, struct.pack("<HHI", 1, 0, 65535) + options)


def _enhanced_packet(frame: bytes, timestamp: int) -> bytes:
    padded = frame + b"\x00" * ((4 - len(frame) % 4) % 4)
    body = struct.pack(
        "<IIIII",
        0,
        (timestamp >> 32) & 0xFFFFFFFF,
        timestamp & 0xFFFFFFFF,
        len(frame),
        len(frame),
    )
    return _block(6, body + padded)


def _interface_statistics() -> bytes:
    options = (
        _counter_option(2, START_TIME)
        + _counter_option(3, END_TIME)
        + _counter_option(4, 2)
        + _counter_option(5, 3)
        + _counter_option(6, 2)
        + _counter_option(7, 1)
        + _counter_option(8, 2)
        + struct.pack("<HH", 0, 0)
    )
    body = struct.pack(
        "<III",
        0,
        (BLOCK_TIME >> 32) & 0xFFFFFFFF,
        BLOCK_TIME & 0xFFFFFFFF,
    )
    return _block(5, body + options)


def build_pcapng() -> bytes:
    source = _source_module()
    frames = (source._arp_request(), source._dns_query())
    return (
        _section_header()
        + _interface_description()
        + _enhanced_packet(frames[0], 1_000_000)
        + _enhanced_packet(frames[1], 2_000_000)
        + _interface_statistics()
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
