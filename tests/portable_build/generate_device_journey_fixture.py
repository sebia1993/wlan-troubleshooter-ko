#!/usr/bin/env python3
"""Generate the event fixture with a distinct RADIUS NAD L2 address.

The shared Ethernet fixture intentionally reuses a compact set of synthetic
addresses. Device-journey validation needs a realistic RADIUS path where the
outer NAD/server Ethernet addresses are not the supplicant address. Only the
Ethernet headers of RADIUS frames 6 and 7 are changed; protocol payloads remain
identical.
"""

from __future__ import annotations

import argparse
import importlib.util
import struct
from pathlib import Path
from typing import Iterable, Sequence, Tuple


NAD_MAC = bytes.fromhex("020000000030")


def _source_module():
    source_path = Path(__file__).resolve().with_name("generate_event_fixture.py")
    specification = importlib.util.spec_from_file_location(
        "portable_event_fixture_for_device_journey",
        source_path,
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("shared event fixture could not be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def frames() -> Iterable[Tuple[int, bytes]]:
    module = _source_module()
    for timestamp, original in module.frames():
        frame = original
        if timestamp == 6:
            frame = frame[:6] + NAD_MAC + frame[12:]
        elif timestamp == 7:
            frame = NAD_MAC + frame[6:]
        yield timestamp, frame


def build_pcap() -> bytes:
    output = bytearray(bytes.fromhex("d4c3b2a1"))
    output += struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    for timestamp, frame in frames():
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
