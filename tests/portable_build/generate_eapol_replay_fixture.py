#!/usr/bin/env python3
"""Generate the Phase 4I EAPOL fixture with distinctive 64-bit counters."""

from __future__ import annotations

import argparse
import importlib.util
import struct
from pathlib import Path
from typing import Iterable, Sequence, Tuple


FIRST_COUNTER = 18_446_744_073_709_551_000
LATER_COUNTER = FIRST_COUNTER + 1


def _source_module():
    source = Path(__file__).resolve().with_name(
        "generate_eapol_handshake_fixture.py"
    )
    specification = importlib.util.spec_from_file_location(
        "phase4i_eapol_fixture_for_replay_relations",
        source,
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("Phase 4I EAPOL fixture could not be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def frames() -> Iterable[Tuple[int, bytes]]:
    source = _source_module()
    old_first = struct.pack("!Q", 10)
    old_later = struct.pack("!Q", 11)
    new_first = struct.pack("!Q", FIRST_COUNTER)
    new_later = struct.pack("!Q", LATER_COUNTER)
    first_replacements = 0
    later_replacements = 0
    output = []
    for timestamp, original in source.frames():
        first_count = original.count(old_first)
        later_count = original.count(old_later)
        if first_count > 1 or later_count > 1 or (first_count and later_count):
            raise RuntimeError("unexpected Replay Counter layout")
        frame = original
        if first_count:
            frame = frame.replace(old_first, new_first, 1)
            first_replacements += 1
        elif later_count:
            frame = frame.replace(old_later, new_later, 1)
            later_replacements += 1
        output.append((timestamp, frame))
    if (first_replacements, later_replacements) != (2, 3):
        raise RuntimeError("expected M1/M2 and M3/M3/M4 counters were not found")
    return tuple(output)


def build_pcap() -> bytes:
    output = bytearray(bytes.fromhex("d4c3b2a1"))
    output += struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 127)
    for timestamp, frame in frames():
        output += struct.pack(
            "<IIII",
            1_700_003_000 + timestamp,
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
