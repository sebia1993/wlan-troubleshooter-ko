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


def _eapol_key(
    source: object,
    message_number: int,
    sequence: int,
    replay_counter: int,
    *,
    retry: bool = False,
) -> bytes:
    from_access_point = message_number in {1, 3}
    descriptor = source._key_descriptor(message_number, replay_counter)
    eapol = struct.pack("!BBH", 2, 3, len(descriptor)) + descriptor
    llc_snap = bytes.fromhex("aaaa03000000888e")
    return (
        source._qos_data_header(
            from_access_point,
            sequence,
            retry=retry,
        )
        + llc_snap
        + eapol
    )


def frames() -> Iterable[Tuple[int, bytes]]:
    source = _source_module()
    source_frames = tuple(source.frames())
    if len(source_frames) != 9:
        raise RuntimeError("Phase 4I fixture frame layout changed")

    for timestamp, frame in source_frames[:4]:
        yield timestamp, frame
    yield 5, _eapol_key(source, 1, 5, FIRST_COUNTER)
    yield 6, _eapol_key(source, 2, 6, FIRST_COUNTER)
    yield 7, _eapol_key(source, 3, 7, LATER_COUNTER)
    yield 8, _eapol_key(source, 3, 8, LATER_COUNTER, retry=True)
    yield 9, _eapol_key(source, 4, 9, LATER_COUNTER)


def build_pcap() -> bytes:
    source = _source_module()
    output = bytearray(bytes.fromhex("d4c3b2a1"))
    output += struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 127)
    radiotap = source._radiotap_header()
    for timestamp, dot11_frame in frames():
        frame = radiotap + dot11_frame
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
