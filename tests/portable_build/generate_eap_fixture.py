#!/usr/bin/env python3
"""Generate a minimal synthetic PPP EAP request, response, and success PCAP."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path
from typing import Iterable, Sequence, Tuple


PPP_ADDRESS_CONTROL = bytes.fromhex("ff03")
PPP_EAP_PROTOCOL = struct.pack("!H", 0xC227)


def _eap_packet(
    code: int,
    identifier: int,
    eap_type: int | None = None,
    data: bytes = b"",
) -> bytes:
    if eap_type is None:
        if data:
            raise ValueError("EAP Success and Failure cannot contain type data")
        body = b""
    else:
        body = bytes((eap_type,)) + data
    return struct.pack("!BBH", code, identifier, 4 + len(body)) + body


def _ppp_eap(packet: bytes) -> bytes:
    return PPP_ADDRESS_CONTROL + PPP_EAP_PROTOCOL + packet


def frames() -> Iterable[Tuple[int, bytes]]:
    yield 1, _ppp_eap(_eap_packet(1, 9, 1))
    yield 2, _ppp_eap(_eap_packet(2, 9, 1, b"synthetic-user"))
    yield 3, _ppp_eap(_eap_packet(3, 9))


def build_pcap() -> bytes:
    output = bytearray(bytes.fromhex("d4c3b2a1"))
    output += struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 9)
    for timestamp, frame in frames():
        output += struct.pack(
            "<IIII",
            1_700_000_200 + timestamp,
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
