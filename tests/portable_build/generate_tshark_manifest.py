#!/usr/bin/env python3
"""Generate the runtime TShark integrity manifest from a staged directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Dict, List, Sequence


_METADATA_NAMES = {"manifest.json", "manifest.example.json", "README.md"}
_HASH_CHUNK_BYTES = 1024 * 1024


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(_HASH_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _files(root: Path) -> List[Dict[str, object]]:
    values: List[Dict[str, object]] = []
    for current, directories, names in os.walk(root, followlinks=False):
        current_path = Path(current)
        kept = []
        for name in sorted(directories):
            path = current_path / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError("TShark stage must not contain directory links")
            kept.append(name)
        directories[:] = kept
        for name in sorted(names):
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            if relative in _METADATA_NAMES:
                continue
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise ValueError("TShark stage must contain regular files only")
            values.append(
                {
                    "path": relative,
                    "sha256": _sha256(path),
                    "size_bytes": metadata.st_size,
                }
            )
    values.sort(key=lambda item: str(item["path"]).casefold())
    if not any(item["path"] == "tshark.exe" for item in values):
        raise ValueError("tshark.exe is missing")
    if not any(item["path"] == "COPYING" for item in values):
        raise ValueError("COPYING is missing")
    return values


def generate(root: Path, version: str, approval_reference: str) -> Dict[str, object]:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("TShark stage root must be a directory")
    return {
        "schema_version": 1,
        "version": version,
        "approval_reference": approval_reference,
        "executable": "tshark.exe",
        "files": _files(root),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--approval-reference", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    value = generate(arguments.root, arguments.version, arguments.approval_reference)
    output = arguments.root / "manifest.json"
    with output.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
