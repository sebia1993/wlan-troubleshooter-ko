"""TShark 격리 경로의 링크·정체성 검사 도우미."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Tuple

from wlan_troubleshooter_ko.tshark.errors import TSharkExecutionError


_REPARSE_POINT_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _stat_is_link_or_reparse(file_stat: os.stat_result) -> bool:
    return stat.S_ISLNK(file_stat.st_mode) or bool(
        (getattr(file_stat, "st_file_attributes", 0) or 0) & _REPARSE_POINT_FLAG
    )


def _absolute_path(path: Path) -> Path:
    try:
        return Path(os.path.abspath(os.fspath(path)))
    except (OSError, TypeError, ValueError) as exc:
        raise TSharkExecutionError("격리 작업공간 경로가 올바르지 않습니다.") from exc


def _path_components(path: Path):
    current = Path(path.anchor)
    if path.anchor:
        yield current
        remaining = path.parts[1:]
    else:
        remaining = path.parts
    for part in remaining:
        current = current / part
        yield current


def _reject_existing_linked_components(path: Path, allow_missing_tail: bool = False) -> Path:
    """해석 전 경로의 symlink와 Windows reparse point를 모두 거부한다."""

    absolute = _absolute_path(path)
    missing = False
    for component in _path_components(absolute):
        if missing:
            continue
        try:
            component_stat = os.lstat(component)
        except FileNotFoundError:
            if allow_missing_tail:
                missing = True
                continue
            raise TSharkExecutionError("격리 작업공간을 사용할 수 없습니다.") from None
        except (OSError, ValueError):
            raise TSharkExecutionError("격리 작업공간을 확인할 수 없습니다.") from None
        if _stat_is_link_or_reparse(component_stat):
            raise TSharkExecutionError(
                "격리 작업공간에 링크 또는 reparse point를 사용할 수 없습니다."
            )
    return absolute


def _stat_snapshot(file_stat: os.stat_result) -> Tuple[int, ...]:
    return (
        file_stat.st_dev,
        file_stat.st_ino,
        stat.S_IFMT(file_stat.st_mode),
        file_stat.st_nlink,
        file_stat.st_size,
        getattr(file_stat, "st_mtime_ns", int(file_stat.st_mtime * 1_000_000_000)),
        getattr(file_stat, "st_ctime_ns", int(file_stat.st_ctime * 1_000_000_000)),
        getattr(file_stat, "st_file_attributes", 0) or 0,
    )


def _same_directory_identity(current: os.stat_result, expected: Tuple[int, ...]) -> bool:
    snapshot = _stat_snapshot(current)
    return all(snapshot[index] == expected[index] for index in (0, 1, 2, 3, 7))
