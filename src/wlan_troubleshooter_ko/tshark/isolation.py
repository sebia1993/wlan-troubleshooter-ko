"""TShark 실행용 빈 격리 디렉터리와 환경 검증."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Tuple

from wlan_troubleshooter_ko.tshark.errors import TSharkExecutionError
from wlan_troubleshooter_ko.tshark.isolation_path import (
    _absolute_path,
    _reject_existing_linked_components,
    _same_directory_identity,
    _stat_is_link_or_reparse,
    _stat_snapshot,
)


_PASSTHROUGH_ENVIRONMENT = (
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
)


@dataclass(frozen=True)
class _PreparedIsolation:
    """이 호출이 배타적으로 만든 빈 격리 디렉터리의 정체성."""

    root: Path
    root_snapshot: Tuple[int, ...]
    directory_snapshots: Tuple[Tuple[Path, Tuple[int, ...]], ...]
    environment: Mapping[str, str]


def _prepare_isolated_environment(
    isolation_root: Path,
    source_environment: Optional[Mapping[str, str]] = None,
) -> _PreparedIsolation:
    """존재하지 않는 경로에 이 호출 소유의 빈 격리 트리를 만든다."""

    source = os.environ if source_environment is None else source_environment
    environment = {key: source[key] for key in _PASSTHROUGH_ENVIRONMENT if key in source}
    requested_root = _absolute_path(isolation_root)
    try:
        _reject_existing_linked_components(requested_root.parent)
        parent_stat = os.lstat(requested_root.parent)
        if _stat_is_link_or_reparse(parent_stat) or not stat.S_ISDIR(parent_stat.st_mode):
            raise TSharkExecutionError("격리 작업공간의 상위 경로가 안전하지 않습니다.")
        try:
            os.lstat(requested_root)
        except FileNotFoundError:
            pass
        else:
            raise TSharkExecutionError("기존 격리 작업공간은 재사용할 수 없습니다.")
        requested_root.mkdir(mode=0o700, parents=False, exist_ok=False)
        _reject_existing_linked_components(requested_root)
        root = requested_root.resolve(strict=True)
        root_stat = os.lstat(root)
    except TSharkExecutionError:
        raise
    except (OSError, ValueError):
        raise TSharkExecutionError("새 격리 작업공간을 만들 수 없습니다.") from None
    if _stat_is_link_or_reparse(root_stat) or not stat.S_ISDIR(root_stat.st_mode):
        raise TSharkExecutionError("격리 작업공간을 사용할 수 없습니다.")

    paths = {}
    try:
        for name in ("config", "plugins", "extcap", "data", "temp"):
            directory = root / name
            directory.mkdir(mode=0o700, parents=False, exist_ok=False)
            _reject_existing_linked_components(directory)
            directory_stat = os.lstat(directory)
            if _stat_is_link_or_reparse(directory_stat) or not stat.S_ISDIR(
                directory_stat.st_mode
            ):
                raise TSharkExecutionError("격리 하위 경로가 안전하지 않습니다.")
            paths[name] = directory
    except TSharkExecutionError:
        raise
    except (OSError, ValueError):
        raise TSharkExecutionError("격리 하위 경로를 만들 수 없습니다.") from None

    environment.update(
        {
            "WIRESHARK_CONFIG_DIR": str(paths["config"]),
            "WIRESHARK_PLUGIN_DIR": str(paths["plugins"]),
            "WIRESHARK_EXTCAP_DIR": str(paths["extcap"]),
            "WIRESHARK_DATA_DIR": str(paths["data"]),
            "TEMP": str(paths["temp"]),
            "TMP": str(paths["temp"]),
            "TMPDIR": str(paths["temp"]),
            "PYTHONUTF8": "1",
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
        }
    )
    prepared = _PreparedIsolation(
        root=root,
        root_snapshot=_stat_snapshot(os.lstat(root)),
        directory_snapshots=tuple(
            (paths[name], _stat_snapshot(os.lstat(paths[name])))
            for name in ("config", "plugins", "extcap", "data", "temp")
        ),
        environment=environment,
    )
    _validate_prepared_isolation(prepared)
    return prepared


def _validate_prepared_isolation(prepared: _PreparedIsolation) -> None:
    """소유 트리가 교체되지 않았고 정확한 빈 디렉터리만 갖는지 확인한다."""

    expected_directories = {path for path, _snapshot in prepared.directory_snapshots}
    try:
        _reject_existing_linked_components(prepared.root)
        if prepared.root.resolve(strict=True) != prepared.root:
            raise TSharkExecutionError("격리 작업공간 정체성이 변경됐습니다.")
        root_before = os.lstat(prepared.root)
        if (
            _stat_is_link_or_reparse(root_before)
            or not stat.S_ISDIR(root_before.st_mode)
            or _stat_snapshot(root_before) != prepared.root_snapshot
        ):
            raise TSharkExecutionError("격리 작업공간 정체성이 변경됐습니다.")

        discovered = set()
        with os.scandir(prepared.root) as entries:
            for entry in entries:
                entry_path = Path(entry.path)
                entry_stat = entry.stat(follow_symlinks=False)
                if (
                    _stat_is_link_or_reparse(entry_stat)
                    or not stat.S_ISDIR(entry_stat.st_mode)
                ):
                    raise TSharkExecutionError("격리 작업공간에 임의 파일이 있습니다.")
                discovered.add(entry_path)
        if discovered != expected_directories:
            raise TSharkExecutionError("격리 작업공간 구성이 변경됐습니다.")

        for directory, expected_snapshot in prepared.directory_snapshots:
            _reject_existing_linked_components(directory)
            directory_before = os.lstat(directory)
            if (
                _stat_is_link_or_reparse(directory_before)
                or not stat.S_ISDIR(directory_before.st_mode)
                or _stat_snapshot(directory_before) != expected_snapshot
            ):
                raise TSharkExecutionError("격리 하위 경로 정체성이 변경됐습니다.")
            with os.scandir(directory) as entries:
                if next(entries, None) is not None:
                    raise TSharkExecutionError(
                        "격리 하위 경로에는 Lua, plugin, config 파일을 둘 수 없습니다."
                    )
            directory_after = os.lstat(directory)
            if _stat_snapshot(directory_after) != expected_snapshot:
                raise TSharkExecutionError("격리 하위 경로가 확인 중 변경됐습니다.")

        root_after = os.lstat(prepared.root)
        if _stat_snapshot(root_after) != prepared.root_snapshot:
            raise TSharkExecutionError("격리 작업공간이 확인 중 변경됐습니다.")
    except TSharkExecutionError:
        raise
    except (OSError, ValueError):
        raise TSharkExecutionError("격리 작업공간을 다시 확인할 수 없습니다.") from None


def _validate_post_execution_isolation(prepared: _PreparedIsolation) -> None:
    """실행 후 격리 트리가 교체되지 않았고 산출물이 남지 않았는지 확인한다."""

    expected_directories = {path for path, _snapshot in prepared.directory_snapshots}
    try:
        _reject_existing_linked_components(prepared.root)
        root_stat = os.lstat(prepared.root)
        if (
            _stat_is_link_or_reparse(root_stat)
            or not stat.S_ISDIR(root_stat.st_mode)
            or not _same_directory_identity(root_stat, prepared.root_snapshot)
        ):
            raise TSharkExecutionError("TShark 격리 작업공간이 교체됐습니다.")
        discovered = set()
        with os.scandir(prepared.root) as entries:
            for entry in entries:
                entry_path = Path(entry.path)
                entry_stat = entry.stat(follow_symlinks=False)
                if (
                    _stat_is_link_or_reparse(entry_stat)
                    or not stat.S_ISDIR(entry_stat.st_mode)
                ):
                    raise TSharkExecutionError("TShark가 승인되지 않은 산출물을 남겼습니다.")
                discovered.add(entry_path)
        if discovered != expected_directories:
            raise TSharkExecutionError("TShark 격리 디렉터리 구성이 변경됐습니다.")
        for directory, expected_snapshot in prepared.directory_snapshots:
            current = os.lstat(directory)
            if (
                _stat_is_link_or_reparse(current)
                or not stat.S_ISDIR(current.st_mode)
                or not _same_directory_identity(current, expected_snapshot)
            ):
                raise TSharkExecutionError("TShark 격리 하위 경로가 교체됐습니다.")
            with os.scandir(directory) as entries:
                if next(entries, None) is not None:
                    raise TSharkExecutionError("TShark가 격리 경로에 파일을 남겼습니다.")
    except TSharkExecutionError:
        raise
    except (OSError, ValueError):
        raise TSharkExecutionError("TShark 종료 후 격리 상태를 확인할 수 없습니다.") from None


def build_isolated_environment(
    isolation_root: Path,
    source_environment: Optional[Mapping[str, str]] = None,
) -> Mapping[str, str]:
    """아직 존재하지 않는 경로에 호출 전용의 빈 TShark 환경을 만든다."""

    return dict(_prepare_isolated_environment(isolation_root, source_environment).environment)
