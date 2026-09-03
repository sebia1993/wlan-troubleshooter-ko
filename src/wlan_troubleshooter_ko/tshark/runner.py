"""Phase 2 실행 없이 격리된 TShark 호출 경계만 준비한다."""

from __future__ import annotations

import os
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Optional, Tuple

from wlan_troubleshooter_ko.tshark.manifest import (
    revalidate_bundle_snapshot,
    verify_bundle,
)
from wlan_troubleshooter_ko.tshark.policy import build_analysis_argv


_PASSTHROUGH_ENVIRONMENT = (
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
)
_REPARSE_POINT_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class TSharkExecutionError(RuntimeError):
    """TShark 실행 준비 경계가 안전하지 않은 경우."""


@dataclass(frozen=True)
class PreparedTSharkInvocation:
    """실행되지 않은 승인 argv와 격리 환경."""

    arguments: Tuple[str, ...]
    environment: Mapping[str, str]


@dataclass(frozen=True)
class _PreparedIsolation:
    """이 호출이 배타적으로 만든 빈 격리 디렉터리의 정체성."""

    root: Path
    root_snapshot: Tuple[int, ...]
    directory_snapshots: Tuple[Tuple[Path, Tuple[int, ...]], ...]
    environment: Mapping[str, str]


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


def build_isolated_environment(
    isolation_root: Path,
    source_environment: Optional[Mapping[str, str]] = None,
) -> Mapping[str, str]:
    """아직 존재하지 않는 경로에 호출 전용의 빈 TShark 환경을 만든다."""

    return dict(_prepare_isolated_environment(isolation_root, source_environment).environment)


def prepare_fields_invocation(
    vendor_root: Path,
    capture_path: Path,
    isolation_root: Path,
    display_filter_name: str = "capture-overview",
    fields: Iterable[str] = ("frame.number", "frame.time_epoch", "frame.protocols"),
) -> PreparedTSharkInvocation:
    """승인 호출을 검증해 반환하되 자식 프로세스는 절대 시작하지 않는다."""

    bundle = verify_bundle(vendor_root)
    arguments = build_analysis_argv(bundle, capture_path, display_filter_name, fields)
    environment = build_isolated_environment(isolation_root)
    return PreparedTSharkInvocation(tuple(arguments), environment)


def _stop_probe(process: object) -> None:
    try:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
    except (OSError, subprocess.SubprocessError):
        try:
            process.kill()
        except (OSError, subprocess.SubprocessError):
            pass


def probe_bundle_runtime(
    vendor_root: Path,
    isolation_root: Path,
    timeout_seconds: int = 10,
    cancel_event: Optional[threading.Event] = None,
) -> str:
    """캡처를 열지 않는 고정 `-n -v` 준비 확인만 실행한다."""

    if timeout_seconds <= 0 or timeout_seconds > 60:
        raise TSharkExecutionError("허용되지 않은 준비 확인 제한시간입니다.")
    if cancel_event is not None and cancel_event.is_set():
        raise TSharkExecutionError("TShark 준비 확인이 취소됐습니다.")
    deadline = time.monotonic() + timeout_seconds
    initial_bundle = verify_bundle(vendor_root)
    source_environment = dict(os.environ)
    prepared_isolation = _prepare_isolated_environment(isolation_root, source_environment)
    # 디렉터리 준비 중 공급망 파일이 바뀌는 경우를 막기 위해 실제 실행 직전에
    # 전체 매니페스트, 크기, 동일 핸들 해시, 경로 정체성을 다시 검증한다.
    bundle = verify_bundle(vendor_root)
    if bundle != initial_bundle:
        raise TSharkExecutionError("TShark 번들이 준비 확인 전에 변경됐습니다.")
    _validate_prepared_isolation(prepared_isolation)
    revalidate_bundle_snapshot(bundle)
    if cancel_event is not None and cancel_event.is_set():
        raise TSharkExecutionError("TShark 준비 확인이 취소됐습니다.")
    if time.monotonic() >= deadline:
        raise TSharkExecutionError("TShark 준비 확인 제한시간을 초과했습니다.")
    arguments = [str(bundle.executable), "-n", "-v"]
    try:
        process = subprocess.Popen(
            arguments,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=prepared_isolation.environment,
            cwd=str(bundle.root),
            close_fds=True,
        )
    except OSError:
        raise TSharkExecutionError("TShark 준비 확인을 시작할 수 없습니다.") from None
    while True:
        if cancel_event is not None and cancel_event.is_set():
            _stop_probe(process)
            raise TSharkExecutionError("TShark 준비 확인이 취소됐습니다.")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _stop_probe(process)
            raise TSharkExecutionError("TShark 준비 확인 제한시간을 초과했습니다.")
        try:
            return_code = process.wait(timeout=min(0.1, remaining))
            break
        except subprocess.TimeoutExpired:
            continue
        except (OSError, subprocess.SubprocessError):
            _stop_probe(process)
            raise TSharkExecutionError("TShark 준비 확인을 완료할 수 없습니다.") from None
    if return_code != 0:
        raise TSharkExecutionError("TShark 준비 확인이 실패했습니다.")
    return bundle.version
