"""격리된 Portable TShark 준비 확인과 제한된 Phase 2B 실행 경계."""

from __future__ import annotations

import os
import queue
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Mapping, Optional, Tuple

from wlan_troubleshooter_ko.analysis.protocol_inventory import (
    ProtocolInventory,
    build_protocol_inventory,
)
from wlan_troubleshooter_ko.core.capture import CaptureInfo, validate_capture
from wlan_troubleshooter_ko.tshark.catalog import FieldCatalog, parse_field_catalog
from wlan_troubleshooter_ko.tshark.manifest import (
    VerifiedBundle,
    revalidate_bundle_snapshot,
    verify_bundle,
)
from wlan_troubleshooter_ko.tshark.policy import (
    build_analysis_argv,
    build_field_catalog_argv,
    build_profile_argv,
)
from wlan_troubleshooter_ko.tshark.profiles import (
    ResolvedProfile,
    load_field_profiles,
    resolve_profile,
)


_PASSTHROUGH_ENVIRONMENT = (
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
)
_REPARSE_POINT_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_STREAM_CHUNK_BYTES = 64 * 1024


class TSharkExecutionError(RuntimeError):
    """TShark 실행 준비 또는 제한된 실행 경계가 안전하지 않은 경우."""


@dataclass(frozen=True)
class PreparedTSharkInvocation:
    """실행되지 않은 승인 argv와 격리 환경."""

    arguments: Tuple[str, ...]
    environment: Mapping[str, str]


@dataclass(frozen=True)
class FieldCatalogRun:
    bundle_version: str
    manifest_sha256: str
    catalog: FieldCatalog


@dataclass(frozen=True)
class ProtocolInventoryRun:
    bundle_version: str
    manifest_sha256: str
    resolved_profile: ResolvedProfile
    catalog_records: int
    inventory: ProtocolInventory

    def to_dict(self) -> Dict[str, object]:
        return {
            "bundle_version": self.bundle_version,
            "manifest_sha256": self.manifest_sha256,
            "profile_id": self.resolved_profile.profile_id,
            "profile_version": self.resolved_profile.profile_version,
            "resolved_fields": list(self.resolved_profile.headers()),
            "catalog_records": self.catalog_records,
            "inventory": self.inventory.to_dict(),
        }


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


def _same_directory_identity(current: os.stat_result, expected: Tuple[int, ...]) -> bool:
    snapshot = _stat_snapshot(current)
    return all(snapshot[index] == expected[index] for index in (0, 1, 2, 3, 7))


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
                if _stat_is_link_or_reparse(entry_stat) or not stat.S_ISDIR(entry_stat.st_mode):
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
    """TShark 종료 후 예상 디렉터리 외 산출물이 남지 않았는지 확인한다."""

    expected_directories = {path for path, _snapshot in prepared.directory_snapshots}
    try:
        _reject_existing_linked_components(prepared.root)
        root_stat = os.lstat(prepared.root)
        if (
            _stat_is_link_or_reparse(root_stat)
            or not stat.S_ISDIR(root_stat.st_mode)
            or not _same_directory_identity(root_stat, prepared.root_snapshot)
        ):
            raise TSharkExecutionError("격리 작업공간 정체성이 변경됐습니다.")
        discovered = set()
        with os.scandir(prepared.root) as entries:
            for entry in entries:
                entry_path = Path(entry.path)
                entry_stat = entry.stat(follow_symlinks=False)
                if _stat_is_link_or_reparse(entry_stat) or not stat.S_ISDIR(entry_stat.st_mode):
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


def _put_stream_event(events, stop_event, value) -> None:
    while not stop_event.is_set():
        try:
            events.put(value, timeout=0.1)
            return
        except queue.Full:
            continue


def _pump_stream(name: str, stream, events, stop_event: threading.Event) -> None:
    try:
        while not stop_event.is_set():
            chunk = stream.read(_STREAM_CHUNK_BYTES)
            if not chunk:
                break
            _put_stream_event(events, stop_event, (name, "data", chunk))
    except (OSError, ValueError):
        _put_stream_event(events, stop_event, (name, "error", b""))
    finally:
        _put_stream_event(events, stop_event, (name, "eof", b""))


def _run_bounded_utf8(
    bundle: VerifiedBundle,
    prepared_isolation: _PreparedIsolation,
    arguments: Tuple[str, ...],
    *,
    timeout_seconds: int,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    cancel_event: Optional[threading.Event],
) -> str:
    """출력을 파일에 남기지 않고 고정 상한 내 UTF-8 텍스트만 반환한다."""

    if not 1 <= timeout_seconds <= 600:
        raise TSharkExecutionError("TShark 실행 제한시간이 올바르지 않습니다.")
    if not 1024 <= max_stdout_bytes <= 256 * 1024 * 1024:
        raise TSharkExecutionError("TShark 표준 출력 제한이 올바르지 않습니다.")
    if not 1024 <= max_stderr_bytes <= 8 * 1024 * 1024:
        raise TSharkExecutionError("TShark 표준 오류 제한이 올바르지 않습니다.")
    if cancel_event is not None and cancel_event.is_set():
        raise TSharkExecutionError("TShark 실행이 취소됐습니다.")

    _validate_prepared_isolation(prepared_isolation)
    revalidate_bundle_snapshot(bundle)
    deadline = time.monotonic() + timeout_seconds
    try:
        process = subprocess.Popen(
            list(arguments),
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=prepared_isolation.environment,
            cwd=str(bundle.root),
            close_fds=True,
        )
    except OSError:
        raise TSharkExecutionError("TShark 실행을 시작할 수 없습니다.") from None
    if process.stdout is None or process.stderr is None:
        _stop_probe(process)
        raise TSharkExecutionError("TShark 출력 파이프를 만들 수 없습니다.")

    events = queue.Queue(maxsize=32)
    stop_event = threading.Event()
    threads = (
        threading.Thread(
            target=_pump_stream,
            args=("stdout", process.stdout, events, stop_event),
            daemon=True,
        ),
        threading.Thread(
            target=_pump_stream,
            args=("stderr", process.stderr, events, stop_event),
            daemon=True,
        ),
    )
    for reader in threads:
        reader.start()

    stdout_chunks = []
    stdout_size = 0
    stderr_size = 0
    eof = set()
    failed_reader = False
    return_code = None
    try:
        while len(eof) < 2:
            if cancel_event is not None and cancel_event.is_set():
                raise TSharkExecutionError("TShark 실행이 취소됐습니다.")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TSharkExecutionError("TShark 실행 제한시간을 초과했습니다.")
            try:
                name, event_type, chunk = events.get(timeout=min(0.1, remaining))
            except queue.Empty:
                continue
            if event_type == "eof":
                eof.add(name)
                continue
            if event_type == "error":
                failed_reader = True
                continue
            if name == "stdout":
                stdout_size += len(chunk)
                if stdout_size > max_stdout_bytes:
                    raise TSharkExecutionError("TShark 표준 출력이 안전 제한을 초과했습니다.")
                stdout_chunks.append(chunk)
            else:
                stderr_size += len(chunk)
                if stderr_size > max_stderr_bytes:
                    raise TSharkExecutionError("TShark 표준 오류가 안전 제한을 초과했습니다.")
        if failed_reader:
            raise TSharkExecutionError("TShark 출력을 안전하게 읽을 수 없습니다.")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TSharkExecutionError("TShark 실행 제한시간을 초과했습니다.")
        return_code = process.wait(timeout=remaining)
    except subprocess.TimeoutExpired:
        _stop_probe(process)
        raise TSharkExecutionError("TShark 실행 제한시간을 초과했습니다.") from None
    except TSharkExecutionError:
        _stop_probe(process)
        raise
    except (OSError, subprocess.SubprocessError):
        _stop_probe(process)
        raise TSharkExecutionError("TShark 실행을 완료할 수 없습니다.") from None
    finally:
        stop_event.set()
        try:
            process.stdout.close()
        except (OSError, ValueError):
            pass
        try:
            process.stderr.close()
        except (OSError, ValueError):
            pass
        for reader in threads:
            reader.join(timeout=1)

    if return_code != 0:
        raise TSharkExecutionError("TShark가 프로토콜 메타데이터 추출에 실패했습니다.")
    revalidate_bundle_snapshot(bundle)
    _validate_post_execution_isolation(prepared_isolation)
    try:
        text = b"".join(stdout_chunks).decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise TSharkExecutionError("TShark 출력이 올바른 UTF-8이 아닙니다.") from None
    if "\x00" in text:
        raise TSharkExecutionError("TShark 출력에 허용되지 않은 NUL 문자가 있습니다.")
    return text


def _same_capture(first: CaptureInfo, second: CaptureInfo) -> bool:
    return (
        first.path == second.path
        and first.capture_format == second.capture_format
        and first.size_bytes == second.size_bytes
        and first.sha256 == second.sha256
    )


def run_field_catalog(
    vendor_root: Path,
    isolation_root: Path,
    *,
    timeout_seconds: int = 60,
    cancel_event: Optional[threading.Event] = None,
) -> FieldCatalogRun:
    """승인 번들의 필드 등록 정보를 외부 저장 없이 검사한다."""

    initial_bundle = verify_bundle(vendor_root)
    prepared = _prepare_isolated_environment(isolation_root)
    bundle = verify_bundle(vendor_root)
    if bundle != initial_bundle:
        raise TSharkExecutionError("TShark 번들이 필드 검사 전에 변경됐습니다.")
    arguments = tuple(build_field_catalog_argv(bundle))
    text = _run_bounded_utf8(
        bundle,
        prepared,
        arguments,
        timeout_seconds=timeout_seconds,
        max_stdout_bytes=64 * 1024 * 1024,
        max_stderr_bytes=1024 * 1024,
        cancel_event=cancel_event,
    )
    catalog = parse_field_catalog(text.splitlines(keepends=True))
    return FieldCatalogRun(bundle.version, bundle.manifest_sha256, catalog)


def run_protocol_inventory(
    vendor_root: Path,
    capture_path: Path,
    isolation_parent: Path,
    profile_path: Path,
    *,
    expected_frames: Optional[int],
    timeout_seconds: int = 180,
    cancel_event: Optional[threading.Event] = None,
) -> ProtocolInventoryRun:
    """식별자 없이 프로토콜 존재 프레임 수만 집계한다."""

    if not isolation_parent.is_dir():
        raise TSharkExecutionError("분석 작업공간이 준비되지 않았습니다.")
    initial_capture = validate_capture(capture_path, cancel_event=cancel_event)
    registry = load_field_profiles(profile_path)
    catalog_run = run_field_catalog(
        vendor_root,
        isolation_parent / "field-catalog",
        timeout_seconds=min(timeout_seconds, 60),
        cancel_event=cancel_event,
    )
    current_capture = validate_capture(capture_path, cancel_event=cancel_event)
    if not _same_capture(initial_capture, current_capture):
        raise TSharkExecutionError("캡처 파일이 필드 검사 중 변경됐습니다.")
    profile = resolve_profile(registry, catalog_run.catalog, "protocol-inventory")

    initial_bundle = verify_bundle(vendor_root)
    if (
        initial_bundle.version != catalog_run.bundle_version
        or initial_bundle.manifest_sha256 != catalog_run.manifest_sha256
    ):
        raise TSharkExecutionError("TShark 번들이 필드 검사 이후 변경됐습니다.")
    prepared = _prepare_isolated_environment(isolation_parent / "protocol-inventory")
    bundle = verify_bundle(vendor_root)
    if bundle != initial_bundle:
        raise TSharkExecutionError("TShark 번들이 인벤토리 실행 전에 변경됐습니다.")
    arguments = tuple(build_profile_argv(bundle, capture_path, profile))
    text = _run_bounded_utf8(
        bundle,
        prepared,
        arguments,
        timeout_seconds=timeout_seconds,
        max_stdout_bytes=64 * 1024 * 1024,
        max_stderr_bytes=1024 * 1024,
        cancel_event=cancel_event,
    )
    final_capture = validate_capture(capture_path, cancel_event=cancel_event)
    if not _same_capture(initial_capture, final_capture):
        raise TSharkExecutionError("캡처 파일이 프로토콜 검사 중 변경됐습니다.")
    inventory = build_protocol_inventory(
        text,
        profile,
        registry.protocol_groups,
        expected_frames=expected_frames,
    )
    return ProtocolInventoryRun(
        bundle_version=bundle.version,
        manifest_sha256=bundle.manifest_sha256,
        resolved_profile=profile,
        catalog_records=catalog_run.catalog.records_scanned,
        inventory=inventory,
    )


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
