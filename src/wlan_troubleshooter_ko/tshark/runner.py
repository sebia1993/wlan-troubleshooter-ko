"""격리된 Portable TShark의 승인된 저장 캡처 실행 경계."""

from __future__ import annotations

import os
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Optional, Tuple

from wlan_troubleshooter_ko.tshark.errors import TSharkExecutionError
from wlan_troubleshooter_ko.tshark.isolation import (
    _prepare_isolated_environment,
    _stat_is_link_or_reparse,
    _validate_post_execution_isolation,
    _validate_prepared_isolation,
    build_isolated_environment,
)
from wlan_troubleshooter_ko.tshark.manifest import (
    revalidate_bundle_snapshot,
    verify_bundle,
)
from wlan_troubleshooter_ko.tshark.policy import (
    build_analysis_argv,
    build_field_catalog_argv,
    build_profile_argv,
)
from wlan_troubleshooter_ko.tshark.profiles import ResolvedProfile
from wlan_troubleshooter_ko.tshark.stream_capture import collect_bounded_output


_DEFAULT_STDOUT_LIMIT = 64 * 1024 * 1024
_DEFAULT_STDERR_LIMIT = 1024 * 1024
_CREATE_NO_WINDOW = 0x08000000


@dataclass(frozen=True)
class PreparedTSharkInvocation:
    """실행되지 않은 승인 argv와 격리 환경."""

    arguments: Tuple[str, ...]
    environment: Mapping[str, str]


def prepare_fields_invocation(
    vendor_root: Path,
    capture_path: Path,
    isolation_root: Path,
    display_filter_name: str = "capture-overview",
    fields: Iterable[str] = ("frame.number", "frame.time_epoch", "frame.protocols"),
) -> PreparedTSharkInvocation:
    """승인 호출을 검증해 반환하되 자식 프로세스는 시작하지 않는다."""

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


def _decode_output(value: bytes) -> str:
    try:
        text = value.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise TSharkExecutionError("TShark 출력이 올바른 UTF-8이 아닙니다.") from None
    if any(ord(character) == 0 for character in text):
        raise TSharkExecutionError("TShark 출력에 허용되지 않은 NUL 문자가 있습니다.")
    return text


def probe_bundle_runtime(
    vendor_root: Path,
    isolation_root: Path,
    timeout_seconds: int = 10,
    cancel_event: Optional[threading.Event] = None,
    *,
    _mode: str = "version",
    _capture_path: Optional[Path] = None,
    _profile: Optional[ResolvedProfile] = None,
    _max_stdout_bytes: int = _DEFAULT_STDOUT_LIMIT,
    _max_stderr_bytes: int = _DEFAULT_STDERR_LIMIT,
) -> str:
    """모든 승인 TShark 프로세스 생성을 한 감사 경계에서 수행한다.

    공개 기본 동작은 캡처를 열지 않는 고정 ``-n -v`` 준비 확인이다.
    밑줄 매개변수는 같은 모듈의 필드 카탈로그와 인벤토리 함수만 사용한다.
    """

    maximum_timeout = 60 if _mode == "version" else 600
    if timeout_seconds <= 0 or timeout_seconds > maximum_timeout:
        raise TSharkExecutionError("허용되지 않은 TShark 실행 제한시간입니다.")
    if not 1024 <= _max_stdout_bytes <= 256 * 1024 * 1024:
        raise TSharkExecutionError("TShark 표준 출력 제한이 올바르지 않습니다.")
    if not 1024 <= _max_stderr_bytes <= 8 * 1024 * 1024:
        raise TSharkExecutionError("TShark 표준 오류 제한이 올바르지 않습니다.")
    if cancel_event is not None and cancel_event.is_set():
        raise TSharkExecutionError("TShark 실행이 취소됐습니다.")

    deadline = time.monotonic() + timeout_seconds
    initial_bundle = verify_bundle(vendor_root)
    prepared = _prepare_isolated_environment(isolation_root, dict(os.environ))
    bundle = verify_bundle(vendor_root)
    if bundle != initial_bundle:
        raise TSharkExecutionError("TShark 번들이 실행 전에 변경됐습니다.")
    _validate_prepared_isolation(prepared)
    revalidate_bundle_snapshot(bundle)
    if cancel_event is not None and cancel_event.is_set():
        raise TSharkExecutionError("TShark 실행이 취소됐습니다.")
    if time.monotonic() >= deadline:
        raise TSharkExecutionError("TShark 실행 제한시간을 초과했습니다.")

    capture_output = False
    if _mode == "version":
        arguments = [str(bundle.executable), "-n", "-v"]
    elif _mode == "field-catalog":
        arguments = build_field_catalog_argv(bundle)
        capture_output = True
    elif _mode == "protocol-inventory":
        if _capture_path is None or _profile is None:
            raise TSharkExecutionError("프로토콜 인벤토리 실행 정보가 누락됐습니다.")
        arguments = build_profile_argv(bundle, _capture_path, _profile)
        capture_output = True
    else:
        raise TSharkExecutionError("승인되지 않은 TShark 실행 모드입니다.")

    creation_flags = _CREATE_NO_WINDOW if os.name == "nt" else 0
    try:
        process = subprocess.Popen(
            arguments,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture_output else subprocess.DEVNULL,
            stderr=subprocess.PIPE if capture_output else subprocess.DEVNULL,
            env=prepared.environment,
            cwd=str(bundle.root),
            close_fds=True,
            creationflags=creation_flags,
        )
    except OSError:
        raise TSharkExecutionError("TShark 실행을 시작할 수 없습니다.") from None

    if capture_output:
        output = collect_bounded_output(
            process,
            deadline=deadline,
            max_stdout_bytes=_max_stdout_bytes,
            max_stderr_bytes=_max_stderr_bytes,
            cancel_event=cancel_event,
            stop_process=_stop_probe,
        )
        while True:
            if cancel_event is not None and cancel_event.is_set():
                _stop_probe(process)
                raise TSharkExecutionError("TShark 실행이 취소됐습니다.")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _stop_probe(process)
                raise TSharkExecutionError("TShark 실행 제한시간을 초과했습니다.")
            try:
                return_code = process.wait(timeout=min(0.1, remaining))
                break
            except subprocess.TimeoutExpired:
                continue
            except (OSError, subprocess.SubprocessError):
                _stop_probe(process)
                raise TSharkExecutionError("TShark 실행을 완료할 수 없습니다.") from None
        if return_code != 0:
            raise TSharkExecutionError("TShark가 프로토콜 메타데이터 추출에 실패했습니다.")
        revalidate_bundle_snapshot(bundle)
        _validate_post_execution_isolation(prepared)
        return _decode_output(output)

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
    revalidate_bundle_snapshot(bundle)
    _validate_post_execution_isolation(prepared)
    return bundle.version
