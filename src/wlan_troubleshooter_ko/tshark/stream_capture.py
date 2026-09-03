"""TShark stdout/stderr를 제한된 메모리에서 동시에 수집한다."""

from __future__ import annotations

import threading
import time
from typing import Callable, Optional

from wlan_troubleshooter_ko.tshark.errors import TSharkExecutionError


_STREAM_CHUNK_BYTES = 64 * 1024


class _StreamCaptureState:
    """두 파이프를 파일에 남기지 않고 제한된 메모리로 수집한다."""

    def __init__(self) -> None:
        self.condition = threading.Condition()
        self.stdout = bytearray()
        self.stderr_size = 0
        self.eof = set()
        self.reader_error = False
        self.overflow: Optional[str] = None


def _pump_stream(
    name: str,
    stream,
    state: _StreamCaptureState,
    stop_event: threading.Event,
    stdout_limit: int,
    stderr_limit: int,
) -> None:
    try:
        while not stop_event.is_set():
            chunk = stream.read(_STREAM_CHUNK_BYTES)
            if not chunk:
                break
            if not isinstance(chunk, bytes):
                raise ValueError("binary stream required")
            with state.condition:
                if name == "stdout":
                    if len(state.stdout) + len(chunk) > stdout_limit:
                        state.overflow = "stdout"
                        stop_event.set()
                    else:
                        state.stdout.extend(chunk)
                else:
                    if state.stderr_size + len(chunk) > stderr_limit:
                        state.overflow = "stderr"
                        stop_event.set()
                    else:
                        state.stderr_size += len(chunk)
                state.condition.notify_all()
                if state.overflow is not None:
                    break
    except (OSError, ValueError):
        with state.condition:
            state.reader_error = True
            state.condition.notify_all()
    finally:
        with state.condition:
            state.eof.add(name)
            state.condition.notify_all()


def collect_bounded_output(
    process: object,
    *,
    deadline: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    cancel_event: Optional[threading.Event],
    stop_process: Callable[[object], None],
) -> bytes:
    """두 파이프가 닫힐 때까지 읽고 stdout 원문만 반환한다."""

    stdout = process.stdout
    stderr = process.stderr
    if stdout is None or stderr is None:
        stop_process(process)
        raise TSharkExecutionError("TShark 출력 파이프를 만들 수 없습니다.")

    state = _StreamCaptureState()
    stop_event = threading.Event()
    readers = (
        threading.Thread(
            target=_pump_stream,
            args=("stdout", stdout, state, stop_event, max_stdout_bytes, max_stderr_bytes),
            daemon=True,
        ),
        threading.Thread(
            target=_pump_stream,
            args=("stderr", stderr, state, stop_event, max_stdout_bytes, max_stderr_bytes),
            daemon=True,
        ),
    )
    for reader in readers:
        reader.start()

    try:
        with state.condition:
            while len(state.eof) < 2:
                if cancel_event is not None and cancel_event.is_set():
                    raise TSharkExecutionError("TShark 실행이 취소됐습니다.")
                if state.overflow == "stdout":
                    raise TSharkExecutionError("TShark 표준 출력이 안전 제한을 초과했습니다.")
                if state.overflow == "stderr":
                    raise TSharkExecutionError("TShark 표준 오류가 안전 제한을 초과했습니다.")
                if state.reader_error:
                    raise TSharkExecutionError("TShark 출력을 안전하게 읽을 수 없습니다.")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TSharkExecutionError("TShark 실행 제한시간을 초과했습니다.")
                state.condition.wait(timeout=min(0.1, remaining))
        if state.overflow == "stdout":
            raise TSharkExecutionError("TShark 표준 출력이 안전 제한을 초과했습니다.")
        if state.overflow == "stderr":
            raise TSharkExecutionError("TShark 표준 오류가 안전 제한을 초과했습니다.")
        if state.reader_error:
            raise TSharkExecutionError("TShark 출력을 안전하게 읽을 수 없습니다.")
        return bytes(state.stdout)
    except TSharkExecutionError:
        stop_process(process)
        raise
    finally:
        stop_event.set()
        try:
            stdout.close()
        except (OSError, ValueError):
            pass
        try:
            stderr.close()
        except (OSError, ValueError):
            pass
        for reader in readers:
            reader.join(timeout=1)
