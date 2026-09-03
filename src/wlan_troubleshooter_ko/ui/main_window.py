"""Phase 1 범위의 로컬 파일 선택 및 검증 화면."""

from __future__ import annotations

import tkinter as tk
import threading
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Optional

from wlan_troubleshooter_ko.core.capture import CaptureInfo, CaptureValidationError, validate_capture
from wlan_troubleshooter_ko.tshark.status import inspect_bundle


@dataclass(frozen=True)
class CaptureViewState:
    status: str
    detail: str
    valid: bool


class CaptureViewModel:
    """창을 만들지 않고도 테스트할 수 있는 파일 검증 상태 모델."""

    def __init__(self) -> None:
        self.state = CaptureViewState(
            status="파일을 선택해 주세요.",
            detail="PCAP 또는 PCAPNG 파일을 로컬에서만 검사합니다.",
            valid=False,
        )
        self.capture: Optional[CaptureInfo] = None

    def select_capture(
        self,
        path: str,
        cancel_event: Optional[threading.Event] = None,
    ) -> CaptureViewState:
        try:
            capture = validate_capture(path, cancel_event=cancel_event)
        except CaptureValidationError as exc:
            self.capture = None
            self.state = CaptureViewState("파일을 사용할 수 없습니다.", str(exc), False)
            return self.state
        except Exception:
            self.capture = None
            self.state = CaptureViewState(
                "파일을 사용할 수 없습니다.",
                "파일을 안전하게 확인하지 못했습니다.",
                False,
            )
            return self.state
        self.capture = capture
        self.state = CaptureViewState(
            status="로컬 캡처 파일을 확인했습니다.",
            detail=(
                "선택 파일: 파일명 비공개 · 형식: {0} · 크기: {1:,}바이트 · SHA-256: {2}…\n"
                "Phase 2 전에는 패킷 분석을 수행하지 않습니다."
            ).format(capture.capture_format.upper(), capture.size_bytes, capture.sha256[:12]),
            valid=True,
        )
        return self.state


class MainWindow:
    def __init__(self, root: tk.Tk) -> None:
        self._root = root
        self._view_model = CaptureViewModel()
        self._status = tk.StringVar(value=self._view_model.state.status)
        self._detail = tk.StringVar(value=self._view_model.state.detail)
        vendor_root = Path(__file__).resolve().parents[3] / "vendor" / "wireshark"
        self._tshark_status = tk.StringVar(value=inspect_bundle(vendor_root).message)
        self._selection_generation = 0
        self._validation_cancel = threading.Event()
        self._closed = False
        self._root.protocol("WM_DELETE_WINDOW", self._close)
        self._build()

    def _build(self) -> None:
        self._root.title("WLAN 장애 분석기 KO")
        self._root.minsize(620, 360)

        frame = ttk.Frame(self._root, padding=24)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="완전 오프라인", style="Accent.TLabel").pack(anchor="w")
        ttk.Label(frame, text="무선 네트워크 장애 분석", font=("TkDefaultFont", 18, "bold")).pack(
            anchor="w", pady=(12, 4)
        )
        ttk.Label(
            frame,
            text="초급 네트워크 엔지니어를 위한 Phase 1 안전 기반",
        ).pack(anchor="w")

        ttk.Separator(frame).pack(fill="x", pady=20)
        ttk.Button(frame, text="PCAP 또는 PCAPNG 파일 선택", command=self._choose_file).pack(
            anchor="w"
        )
        ttk.Label(frame, textvariable=self._status, font=("TkDefaultFont", 12, "bold")).pack(
            anchor="w", pady=(20, 6)
        )
        ttk.Label(frame, textvariable=self._detail, wraplength=560, justify="left").pack(anchor="w")

        ttk.Separator(frame).pack(fill="x", pady=20)
        ttk.Label(
            frame,
            text="AI·외부 API·실시간 캡처·장비 접속을 사용하지 않습니다.",
        ).pack(anchor="w")
        ttk.Label(
            frame,
            textvariable=self._tshark_status,
        ).pack(anchor="w", pady=(6, 0))
        ttk.Label(frame, text="Phase 1에서는 실제 패킷 분석을 지원하지 않습니다.").pack(
            anchor="w", pady=(3, 0)
        )
        ttk.Button(frame, text="종료", command=self._close).pack(anchor="e", pady=(18, 0))

    def _choose_file(self) -> None:
        selected = filedialog.askopenfilename(
            title="로컬 패킷 캡처 선택",
            filetypes=(("패킷 캡처", "*.pcap *.pcapng"), ("모든 파일", "*.*")),
        )
        if not selected:
            return
        self._selection_generation += 1
        generation = self._selection_generation
        self._validation_cancel.set()
        cancel_event = threading.Event()
        self._validation_cancel = cancel_event
        self._status.set("로컬 캡처 파일을 확인하고 있습니다.")
        self._detail.set("파일명은 화면과 로그에 표시하지 않습니다.")

        def validate_in_background() -> None:
            worker_view_model = CaptureViewModel()
            state = worker_view_model.select_capture(selected, cancel_event=cancel_event)

            def apply_result() -> None:
                if generation != self._selection_generation:
                    return
                self._view_model = worker_view_model
                self._status.set(state.status)
                self._detail.set(state.detail)

            if generation != self._selection_generation:
                return
            try:
                self._root.after(0, apply_result)
            except (RuntimeError, tk.TclError):
                return

        threading.Thread(target=validate_in_background, daemon=True).start()

    def _close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._selection_generation += 1
        self._validation_cancel.set()
        self._root.destroy()


def launch() -> None:
    root = tk.Tk()
    style = ttk.Style(root)
    style.configure("Accent.TLabel", foreground="#146c43")
    MainWindow(root)
    root.mainloop()
