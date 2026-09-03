"""로컬 캡처 검증과 Phase 2A 구조 사전 점검 화면."""

from __future__ import annotations

import threading
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Optional, Tuple

from wlan_troubleshooter_ko.analysis.preflight import (
    CaptureCapabilityReport,
    CaptureStructure,
    CaptureStructureError,
    classify_capture_capabilities,
    inspect_capture_structure,
)
from wlan_troubleshooter_ko.core.capture import (
    CaptureInfo,
    CaptureValidationError,
    validate_capture,
)
from wlan_troubleshooter_ko.tshark.status import inspect_bundle


@dataclass(frozen=True)
class CaptureViewState:
    status: str
    detail: str
    valid: bool


def _compact(items: Tuple[str, ...], limit: int = 3) -> str:
    if not items:
        return "없음"
    visible = list(items[:limit])
    if len(items) > limit:
        visible.append("외 {0}개".format(len(items) - limit))
    return " · ".join(visible)


def format_preflight_detail(
    capture: CaptureInfo,
    structure: CaptureStructure,
    report: CaptureCapabilityReport,
) -> str:
    """경로와 패킷 원문 없이 초급자용 사전 점검 문장을 만든다."""

    return (
        "선택 파일: 파일명 비공개 · 형식: {format_name} · 크기: {size:,}바이트 · "
        "SHA-256: {digest}…\n"
        "캡처 유형 추정: {kind}\n"
        "설명: {summary}\n"
        "구조 점검: 인터페이스 {interfaces}개 · 패킷 레코드 {packets:,}개 · "
        "잘린 패킷 {truncated:,}개 · 전체 점검 {complete}\n"
        "형식상 확인 가능: {available}\n"
        "현재 확인 불가: {unavailable}\n"
        "주의: {cautions}\n"
        "프로토콜별 장애 판정은 승인된 Portable TShark가 준비된 다음 단계에서 수행합니다."
    ).format(
        format_name=capture.capture_format.upper(),
        size=capture.size_bytes,
        digest=capture.sha256[:12],
        kind=report.capture_kind_label,
        summary=report.summary,
        interfaces=len(structure.interfaces),
        packets=structure.packets_scanned,
        truncated=structure.truncated_packets_observed,
        complete="완료" if structure.scan_complete else "일부",
        available=_compact(report.available_checks),
        unavailable=_compact(report.unavailable_checks),
        cautions=_compact(report.cautions),
    )


class CaptureViewModel:
    """창 없이 테스트 가능한 캡처 사전 점검 상태 모델."""

    def __init__(self) -> None:
        self.state = CaptureViewState(
            status="파일을 선택해 주세요.",
            detail="PCAP 또는 PCAPNG 파일을 외부 전송 없이 로컬에서만 검사합니다.",
            valid=False,
        )
        self.capture: Optional[CaptureInfo] = None
        self.structure: Optional[CaptureStructure] = None
        self.capabilities: Optional[CaptureCapabilityReport] = None

    def select_capture(
        self,
        path: str,
        cancel_event: Optional[threading.Event] = None,
    ) -> CaptureViewState:
        try:
            capture = validate_capture(path, cancel_event=cancel_event)
            if cancel_event is not None and cancel_event.is_set():
                raise CaptureValidationError("파일 확인이 취소됐습니다.")
            structure = inspect_capture_structure(
                capture,
                cancel_event=cancel_event,
            )
            capabilities = classify_capture_capabilities(structure)
        except (CaptureValidationError, CaptureStructureError) as exc:
            self.capture = None
            self.structure = None
            self.capabilities = None
            self.state = CaptureViewState(
                "파일을 사용할 수 없습니다.",
                str(exc),
                False,
            )
            return self.state
        except Exception:
            self.capture = None
            self.structure = None
            self.capabilities = None
            self.state = CaptureViewState(
                "파일을 사용할 수 없습니다.",
                "파일을 안전하게 확인하지 못했습니다.",
                False,
            )
            return self.state

        self.capture = capture
        self.structure = structure
        self.capabilities = capabilities
        self.state = CaptureViewState(
            status="캡처 사전 점검을 완료했습니다.",
            detail=format_preflight_detail(capture, structure, capabilities),
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
        self._root.minsize(760, 520)

        frame = ttk.Frame(self._root, padding=24)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="완전 오프라인", style="Accent.TLabel").pack(anchor="w")
        ttk.Label(
            frame,
            text="무선 네트워크 장애 분석",
            font=("TkDefaultFont", 18, "bold"),
        ).pack(anchor="w", pady=(12, 4))
        ttk.Label(
            frame,
            text="초급 네트워크 엔지니어를 위한 Phase 2A 캡처 사전 점검",
        ).pack(anchor="w")

        ttk.Separator(frame).pack(fill="x", pady=20)
        ttk.Button(
            frame,
            text="PCAP 또는 PCAPNG 파일 선택",
            command=self._choose_file,
        ).pack(anchor="w")
        ttk.Label(
            frame,
            textvariable=self._status,
            font=("TkDefaultFont", 12, "bold"),
        ).pack(anchor="w", pady=(20, 6))
        ttk.Label(
            frame,
            textvariable=self._detail,
            wraplength=700,
            justify="left",
        ).pack(anchor="w")

        ttk.Separator(frame).pack(fill="x", pady=20)
        ttk.Label(
            frame,
            text="AI·외부 API·실시간 캡처·장비 접속을 사용하지 않습니다.",
        ).pack(anchor="w")
        ttk.Label(frame, textvariable=self._tshark_status).pack(anchor="w", pady=(6, 0))
        ttk.Label(
            frame,
            text=(
                "현재 버전은 캡처 유형과 분석 가능 범위를 점검하며 "
                "실제 장애 판정은 아직 지원하지 않습니다."
            ),
            wraplength=700,
        ).pack(anchor="w", pady=(3, 0))
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
        self._status.set("로컬 캡처 파일의 구조를 확인하고 있습니다.")
        self._detail.set("파일명과 패킷 원문은 화면과 로그에 표시하지 않습니다.")

        def validate_in_background() -> None:
            worker_view_model = CaptureViewModel()
            state = worker_view_model.select_capture(
                selected,
                cancel_event=cancel_event,
            )

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
