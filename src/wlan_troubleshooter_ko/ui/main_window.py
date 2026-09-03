"""캡처 구조와 실제 프로토콜 존재 인벤토리를 보여 주는 로컬 GUI."""

from __future__ import annotations

import threading
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Optional, Tuple

from wlan_troubleshooter_ko.analysis.models import (
    CaptureCapabilityReport,
    CaptureStructure,
)
from wlan_troubleshooter_ko.analysis.service import (
    CaptureAnalysisError,
    CaptureAnalysisResult,
    analyze_capture,
)
from wlan_troubleshooter_ko.core.capture import CaptureInfo
from wlan_troubleshooter_ko.tshark.profiles import FieldProfileError, load_field_profiles
from wlan_troubleshooter_ko.tshark.status import BundleStatus, inspect_bundle


@dataclass(frozen=True)
class CaptureViewState:
    status: str
    detail: str
    valid: bool


def _compact(items: Tuple[str, ...], limit: int = 5) -> str:
    if not items:
        return "없음"
    visible = list(items[:limit])
    if len(items) > limit:
        visible.append("외 {0}개".format(len(items) - limit))
    return " · ".join(visible)


def _portable_status(bundle_status: BundleStatus) -> str:
    resources = Path(__file__).resolve().parents[1] / "resources"
    try:
        registry = load_field_profiles(resources / "tshark" / "field-profiles.v1.json")
        profile = registry.get_profile("protocol-inventory")
    except FieldProfileError:
        return "프로토콜 인벤토리 프로파일 오류 · 배포본을 다시 받아야 합니다."
    base = "필드 프로파일 {0} · 승인 필드 {1}개 · 프로토콜 그룹 {2}개".format(
        registry.profile_version,
        len(profile.fields),
        len(registry.protocol_groups),
    )
    if bundle_status.code == "integrity_verified":
        return base + " · 내장 TShark 무결성 확인됨 · 실제 인벤토리 사용 가능"
    return base + " · 소스 실행 모드 · Portable 배포본에서는 내장 TShark가 사용됩니다."


def _format_preflight(
    capture_format: str,
    size_bytes: int,
    sha256_prefix: str,
    structure: CaptureStructure,
    report: CaptureCapabilityReport,
) -> str:
    return (
        "선택 파일: 파일명 비공개 · 형식: {format_name} · 크기: {size:,}바이트 · "
        "SHA-256: {digest}…\n"
        "캡처 유형 추정: {kind}\n"
        "설명: {summary}\n"
        "구조 점검: 인터페이스 {interfaces}개 · 패킷 레코드 {packets:,}개 · "
        "잘린 패킷 {truncated:,}개 · 전체 점검 {complete}\n"
        "형식상 확인 가능: {available}\n"
        "현재 확인 불가: {unavailable}\n"
        "사전 점검 주의: {cautions}"
    ).format(
        format_name=capture_format.upper(),
        size=size_bytes,
        digest=sha256_prefix,
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


def format_preflight_detail(
    capture: CaptureInfo,
    structure: CaptureStructure,
    report: CaptureCapabilityReport,
) -> str:
    """기존 호출자와 테스트를 위한 사전 점검 문장 호환 함수."""

    return _format_preflight(
        capture.capture_format,
        capture.size_bytes,
        capture.sha256[:12],
        structure,
        report,
    )


def _format_observations(result: CaptureAnalysisResult) -> str:
    run = result.protocol_inventory
    if run is None:
        return ""
    inventory = run.inventory
    observed = []
    for item in inventory.observations:
        observed.append(
            "- {label}: {count:,}프레임 · 처음 #{first:,} · 마지막 #{last:,}".format(
                label=item.label_ko,
                count=item.frame_count,
                first=item.first_frame,
                last=item.last_frame,
            )
        )
    if not observed:
        observed.append("- 승인된 프로토콜 그룹이 관찰되지 않았습니다.")
    expected = "알 수 없음" if inventory.expected_frames is None else "{0:,}".format(inventory.expected_frames)
    return (
        "\n\n프로토콜 존재 인벤토리: {state}\n"
        "TShark {version} · 관찰 프레임 {frames:,}개 / 사전 점검 {expected}개 · "
        "잘린 프레임 {truncated:,}개\n"
        "관찰됨:\n{observed}\n"
        "관찰되지 않음: {not_observed}\n"
        "인벤토리 주의: {cautions}\n"
        "중요: 프로토콜이 보였다는 사실은 성공을 뜻하지 않고, 보이지 않았다는 사실도 장애 증거가 아닙니다."
    ).format(
        state="전체" if inventory.complete else "일부 또는 판단 불가",
        version=run.bundle_version,
        frames=inventory.frames_observed,
        expected=expected,
        truncated=inventory.truncated_frames,
        observed="\n".join(observed),
        not_observed=_compact(inventory.not_observed_labels, limit=8),
        cautions=_compact(inventory.cautions, limit=6),
    )


def format_analysis_detail(result: CaptureAnalysisResult) -> str:
    detail = _format_preflight(
        result.capture_format,
        result.size_bytes,
        result.sha256_prefix,
        result.structure,
        result.capabilities,
    )
    if result.inventory_state == "completed":
        return detail + _format_observations(result)
    return (
        detail
        + "\n\n프로토콜 존재 인벤토리: "
        + ("실행 안 함" if result.inventory_state == "unavailable" else "실패")
        + "\n"
        + result.inventory_message
        + "\n사전 점검 결과는 유지되지만 실제 프로토콜 존재 여부는 확정하지 않습니다."
    )


class CaptureViewModel:
    """Tk 루트 없이 테스트 가능한 전체 캡처 분석 상태 모델."""

    def __init__(
        self,
        vendor_root: Optional[Path] = None,
        profile_path: Optional[Path] = None,
    ) -> None:
        package_root = Path(__file__).resolve().parents[1]
        self.vendor_root = (
            Path(__file__).resolve().parents[3] / "vendor" / "wireshark"
            if vendor_root is None
            else vendor_root
        )
        self.profile_path = (
            package_root / "resources" / "tshark" / "field-profiles.v1.json"
            if profile_path is None
            else profile_path
        )
        self.state = CaptureViewState(
            status="파일을 선택해 주세요.",
            detail="PCAP 또는 PCAPNG 파일을 외부 전송 없이 로컬에서만 분석합니다.",
            valid=False,
        )
        self.capture: Optional[CaptureInfo] = None
        self.structure: Optional[CaptureStructure] = None
        self.capabilities: Optional[CaptureCapabilityReport] = None
        self.analysis_result: Optional[CaptureAnalysisResult] = None

    def select_capture(
        self,
        path: str,
        cancel_event: Optional[threading.Event] = None,
    ) -> CaptureViewState:
        try:
            result = analyze_capture(
                path,
                self.vendor_root,
                self.profile_path,
                cancel_event=cancel_event,
            )
        except CaptureAnalysisError as exc:
            self.capture = None
            self.structure = None
            self.capabilities = None
            self.analysis_result = None
            self.state = CaptureViewState("파일을 사용할 수 없습니다.", str(exc), False)
            return self.state
        except Exception:
            self.capture = None
            self.structure = None
            self.capabilities = None
            self.analysis_result = None
            self.state = CaptureViewState(
                "파일을 사용할 수 없습니다.",
                "파일을 안전하게 분석하지 못했습니다.",
                False,
            )
            return self.state

        self.capture = None
        self.structure = result.structure
        self.capabilities = result.capabilities
        self.analysis_result = result
        if result.inventory_state == "completed":
            status = "캡처 구조와 프로토콜 존재 인벤토리를 완료했습니다."
        elif result.inventory_state == "failed":
            status = "캡처 사전 점검은 완료했지만 프로토콜 인벤토리에 실패했습니다."
        else:
            status = "캡처 사전 점검을 완료했습니다."
        self.state = CaptureViewState(
            status=status,
            detail=format_analysis_detail(result),
            valid=True,
        )
        return self.state


class MainWindow:
    def __init__(self, root: tk.Tk) -> None:
        self._root = root
        self._vendor_root = Path(__file__).resolve().parents[3] / "vendor" / "wireshark"
        self._profile_path = (
            Path(__file__).resolve().parents[1]
            / "resources"
            / "tshark"
            / "field-profiles.v1.json"
        )
        self._view_model = CaptureViewModel(self._vendor_root, self._profile_path)
        self._status = tk.StringVar(value=self._view_model.state.status)
        bundle_status = inspect_bundle(self._vendor_root)
        self._tshark_status = tk.StringVar(value=bundle_status.message)
        self._portable_status = tk.StringVar(value=_portable_status(bundle_status))
        self._selection_generation = 0
        self._validation_cancel = threading.Event()
        self._closed = False
        self._root.protocol("WM_DELETE_WINDOW", self._close)
        self._build()

    def _build(self) -> None:
        self._root.title("WLAN 장애 분석기 KO")
        self._root.minsize(860, 680)

        frame = ttk.Frame(self._root, padding=24)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="완전 오프라인", style="Accent.TLabel").pack(anchor="w")
        ttk.Label(
            frame,
            text="무선 네트워크 패킷 분석",
            font=("TkDefaultFont", 18, "bold"),
        ).pack(anchor="w", pady=(12, 4))
        ttk.Label(
            frame,
            text="캡처 구조 점검 + 내장 TShark 프로토콜 존재 인벤토리",
        ).pack(anchor="w")

        ttk.Separator(frame).pack(fill="x", pady=16)
        controls = ttk.Frame(frame)
        controls.pack(fill="x")
        self._select_button = ttk.Button(
            controls,
            text="PCAP 또는 PCAPNG 파일 선택",
            command=self._choose_file,
        )
        self._select_button.pack(side="left")
        self._cancel_button = ttk.Button(
            controls,
            text="분석 취소",
            command=self._cancel_analysis,
            state="disabled",
        )
        self._cancel_button.pack(side="left", padx=(8, 0))
        self._progress = ttk.Progressbar(controls, mode="indeterminate", length=180)
        self._progress.pack(side="right")

        ttk.Label(
            frame,
            textvariable=self._status,
            font=("TkDefaultFont", 12, "bold"),
        ).pack(anchor="w", pady=(16, 6))

        result_frame = ttk.Frame(frame)
        result_frame.pack(fill="both", expand=True)
        self._detail_text = tk.Text(
            result_frame,
            wrap="word",
            height=22,
            padx=12,
            pady=10,
            state="disabled",
        )
        result_scroll = ttk.Scrollbar(
            result_frame,
            orient="vertical",
            command=self._detail_text.yview,
        )
        self._detail_text.configure(yscrollcommand=result_scroll.set)
        self._detail_text.pack(side="left", fill="both", expand=True)
        result_scroll.pack(side="right", fill="y")
        self._set_detail(self._view_model.state.detail)

        ttk.Separator(frame).pack(fill="x", pady=16)
        ttk.Label(
            frame,
            text="AI·외부 API·실시간 캡처·장비 접속을 사용하지 않습니다.",
        ).pack(anchor="w")
        ttk.Label(frame, textvariable=self._tshark_status).pack(anchor="w", pady=(5, 0))
        ttk.Label(
            frame,
            textvariable=self._portable_status,
            wraplength=800,
        ).pack(anchor="w", pady=(3, 0))
        ttk.Label(
            frame,
            text="현재 버전은 프로토콜 존재 여부만 보여 주며 장애 원인 판정은 아직 지원하지 않습니다.",
            wraplength=800,
        ).pack(anchor="w", pady=(3, 0))
        ttk.Button(frame, text="종료", command=self._close).pack(anchor="e", pady=(12, 0))

    def _set_detail(self, value: str) -> None:
        self._detail_text.configure(state="normal")
        self._detail_text.delete("1.0", "end")
        self._detail_text.insert("1.0", value)
        self._detail_text.configure(state="disabled")
        self._detail_text.yview_moveto(0.0)

    def _set_busy(self, busy: bool) -> None:
        self._select_button.configure(state="disabled" if busy else "normal")
        self._cancel_button.configure(state="normal" if busy else "disabled")
        if busy:
            self._progress.start(12)
        else:
            self._progress.stop()

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
        self._status.set("캡처 구조와 프로토콜 존재 여부를 분석하고 있습니다.")
        self._set_detail(
            "파일명과 패킷 원문은 화면과 로그에 표시하지 않습니다. "
            "큰 캡처는 시간이 걸릴 수 있으며 언제든 분석 취소를 누를 수 있습니다."
        )
        self._set_busy(True)

        def analyze_in_background() -> None:
            worker_view_model = CaptureViewModel(self._vendor_root, self._profile_path)
            state = worker_view_model.select_capture(selected, cancel_event=cancel_event)

            def apply_result() -> None:
                if generation != self._selection_generation or self._closed:
                    return
                self._view_model = worker_view_model
                self._status.set(state.status)
                self._set_detail(state.detail)
                self._set_busy(False)

            if generation != self._selection_generation or self._closed:
                return
            try:
                self._root.after(0, apply_result)
            except (RuntimeError, tk.TclError):
                return

        threading.Thread(target=analyze_in_background, daemon=True).start()

    def _cancel_analysis(self) -> None:
        self._validation_cancel.set()
        self._status.set("분석 취소를 요청했습니다.")
        self._cancel_button.configure(state="disabled")

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
