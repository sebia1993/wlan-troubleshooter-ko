"""Capture the production Tk UI while it analyzes repository-generated packets.

Documentation support only: no product runtime import or network capability is
added. The supplied vendor directory must pass the existing bundle verifier.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import time
import tkinter as tk
from pathlib import Path
from tkinter import ttk
from unittest.mock import patch

from capture_windows import block_network, capture_window, write_manifest
from generate_event_fixture import build_pcap
from generate_pcapng_statistics_fixture import build_pcapng


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vendor-root', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if os.name != 'nt':
        raise RuntimeError('Use the Windows documentation capture workflow')
    block_network()
    from wlan_troubleshooter_ko.tshark.manifest import verify_bundle
    from wlan_troubleshooter_ko.tshark.status import inspect_bundle
    from wlan_troubleshooter_ko.ui.main_window import (
        CaptureViewModel, MainWindow, _portable_status,
    )

    vendor = args.vendor_root.resolve(strict=True)
    verified = verify_bundle(vendor)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    root = tk.Tk()
    root.geometry('1280x960+10+10')
    ttk.Style(root).configure('Accent.TLabel', foreground='#146c43')
    window = MainWindow(root)
    window._vendor_root = vendor
    window._view_model = CaptureViewModel(vendor, window._profile_path)
    status = inspect_bundle(vendor)
    window._tshark_status.set(status.message)
    window._portable_status.set(_portable_status(status))
    failures = []
    deadline = time.monotonic() + 1200

    def guarded(action):
        def run():
            try:
                action()
            except Exception as exc:
                failures.append(exc)
                window._close()
        return run

    def screenshot(name, section=None):
        detail = window._detail_text.get('1.0', 'end')
        for forbidden in ('private-interface-', 'private-section-', '192.0.2.',
                          '198.51.100.', '02:00:00:', str(workspace)):
            if forbidden in detail:
                raise AssertionError('Private fixture identifiers reached the UI')
        if section:
            position = window._detail_text.search(section, '1.0', stopindex='end')
            if not position:
                raise AssertionError('Expected UI section is absent: ' + section)
            window._detail_text.yview(position)
        capture_window(root, output / name)

    def choose(path, on_done, expect_valid=True, capture_busy=False):
        # Only replace the file-picker selection; the production background
        # analysis, view model, formatter and UI update path remain unchanged.
        with patch('wlan_troubleshooter_ko.ui.main_window.filedialog.askopenfilename',
                   return_value=str(path)):
            window._choose_file()
        if capture_busy:
            screenshot('02-analyzing.png')

        def poll():
            if time.monotonic() > deadline:
                raise TimeoutError('Documentation analysis did not finish')
            if window._select_button.instate(['disabled']):
                root.after(250, guarded(poll))
                return
            model = window._view_model
            if model.state.valid != expect_valid:
                raise AssertionError('Unexpected capture validation state')
            if expect_valid and (model.analysis_result is None or
                                 model.analysis_result.inventory_state != 'completed'):
                raise AssertionError('Portable detailed analysis did not complete')
            on_done()
        root.after(250, guarded(poll))

    def finish():
        screenshot('06-rejected-input.png')
        write_manifest(output, app='WLAN Troubleshooter KO',
                       version='Phase 4K source UI',
                       method='Production Tk MainWindow; real analysis of generated local PCAP/PCAPNG; Win32 client capture')
        manifest_path = output / 'capture-manifest.json'
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        manifest['tshark_version'] = verified.version
        manifest['vendor_release'] = 'v0.13.0-alpha.1'
        manifest['fixtures'] = [
            {'generator': 'generate_event_fixture.py', 'sha256': hashlib.sha256(build_pcap()).hexdigest()},
            {'generator': 'generate_pcapng_statistics_fixture.py', 'sha256': hashlib.sha256(build_pcapng()).hexdigest()},
        ]
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        window._close()

    def statistics_done():
        screenshot('05-interface-statistics.png', '[12. PCAPNG 인터페이스 통계]')
        choose(invalid, finish, expect_valid=False)

    def events_done():
        screenshot('03-findings.png', '[4. 근거 기반 Finding]')
        screenshot('04-device-journey.png', '[8. 단말 가명별 관찰 여정]')
        choose(statistics, statistics_done)

    def start():
        screenshot('01-ready.png')
        choose(events, events_done, capture_busy=True)

    try:
        with tempfile.TemporaryDirectory(prefix='wlan-doc-fixtures-') as temporary:
            workspace = Path(temporary).resolve()
            events = workspace / 'synthetic-events.pcap'
            statistics = workspace / 'synthetic-statistics.pcapng'
            invalid = workspace / 'unsupported.txt'
            events.write_bytes(build_pcap())
            statistics.write_bytes(build_pcapng())
            invalid.write_text('This is a generated invalid input.', encoding='utf-8')
            root.after(250, guarded(start))
            root.mainloop()
    finally:
        try:
            root.destroy()
        except tk.TclError:
            pass
    if failures:
        raise failures[0]
    if len(list(output.glob('*.png'))) != 6:
        raise AssertionError('Incomplete screenshot set')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
