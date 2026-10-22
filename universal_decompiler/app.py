"""Windows-friendly Tkinter desktop shell for Stage 1: offline binary identification."""
from __future__ import annotations

import json
from pathlib import Path
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from uuid import uuid4

from . import __version__
from .analyzer import AnalysisReport, analyze_file, report_text
from .diagnostics import GuidedTest, Trace, ScanWatchdog, exception_details
from .live_console import LiveConsole

BG = "#101b2a"
PANEL = "#17273c"
TEXT = "#e8f1fc"
MUTED = "#a8bbce"
ACCENT = "#2e81df"


class DesktopApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"Universal Decompiler | Stage 1: Binary Identification | v{__version__}")
        self.geometry("1160x785")
        self.minsize(920, 640)
        self.configure(bg=BG)
        self.trace_log = Trace()
        self.trace_log.install_exception_hooks()
        self.guide = GuidedTest(self.trace_log)
        self.selected: Path | None = None
        self.report: AnalysisReport | None = None
        self.busy = False
        self._watchdog: ScanWatchdog | None = None
        self._build_ui()
        self.after(100, self._initialize_console_height)
        self.report_callback_exception = self._unexpected_error
        self.protocol("WM_DELETE_WINDOW", self._close_app)
        self.trace_log.event("UI", "READY", view="stage1")
        self.after(1000, self._ui_heartbeat)

    def _initialize_console_height(self):
        """Show enough recent events on first launch; user can resize the sash."""
        if self.split.winfo_exists() and self.split.winfo_height() > 450:
            height = self.split.winfo_height()
            self.split.sash_place(0, 0, max(235, height - 215))

    def _close_app(self):
        self.console.close()
        if self.busy:
            # A daemon scan will be interrupted; preserve its recovery marker.
            self.trace_log.event("APP", "EXIT_WHILE_SCAN_ACTIVE")
        else:
            self.trace_log.close_session()
        self.destroy()

    def _ui_heartbeat(self):
        if self._watchdog is not None:
            self._watchdog.ui_heartbeat()
        self.after(1000, self._ui_heartbeat)

    def _finish_scan_tracking(self, correlation_id: str):
        if self._watchdog is not None:
            self._watchdog.stop()
            self._watchdog = None
        self.trace_log.finish_operation(correlation_id)

    def _build_ui(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10), padding=(12, 8))
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT,
                        rowheight=26, font=("Consolas", 10), borderwidth=0)
        style.configure("Treeview.Heading", background="#25425f", foreground=TEXT,
                        font=("Segoe UI", 10, "bold"), padding=6)
        style.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", "white")])

        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", padx=15, pady=(14, 6))
        tk.Label(header, text="UNIVERSAL DECOMPILER", font=("Segoe UI", 17, "bold"),
                 bg=BG, fg=TEXT).pack(side="left")
        tk.Label(header, text="  STAGE 1 / 5  ·  BINARY IDENTIFICATION", font=("Segoe UI", 10),
                 bg=BG, fg=MUTED).pack(side="left", padx=12)

        toolbar = ttk.Frame(self)
        toolbar.pack(fill="x", padx=15, pady=(2, 13))
        self.open_btn = ttk.Button(toolbar, text="Open File", command=self.open_file)
        self.open_btn.pack(side="left", padx=(0, 6))
        self.scan_btn = ttk.Button(toolbar, text="Scan", command=self.scan, state="disabled")
        self.scan_btn.pack(side="left", padx=6)
        self.report_btn = ttk.Button(toolbar, text="Save Report", command=self.save_report, state="disabled")
        self.report_btn.pack(side="left", padx=6)
        ttk.Button(toolbar, text="Export Diagnostics", command=self.export_diagnostics).pack(side="left", padx=6)
        ttk.Button(toolbar, text="Test This Version", command=self.test_this_version).pack(side="left", padx=6)
        ttk.Label(toolbar, text="Next: Disassembly (not implemented)", foreground=MUTED).pack(side="right")

        identity = tk.Frame(self, bg=PANEL, padx=16, pady=15)
        identity.pack(fill="x", padx=15, pady=(0, 12))
        self.file_label = tk.Label(identity, text="No file selected", font=("Segoe UI", 13, "bold"),
                                   bg=PANEL, fg=TEXT, anchor="w")
        self.file_label.pack(fill="x")
        self.details_label = tk.Label(identity, text="Open a Windows EXE, ELF, or firmware image to begin.",
                                      bg=PANEL, fg=MUTED, justify="left", anchor="w", font=("Segoe UI", 10))
        self.details_label.pack(fill="x", pady=(6, 0))

        self.split = tk.PanedWindow(self, orient="vertical", bg="#38516b", sashwidth=7,
                                    sashrelief="flat", borderwidth=0)
        self.split.pack(fill="both", expand=True, padx=15, pady=(0, 10))
        workspace = ttk.Frame(self.split)
        self.split.add(workspace, minsize=235, stretch="always")
        workspace.columnconfigure(0, weight=3)
        workspace.columnconfigure(1, weight=2)
        workspace.rowconfigure(0, weight=3)
        workspace.rowconfigure(1, weight=2)

        left = tk.Frame(workspace, bg=PANEL, padx=10, pady=9)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8), pady=(0, 8))
        tk.Label(left, text="DETECTED STRUCTURE MAP", font=("Segoe UI", 11, "bold"),
                 bg=PANEL, fg=TEXT).pack(anchor="w", pady=(0, 8))
        self.tree = ttk.Treeview(left, columns=("offset", "size", "label"), show="headings")
        for name, title, width in [("offset", "Offset", 135), ("size", "Size", 110), ("label", "Component / Candidate", 350)]:
            self.tree.heading(name, text=title)
            self.tree.column(name, width=width, anchor="w", stretch=(name == "label"))
        self.tree.pack(fill="both", expand=True)

        right = tk.Frame(workspace, bg=PANEL, padx=10, pady=9)
        right.grid(row=0, column=1, sticky="nsew", pady=(0, 8))
        tk.Label(right, text="BINARY ANALYSIS REPORT", font=("Segoe UI", 11, "bold"),
                 bg=PANEL, fg=TEXT).pack(anchor="w", pady=(0, 8))
        self.info = tk.Text(right, bg=PANEL, fg=TEXT, insertbackground=TEXT, font=("Consolas", 10),
                            relief="flat", wrap="word", state="disabled")
        self.info.pack(fill="both", expand=True)

        bottom = tk.Frame(workspace, bg=PANEL, padx=10, pady=9)
        bottom.grid(row=1, column=0, columnspan=2, sticky="nsew")
        tk.Label(bottom, text="HEX + ASCII PREVIEW (FIRST 256 BYTES)", font=("Segoe UI", 11, "bold"),
                 bg=PANEL, fg=TEXT).pack(anchor="w", pady=(0, 8))
        self.hex_box = tk.Text(bottom, bg=PANEL, fg="#a9ceff", font=("Consolas", 10),
                               relief="flat", wrap="none", state="disabled")
        self.hex_box.pack(fill="both", expand=True)

        self.console = LiveConsole(self.split, self.trace_log)
        self.split.add(self.console, minsize=115, stretch="always")

        self.status = tk.StringVar(value="Ready  ·  No binary loaded  ·  All analysis is read-only and local")
        tk.Label(self, textvariable=self.status, bg="#0a1523", fg=MUTED,
                 anchor="w", padx=14, pady=9, font=("Segoe UI", 9)).pack(fill="x")

    @staticmethod
    def _replace_text(widget: tk.Text, value: str):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    def open_file(self):
        correlation = str(uuid4())
        self.trace_log.event("USER_ACTION", "OPEN_FILE", correlation_id=correlation)
        path = filedialog.askopenfilename(title="Choose a binary or firmware image",
            filetypes=[("Executables and firmware", "*.exe *.dll *.sys *.elf *.bin *.img *.fw"), ("All files", "*.*")])
        if not path:
            self.trace_log.event("OPERATION_RESULT", "FILE_PICK_CANCELLED", correlation_id=correlation)
            return
        self.selected = Path(path)
        self.report = None
        self.file_label.configure(text=self.selected.name)
        self.details_label.configure(text="File selected. Click Scan to inspect headers, architecture and signatures.")
        self.scan_btn.configure(state="normal")
        self.report_btn.configure(state="disabled")
        self.tree.delete(*self.tree.get_children())
        self._replace_text(self.info, "")
        self._replace_text(self.hex_box, "")
        self.status.set("File selected  ·  Scan pending")
        self.trace_log.event("OPERATION_RESULT", "FILE_SELECTED", correlation_id=correlation,
                             filename=self.selected.name)

    def scan(self):
        if self.busy or self.selected is None:
            return
        correlation = str(uuid4())
        path = self.selected
        self.trace_log.event("USER_ACTION", "SCAN", correlation_id=correlation, filename=path.name)
        self.trace_log.event("OPERATION_START", "ANALYZE", correlation_id=correlation)
        self.trace_log.save_operation_state(correlation, "SCAN", "starting")
        self._watchdog = ScanWatchdog(self.trace_log, correlation)
        self._watchdog.start()
        self.busy = True
        self.scan_btn.configure(state="disabled")
        self.open_btn.configure(state="disabled")
        self.report_btn.configure(state="disabled")
        self.status.set("Scanning read-only  ·  Calculating SHA-256 and inspecting signatures...")
        t0 = time.monotonic()

        watchdog = self._watchdog
        last_marker = [0.0, ""]

        def progress(phase: str):
            if watchdog:
                watchdog.progress(phase)
            # Retain phase breadcrumbs without writing a file for every hash chunk.
            now = time.monotonic()
            if phase != last_marker[1] or now - last_marker[0] >= 10:
                self.trace_log.save_operation_state(correlation, "SCAN", phase)
                self.trace_log.event("STATE_TRANSITION", "SCAN_PROGRESS",
                                     correlation_id=correlation, phase=phase)
                last_marker[:] = [now, phase]

        def worker():
            try:
                result = analyze_file(path, progress=progress)
            except Exception as exc:
                event_id = self.trace_log.event("ERROR", "SCAN_FAILED", correlation_id=correlation,
                                                **exception_details(exc))
                self.after(0, lambda e=type(exc).__name__, eid=event_id: self._scan_failed(e, correlation, eid))
                return
            elapsed = round((time.monotonic() - t0) * 1000)
            self.trace_log.event("OPERATION_RESULT", "ANALYZE_SUCCEEDED", correlation_id=correlation,
                                 durationMs=elapsed, format=result.file_format,
                                 architecture=result.architecture, sections=len(result.segments),
                                 sha256=result.sha256_hex)
            self.after(0, lambda: self._scan_done(result, elapsed, correlation))

        threading.Thread(target=worker, daemon=True).start()

    def _scan_failed(self, error: str, correlation_id: str, event_id: str):
        self._finish_scan_tracking(correlation_id)
        self.busy = False
        self.scan_btn.configure(state="normal")
        self.open_btn.configure(state="normal")
        self.status.set("Scan failed  ·  Export Diagnostics for investigation")
        messagebox.showerror("Scan failed", f"The file could not be analyzed ({error}).\nDiagnostic event ID: {event_id}")

    def _scan_done(self, report: AnalysisReport, elapsed: int, correlation_id: str):
        self.busy = False
        self.report = report
        self.scan_btn.configure(state="normal")
        self.open_btn.configure(state="normal")
        self.report_btn.configure(state="normal")
        self.details_label.configure(text=f"{report.size_bytes:,} bytes  ·  {report.file_format}  ·  {report.architecture}")
        info_lines = [
            f"Format: {report.file_format}", f"Architecture: {report.architecture}",
            f"Endianness: {report.endian}", f"Confidence: {report.confidence}",
            f"Entry point: {report.entry_point}", f"SHA-256: {report.sha256_hex}",
            "", "Warnings:",
        ] + ([f"• {w}" for w in report.warnings] or ["None"])
        self._replace_text(self.info, "\n".join(info_lines))
        self._replace_text(self.hex_box, report.hex_preview)
        self.tree.delete(*self.tree.get_children())
        for segment in report.segments:
            self.tree.insert("", "end", values=(segment.offset_hex,
                             "Unknown" if segment.size is None else f"{segment.size:,}", segment.label))
        self.status.set(f"Scan complete ({elapsed} ms)  ·  {len(report.segments)} sections/signatures  ·  Read-only")
        self.guide.observe("T1-PE-SCAN", report.file_format.startswith("Windows Portable Executable")
                           and not report.architecture.startswith("Unknown") and bool(report.sha256_hex),
                           f"PE detected; architecture={report.architecture}; SHA-256 present")
        self._finish_scan_tracking(correlation_id)

    def save_report(self):
        if self.report is None:
            return
        correlation = str(uuid4())
        self.trace_log.event("USER_ACTION", "SAVE_REPORT", correlation_id=correlation)
        selected = filedialog.asksaveasfilename(title="Save analysis report", defaultextension=".txt",
                            initialfile=self.report.filename + ".analysis.txt", filetypes=[("Text report", "*.txt")])
        if not selected:
            self.trace_log.event("OPERATION_RESULT", "SAVE_CANCELLED", correlation_id=correlation)
            return
        output = Path(selected)
        try:
            content = report_text(self.report)
            output.write_text(content, encoding="utf-8")
            valid = output.stat().st_size > 0 and self.report.sha256_hex in output.read_text(encoding="utf-8")
            if not valid:
                raise IOError("Report output failed validation")
            self.trace_log.event("OPERATION_RESULT", "SAVE_SUCCEEDED", correlation_id=correlation,
                                 bytes=output.stat().st_size, validated=True)
            self.guide.observe("T2-SAVE-REPORT", True, "Saved nonempty TXT report containing scanned file SHA-256")
            self.status.set("Report saved and validated  ·  Original binary unchanged")
        except (OSError, UnicodeError) as exc:
            self.trace_log.event("ERROR", "SAVE_FAILED", correlation_id=correlation,
                                 **exception_details(exc))
            messagebox.showerror("Save failed", f"Could not save report ({type(exc).__name__}).")

    def export_diagnostics(self):
        correlation = str(uuid4())
        self.trace_log.event("USER_ACTION", "EXPORT_DIAGNOSTICS", correlation_id=correlation)
        output_name = filedialog.asksaveasfilename(title="Export diagnostic ZIP", defaultextension=".zip",
                              initialfile="universal-decompiler-diagnostics.zip", filetypes=[("ZIP archive", "*.zip")])
        if not output_name:
            self.trace_log.event("OPERATION_RESULT", "EXPORT_CANCELLED", correlation_id=correlation)
            return
        try:
            self.trace_log.event("OPERATION_START", "EXPORT_DIAGNOSTICS", correlation_id=correlation)
            output = Path(output_name)
            count = self.trace_log.export_zip(output, self.guide)
            if count <= 0:
                raise IOError("Empty diagnostic archive")
            self.trace_log.event("OPERATION_RESULT", "EXPORT_DIAGNOSTICS_SUCCEEDED",
                                 correlation_id=correlation, bytes=count)
            self.status.set(f"Diagnostics exported ({count:,} bytes)")
        except (OSError, ValueError) as exc:
            self.trace_log.event("ERROR", "EXPORT_FAILED", correlation_id=correlation,
                                 **exception_details(exc))
            messagebox.showerror("Export failed", f"Could not export diagnostics ({type(exc).__name__}).")

    def test_this_version(self):
        self.trace_log.event("USER_ACTION", "TEST_THIS_VERSION")
        if self.guide.state["status"] != "IN_PROGRESS":
            self.guide.begin()
        window = tk.Toplevel(self)
        window.title("Test This Version — Stage 1")
        window.configure(bg=BG)
        window.geometry("575x335")
        window.transient(self)
        window.grab_set()
        tk.Label(window, text=f"Guided Test — v{__version__}", bg=BG, fg=TEXT,
                 font=("Segoe UI", 16, "bold")).pack(anchor="w", padx=22, pady=(18, 10))
        body = tk.Label(window, text="", bg=BG, fg=TEXT, font=("Segoe UI", 11),
                        wraplength=530, justify="left", anchor="nw")
        body.pack(fill="both", expand=True, padx=22)

        def refresh():
            step = self.guide.current_step()
            if step is None:
                body.configure(text="Guided test PASS. Both actions were automatically verified.\n\nExport Diagnostics to preserve your test results.")
            else:
                body.configure(text=f"STEP {self.guide.state['nextStep'] + 1} OF 2: {step['title']}\n\n"
                          f"WHAT TO DO\n{step['instruction']}\n\nEXPECTED RESULT\n{step['expected']}\n\n"
                          "Close this window while testing, then reopen it to check your progress. The session persists across restarts.")

        def mark_problem():
            if self.guide.current_step() is None:
                return
            note = simpledialog.askstring("Expected Behavior Failed", "What did you do, and what happened?", parent=window)
            if note is None:
                return
            self.guide.fail(note)
            body.configure(text="Test marked FAILED. Please export diagnostics and send them with your description.")

        buttons = ttk.Frame(window)
        buttons.pack(padx=20, pady=16, fill="x")
        ttk.Button(buttons, text="Refresh Progress", command=refresh).pack(side="left", padx=4)
        ttk.Button(buttons, text="Expected Behavior Failed", command=mark_problem).pack(side="left", padx=4)
        ttk.Button(buttons, text="Close", command=window.destroy).pack(side="right", padx=4)
        refresh()

    def _unexpected_error(self, error_type, value, traceback_obj):
        event_id = self.trace_log.event("ERROR", "UNHANDLED_UI_EXCEPTION",
                                        **exception_details(value, traceback_obj))
        messagebox.showerror("Unexpected error",
                             f"An unexpected error occurred. Export diagnostics.\nDiagnostic event ID: {event_id}")


def main():
    DesktopApp().mainloop()


if __name__ == "__main__":
    main()
