"""Live, read-only, thread-safe presentation of persisted diagnostics.

The UI never reads raw analyzed binaries and never runs external commands. The
same event contract accepts Windows-tool and Linux/WSL-tool output in later stages.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime
import queue
import tkinter as tk
from tkinter import ttk

from .diagnostics import Trace


SOURCE_OPTIONS = ("All", "Application", "Windows", "Linux / WSL")
SOURCE_FILTER = {
    "All": None,
    "Application": "APP",
    "Windows": "WINDOWS",
    "Linux / WSL": "LINUX_WSL",
}
LEVEL_COLORS = {"ERROR": "#ff8181", "CRASH": "#ff8181", "WATCHDOG": "#ffcc66",
                "RECOVERY": "#ffcc66", "TOOL_STDERR": "#ffcc66",
                "OPERATION_RESULT": "#8ce6b3", "TOOL_STDOUT": "#a8ceff"}


def console_source(event: dict) -> str:
    source = event.get("details", {}).get("source", "APP")
    return source if source in ("APP", "WINDOWS", "LINUX_WSL") else "APP"


def console_format(event: dict) -> str:
    """Never include arbitrary input-file content in the console by default."""
    stamp = event.get("timestampUtc", "")
    try:
        stamp = datetime.fromisoformat(stamp).astimezone().strftime("%H:%M:%S")
    except (ValueError, TypeError):
        stamp = "--:--:--"
    category = str(event.get("category", "EVENT"))
    action = str(event.get("action", "UNKNOWN"))
    details = event.get("details") or {}
    visible_keys = ("phase", "format", "architecture", "durationMs", "sections", "errorType",
                    "secondsWithoutProgress", "secondsWithoutUIHeartbeat", "exitCode",
                    "stream", "text", "reason", "bytes", "lineTruncated")
    display = ", ".join(f"{key}={str(details[key])[:220]}" for key in visible_keys if key in details)
    source = console_source(event).replace("LINUX_WSL", "LINUX/WSL")
    return f"[{stamp}] [{source}] [{category}] {action}" + (f"  {display}" if display else "")


class LiveConsole(ttk.Frame):
    """Scrollable console; worker threads enqueue only, Tk operations stay on UI thread."""

    MAX_VISIBLE = 1200
    MAX_QUEUE = 2400

    def __init__(self, master, trace: Trace):
        super().__init__(master)
        self.trace = trace
        self._events: deque[dict] = deque(maxlen=self.MAX_VISIBLE)
        self._pending: queue.Queue[dict] = queue.Queue(maxsize=self.MAX_QUEUE)
        self._missed = 0
        self._closed = False
        self.source_choice = tk.StringVar(value="All")
        self.follow = tk.BooleanVar(value=True)
        self._build()
        for entry in trace.recent_events(limit=self.MAX_VISIBLE):
            self._events.append(entry)
        self._render()
        self.trace.subscribe(self._enqueue)
        self._job = self.after(150, self._drain)

    def _build(self):
        toolbar = ttk.Frame(self)
        toolbar.pack(fill="x", padx=7, pady=(5, 4))
        ttk.Label(toolbar, text="LIVE DIAGNOSTICS", font=("Segoe UI", 10, "bold")).pack(side="left", padx=(0, 12))
        ttk.Label(toolbar, text="Source:").pack(side="left")
        sources = ttk.Combobox(toolbar, width=14, textvariable=self.source_choice,
                               values=SOURCE_OPTIONS, state="readonly")
        sources.pack(side="left", padx=(5, 8))
        sources.bind("<<ComboboxSelected>>", lambda _event: self._render())
        ttk.Checkbutton(toolbar, text="Auto-scroll", variable=self.follow).pack(side="left")
        ttk.Button(toolbar, text="Copy Visible", command=self.copy_visible).pack(side="right", padx=4)
        ttk.Button(toolbar, text="Clear View", command=self.clear_view).pack(side="right", padx=4)
        self.text = tk.Text(self, bg="#080f19", fg="#c5d6ea", font=("Consolas", 9),
                            wrap="none", state="disabled", relief="flat", height=11)
        self.text.pack(side="left", fill="both", expand=True, padx=(7, 0), pady=(0, 6))
        scroll = ttk.Scrollbar(self, command=self.text.yview)
        scroll.pack(side="right", fill="y", padx=(0, 7), pady=(0, 6))
        self.text.configure(yscrollcommand=scroll.set)
        for tag, color in LEVEL_COLORS.items():
            self.text.tag_configure(tag, foreground=color)

    def _enqueue(self, payload: dict) -> None:
        try:
            self._pending.put_nowait(payload)
        except queue.Full:
            # Durable JSONL still has the event even if the UI is slow.
            self._missed += 1

    def _match(self, entry: dict) -> bool:
        selection = SOURCE_FILTER[self.source_choice.get()]
        return selection is None or console_source(entry) == selection

    def _insert(self, event: dict):
        if self._match(event):
            self.text.insert("end", console_format(event) + "\n", (event.get("category", ""),))

    def _render(self):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        for event in self._events:
            self._insert(event)
        self.text.configure(state="disabled")
        if self.follow.get():
            self.text.see("end")

    def _drain(self):
        if self._closed:
            return
        entries = []
        for _ in range(250):
            try:
                entries.append(self._pending.get_nowait())
            except queue.Empty:
                break
        if entries:
            overflow = len(self._events) + len(entries) > self.MAX_VISIBLE
            self._events.extend(entries)
            if overflow:
                # Re-render once per batch instead of once per dropped event.
                self._render()
            else:
                self.text.configure(state="normal")
                for entry in entries:
                    self._insert(entry)
                self.text.configure(state="disabled")
                if self.follow.get():
                    self.text.see("end")
        self._job = self.after(150, self._drain)

    def clear_view(self):
        """Clear only the display; never delete persisted diagnostic records."""
        self._events.clear()
        self._render()
        self.trace.event("USER_ACTION", "CONSOLE_VIEW_CLEARED")

    def copy_visible(self):
        content = self.text.get("1.0", "end-1c")
        self.clipboard_clear()
        self.clipboard_append(content)
        self.trace.event("USER_ACTION", "CONSOLE_VISIBLE_COPIED", lines=len(content.splitlines()))

    def close(self):
        self._closed = True
        self.trace.unsubscribe(self._enqueue)
        if self._job is not None:
            self.after_cancel(self._job)
            self._job = None
