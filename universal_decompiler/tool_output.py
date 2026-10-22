"""Future Windows/WSL tool-output bridge: no program execution in Stage 1.

Accept text from trusted external tool stdout/stderr and record bounded sanitized
lines for the same diagnostic console. An analyzed EXE is never a tool to invoke.
"""
from __future__ import annotations

import re

from .diagnostics import Trace

ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
SECRETS = re.compile(r"(?i)\b(?:api[_-]?key|authorization|access[_-]?token|password|secret)\s*[:=]\s*(?:bearer\s+)?\S+|\bbearer\s+\S+")
WINDOWS_PATH = re.compile(r"(?i)\b[A-Z]:\\(?:[^\\\s]+\\)*[^\\\s]+")
UNIX_PATH = re.compile(r"(?<!\w)/(?:home|Users|root|mnt)/(?:[^\s]+)")


def sanitize_tool_text(text: str, max_length: int = 280) -> str:
    """Best-effort privacy scrubbing; exports still require user review."""
    text = ANSI.sub("", text).replace("\x00", "")
    text = SECRETS.sub("[REDACTED_SECRET]", text)
    text = WINDOWS_PATH.sub("[REDACTED_PATH]", text)
    text = UNIX_PATH.sub("[REDACTED_PATH]", text)
    text = "".join(ch if ch.isprintable() or ch == "\t" else "?" for ch in text)
    return text[:max_length]


class ToolOutputBridge:
    """Feed stdout or stderr chunks from *trusted* Windows or Linux/WSL tools.

    No subprocess is launched. Future tools can stream chunks into this bridge.
    """

    def __init__(self, trace: Trace, *, source: str, stream: str, correlation_id: str,
                 max_line_bytes: int = 1024):
        if source not in ("WINDOWS", "LINUX_WSL"):
            raise ValueError("Unsupported tool source")
        if stream not in ("stdout", "stderr"):
            raise ValueError("Unsupported stream")
        self.trace = trace
        self.source = source
        self.stream = stream
        self.correlation_id = correlation_id
        self.max_line_bytes = max_line_bytes
        self._pending = ""
        self._truncated = False

    def feed(self, chunk: str):
        # Split before storing, do not retain arbitrarily long or binary output.
        for char in chunk:
            if char == "\n":
                self._emit()
            elif len(self._pending) < self.max_line_bytes:
                self._pending += char
            else:
                self._truncated = True

    def finish(self):
        if self._pending or self._truncated:
            self._emit()

    def _emit(self):
        text = sanitize_tool_text(self._pending.rstrip("\r"))
        self.trace.event("TOOL_STDOUT" if self.stream == "stdout" else "TOOL_STDERR", "OUTPUT_LINE",
                         correlation_id=self.correlation_id, source=self.source, stream=self.stream,
                         text=text, lineTruncated=self._truncated)
        self._pending = ""
        self._truncated = False
