"""Local-only bounded event trace and resumable guided tests for actual Stage 1 controls."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading
import time
from uuid import uuid4
from zipfile import ZIP_DEFLATED, ZipFile

from . import __version__


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def data_directory() -> Path:
    base = os.getenv("LOCALAPPDATA") or str(Path.home() / ".universal_decompiler")
    result = Path(base) / "UniversalDecompiler" if os.getenv("LOCALAPPDATA") else Path(base)
    result.mkdir(parents=True, exist_ok=True)
    return result


class Trace:
    """Thread-safe JSONL trace, with one bounded current file and one previous file."""

    def __init__(self, folder: Path | None = None, max_size: int = 2_000_000):
        self.folder = folder or data_directory()
        self.folder.mkdir(parents=True, exist_ok=True)
        self.file = self.folder / "events.jsonl"
        self.previous = self.folder / "events.previous.jsonl"
        self.max_size = max_size
        self.session_id = str(uuid4())
        self.start = time.monotonic()
        self.sequence = 0
        self._lock = threading.Lock()
        self.event("APP", "START", result="started")

    def event(self, category: str, action: str, *, correlation_id: str | None = None,
              test_session_id: str | None = None, **metadata) -> str:
        """Caller passes only safe, non-secret metadata; never full input paths/bytes."""
        event_id = str(uuid4())
        with self._lock:
            self.sequence += 1
            payload = {
                "eventId": event_id, "sequenceNumber": self.sequence,
                "timestampUtc": now_utc(),
                "monotonicTimeMs": round((time.monotonic() - self.start) * 1000),
                "appSessionId": self.session_id, "appVersion": __version__,
                "category": category, "action": action,
                "correlationId": correlation_id, "testSessionId": test_session_id,
                "details": metadata,
            }
            if self.file.exists() and self.file.stat().st_size >= self.max_size:
                self.previous.unlink(missing_ok=True)
                self.file.replace(self.previous)
            with self.file.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(payload, ensure_ascii=True) + "\n")
                stream.flush()
        return event_id

    def export_zip(self, output: Path, guided_test: "GuidedTest | None" = None) -> int:
        # Explicit user export only; source binaries are NEVER included.
        with self._lock:
            with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
                archive.writestr("README.txt", "Universal Decompiler local diagnostics. No analyzed file contents included.\n")
                archive.writestr("summary.txt", f"Version: {__version__}\nSession ID: {self.session_id}\nUTC: {now_utc()}\n")
                if self.file.exists():
                    archive.write(self.file, "events.jsonl")
                if self.previous.exists():
                    archive.write(self.previous, "events.previous.jsonl")
                if guided_test is not None:
                    archive.writestr("guided_test_results.json", json.dumps(guided_test.state, indent=2))
        return output.stat().st_size


class GuidedTest:
    """Two actual app workflows, tracked persistently across restart."""

    STEPS = (
        {
            "id": "T1-PE-SCAN", "title": "Scan a Windows program",
            "instruction": "Click Open File and choose a Windows .exe. Click Scan.",
            "expected": "Report says Windows Portable Executable (PE), has an architecture, and contains its file hash.",
        },
        {
            "id": "T2-SAVE-REPORT", "title": "Export the analysis report",
            "instruction": "With that scanned file still selected, click Save Report and choose an output .txt file.",
            "expected": "The saved file exists, is nonempty, and contains the SHA-256 from the scan.",
        },
    )

    def __init__(self, trace: Trace):
        self.trace = trace
        self.path = trace.folder / "guided_test.json"
        if self.path.is_file():
            try:
                state = json.loads(self.path.read_text(encoding="utf-8"))
                self.state = state if state.get("appVersion") == __version__ else self._new_state()
            except (OSError, ValueError, TypeError):
                self.state = self._new_state()
        else:
            self.state = self._new_state()

    def _new_state(self) -> dict:
        return {
            "testSessionId": str(uuid4()), "appVersion": __version__,
            "startedUtc": now_utc(), "completedUtc": None, "status": "UNTESTED",
            "nextStep": 0, "results": [],
        }

    def begin(self) -> None:
        if self.state["status"] in ("PASS", "FAIL", "UNTESTED"):
            self.state = self._new_state()
        self.state["status"] = "IN_PROGRESS"
        self._save()
        self.trace.event("TEST", "SESSION_STARTED", test_session_id=self.state["testSessionId"])

    def current_step(self) -> dict | None:
        idx = self.state["nextStep"]
        return self.STEPS[idx] if 0 <= idx < len(self.STEPS) else None

    def observe(self, step_id: str, success: bool, evidence: str) -> None:
        step = self.current_step()
        if self.state["status"] != "IN_PROGRESS" or step is None or step["id"] != step_id:
            return
        if not success:
            # Do not automatically fail when the user selects a different file.
            return
        self.state["results"].append({
            "stepId": step_id, "result": "AUTO_VERIFIED",
            "timestampUtc": now_utc(), "evidence": evidence,
        })
        self.trace.event("TEST", "STEP_PASSED", test_session_id=self.state["testSessionId"], stepId=step_id, evidence=evidence)
        self.state["nextStep"] += 1
        if self.current_step() is None:
            self.state["status"] = "PASS"
            self.state["completedUtc"] = now_utc()
            self.trace.event("TEST", "GUIDED_TEST_FINISHED", test_session_id=self.state["testSessionId"], result="PASS")
        self._save()

    def fail(self, note: str) -> None:
        step = self.current_step()
        if not step or self.state["status"] != "IN_PROGRESS":
            return
        # User note may contain arbitrary sensitive data: retain on device only.
        self.state["results"].append({
            "stepId": step["id"], "result": "MANUAL_FAIL", "timestampUtc": now_utc(),
            "testerNote": note,
        })
        self.state["status"] = "FAIL"
        self.state["completedUtc"] = now_utc()
        self._save()
        self.trace.event("TEST", "STEP_FAILED", test_session_id=self.state["testSessionId"], stepId=step["id"], reason="User-reported failure")

    def _save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state, indent=2), encoding="utf-8")
        tmp.replace(self.path)
