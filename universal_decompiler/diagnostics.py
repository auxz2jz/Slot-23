"""Local-only bounded event trace and resumable guided tests for actual Stage 1 controls."""
from __future__ import annotations

from datetime import datetime, timezone
import traceback
import json
import os
import sys
from pathlib import Path
import threading
import time
from uuid import uuid4
from zipfile import ZIP_DEFLATED, ZipFile

from . import __version__


def exception_details(error: BaseException, tb=None) -> dict:
    """Safe traceback locations without paths, source lines or sensitive exception text."""
    frames = traceback.extract_tb(tb if tb is not None else error.__traceback__)
    result = {"errorType": type(error).__name__, "stackFrames": [
        {"file": Path(frame.filename).name, "function": frame.name, "line": frame.lineno}
        for frame in frames[-24:]
    ]}
    if isinstance(error, OSError) and error.errno is not None:
        result["errno"] = error.errno
    return result


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
        self.operation_marker = self.folder / "active_operation.json"
        self.session_marker = self.folder / "active_session.json"
        self.max_size = max_size
        self.session_id = str(uuid4())
        self.start = time.monotonic()
        self.sequence = 0
        self._lock = threading.Lock()
        self.event("APP", "START", result="started")
        if self.session_marker.is_file():
            try:
                previous_session = json.loads(self.session_marker.read_text(encoding="utf-8"))
                self.event("RECOVERY", "PREVIOUS_SESSION_NOT_CLOSED_CLEANLY",
                           previousSessionId=previous_session.get("appSessionId"))
            except (OSError, ValueError, TypeError):
                self.event("RECOVERY", "SESSION_MARKER_UNREADABLE")
        self._write_session_marker()
        if self.operation_marker.is_file():
            try:
                previous = json.loads(self.operation_marker.read_text(encoding="utf-8"))
                self.event("RECOVERY", "PREVIOUS_OPERATION_UNFINISHED",
                           operationId=previous.get("operationId"), operation=previous.get("operation"),
                           lastPhase=previous.get("phase"), updatedUtc=previous.get("updatedUtc"))
            except (OSError, ValueError, TypeError):
                self.event("RECOVERY", "OPERATION_MARKER_UNREADABLE")

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

    def _write_session_marker(self) -> None:
        with self._lock:
            tmp = self.session_marker.with_suffix(".tmp")
            tmp.write_text(json.dumps({"appSessionId": self.session_id,
                                       "startedUtc": now_utc()}), encoding="utf-8")
            tmp.replace(self.session_marker)

    def close_session(self) -> None:
        self.event("APP", "CLEAN_EXIT")
        with self._lock:
            self.session_marker.unlink(missing_ok=True)

    def install_exception_hooks(self) -> None:
        """Best-effort catches for otherwise unhandled Python errors; not native faults."""
        previous_sys_hook = sys.excepthook
        previous_thread_hook = threading.excepthook

        def main_hook(error_type, error, tb):
            try:
                self.event("CRASH", "UNHANDLED_MAIN_EXCEPTION", **exception_details(error, tb))
            finally:
                previous_sys_hook(error_type, error, tb)

        def thread_hook(args):
            try:
                self.event("CRASH", "UNHANDLED_THREAD_EXCEPTION", threadName=args.thread.name if args.thread else None,
                           **exception_details(args.exc_value, args.exc_traceback))
            finally:
                previous_thread_hook(args)

        sys.excepthook = main_hook
        threading.excepthook = thread_hook

    def save_operation_state(self, operation_id: str, operation: str, phase: str) -> None:
        """Crash-recovery breadcrumb; safe names only, written atomically."""
        marker = {"operationId": operation_id, "operation": operation,
                  "phase": phase, "updatedUtc": now_utc()}
        with self._lock:
            tmp = self.operation_marker.with_suffix(".tmp")
            tmp.write_text(json.dumps(marker), encoding="utf-8")
            tmp.replace(self.operation_marker)

    def finish_operation(self, operation_id: str) -> None:
        with self._lock:
            try:
                saved = json.loads(self.operation_marker.read_text(encoding="utf-8"))
                if saved.get("operationId") == operation_id:
                    self.operation_marker.unlink(missing_ok=True)
            except FileNotFoundError:
                pass
            except (OSError, ValueError, TypeError):
                pass  # Never delete an unknown/invalid marker.

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
                if self.operation_marker.exists():
                    archive.write(self.operation_marker, "active_operation.json")
                if self.session_marker.exists():
                    archive.write(self.session_marker, "active_session.json")
                if guided_test is not None:
                    archive.writestr("guided_test_results.json", json.dumps(guided_test.state, indent=2))
        return output.stat().st_size


class ScanWatchdog:
    """Monitor background scan and UI responsiveness without needing Tk's event loop.

    Reports SUSPECTED stalls rather than asserting failure; long legitimate work can
    also appear slow. One alert per no-progress interval to avoid log flooding.
    """

    def __init__(self, trace: Trace, correlation_id: str, *, progress_timeout: float = 45.0,
                 ui_timeout: float = 20.0, check_interval: float = 2.0):
        self.trace = trace
        self.correlation_id = correlation_id
        self.progress_timeout = progress_timeout
        self.ui_timeout = ui_timeout
        self.check_interval = check_interval
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._last_progress = time.monotonic()
        self._last_ui = self._last_progress
        self._phase = "starting"
        self._reported_progress = False
        self._reported_ui = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._monitor, name="stage1-watchdog", daemon=True)
        self._thread.start()

    def progress(self, phase: str, *, bytes_processed: int | None = None) -> None:
        with self._lock:
            self._phase = phase
            self._last_progress = time.monotonic()
            self._reported_progress = False

    def ui_heartbeat(self) -> None:
        with self._lock:
            self._last_ui = time.monotonic()
            self._reported_ui = False

    def inspect(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        with self._lock:
            progress_gap = now - self._last_progress
            ui_gap = now - self._last_ui
            phase = self._phase
            warn_progress = progress_gap >= self.progress_timeout and not self._reported_progress
            warn_ui = ui_gap >= self.ui_timeout and not self._reported_ui
            if warn_progress:
                self._reported_progress = True
            if warn_ui:
                self._reported_ui = True
        if warn_progress:
            self.trace.event("WATCHDOG", "SCAN_PROGRESS_STALLED", correlation_id=self.correlation_id,
                             phase=phase, secondsWithoutProgress=round(progress_gap, 1))
        if warn_ui:
            self.trace.event("WATCHDOG", "UI_UNRESPONSIVE_SUSPECTED", correlation_id=self.correlation_id,
                             phase=phase, secondsWithoutUIHeartbeat=round(ui_gap, 1))

    def _monitor(self) -> None:
        while not self._stop.wait(self.check_interval):
            self.inspect()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=1)


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
