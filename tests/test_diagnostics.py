import json
import sys
import threading
from pathlib import Path
import tempfile
import unittest
from zipfile import ZipFile

from universal_decompiler.diagnostics import GuidedTest, Trace, ScanWatchdog, exception_details


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

    def test_structured_trace_and_zip(self):
        trace = Trace(self.folder)
        trace.event("USER_ACTION", "SCAN", correlation_id="example", filename="test.exe")
        events = [json.loads(line) for line in trace.file.read_text().splitlines()]
        self.assertEqual(events[1]["category"], "USER_ACTION")
        self.assertEqual(events[1]["correlationId"], "example")
        zip_path = self.folder / "diagnostics.zip"
        self.assertGreater(trace.export_zip(zip_path), 0)
        with ZipFile(zip_path) as f:
            self.assertIn("events.jsonl", f.namelist())
            self.assertNotIn("test.exe", f.namelist())

    def test_guided_test_persists_and_cannot_pass_by_button_only(self):
        trace = Trace(self.folder)
        guide = GuidedTest(trace)
        guide.begin()
        guide.observe("T1-PE-SCAN", False, "Not a valid PE")
        self.assertEqual(guide.state["nextStep"], 0)
        guide.observe("T1-PE-SCAN", True, "PE header and hash validated")
        resumed = GuidedTest(trace)
        self.assertEqual(resumed.state["nextStep"], 1)
        resumed.observe("T2-SAVE-REPORT", True, "Output file checked")
        self.assertEqual(resumed.state["status"], "PASS")
        zip_path = self.folder / "results.zip"
        trace.export_zip(zip_path, resumed)
        with ZipFile(zip_path) as f:
            self.assertIn("guided_test_results.json", f.namelist())


    def test_unfinished_scan_reported_after_restart(self):
        trace = Trace(self.folder)
        trace.save_operation_state("op-id", "SCAN", "hashing")
        recovered = Trace(self.folder)
        entries = [json.loads(line) for line in recovered.file.read_text().splitlines()]
        interruptions = [e for e in entries if e["action"] == "PREVIOUS_OPERATION_UNFINISHED"]
        self.assertTrue(interruptions)
        self.assertEqual(interruptions[-1]["details"]["lastPhase"], "hashing")
        recovered.finish_operation("op-id")
        self.assertFalse(recovered.operation_marker.exists())

    def test_watchdog_logs_stall_once_until_progress(self):
        trace = Trace(self.folder)
        monitor = ScanWatchdog(trace, "run-id", progress_timeout=1.0, ui_timeout=1.0)
        monitor.inspect(now=monitor._last_progress + 3.0)
        monitor.inspect(now=monitor._last_progress + 4.0)
        entries = [json.loads(line) for line in trace.file.read_text().splitlines()]
        self.assertEqual(sum(e["action"] == "SCAN_PROGRESS_STALLED" for e in entries), 1)
        self.assertEqual(sum(e["action"] == "UI_UNRESPONSIVE_SUSPECTED" for e in entries), 1)
        monitor.progress("hashing")
        monitor.ui_heartbeat()
        monitor.inspect(now=monitor._last_progress + 3.0)
        entries = [json.loads(line) for line in trace.file.read_text().splitlines()]
        self.assertEqual(sum(e["action"] == "SCAN_PROGRESS_STALLED" for e in entries), 2)

    def test_exception_frames_redact_paths_and_messages(self):
        try:
            raise ValueError("Sensitive C:/private/location/secret.bin")
        except ValueError as exc:
            details = exception_details(exc)
        self.assertEqual(details["errorType"], "ValueError")
        self.assertTrue(details["stackFrames"])
        self.assertNotIn("Sensitive", str(details))
        self.assertNotIn("/private/location", str(details))
        self.assertNotIn("\\", str(details))

    def test_unclosed_session_is_reported_but_clean_exit_is_not(self):
        first = Trace(self.folder)
        first.close_session()
        second = Trace(self.folder)
        entries = [json.loads(line) for line in second.file.read_text().splitlines()]
        self.assertFalse(any(e["action"] == "PREVIOUS_SESSION_NOT_CLOSED_CLEANLY" for e in entries))
        third = Trace(self.folder)
        entries = [json.loads(line) for line in third.file.read_text().splitlines()]
        self.assertTrue(any(e["action"] == "PREVIOUS_SESSION_NOT_CLOSED_CLEANLY" for e in entries))

    def test_unhandled_python_thread_exception_is_logged(self):
        trace = Trace(self.folder)
        original = threading.excepthook
        threading.excepthook = lambda args: None  # keep an intentional test exception off stderr
        trace.install_exception_hooks()
        try:
            worker = threading.Thread(target=lambda: 1 / 0)
            # Thread exception is forwarded to original hook; still logged.
            worker.start()
            worker.join()
        finally:
            threading.excepthook = original
        entries = [json.loads(line) for line in trace.file.read_text().splitlines()]
        self.assertTrue(any(e["action"] == "UNHANDLED_THREAD_EXCEPTION" for e in entries))

    def test_guided_manual_failure(self):
        trace = Trace(self.folder)
        guide = GuidedTest(trace)
        guide.begin()
        guide.fail("Unexpected blank report")
        self.assertEqual(guide.state["status"], "FAIL")
        self.assertEqual(guide.state["results"][0]["result"], "MANUAL_FAIL")


if __name__ == "__main__":
    unittest.main()
