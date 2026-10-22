import json
from pathlib import Path
import tempfile
import unittest
from zipfile import ZipFile

from universal_decompiler.diagnostics import GuidedTest, Trace


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

    def test_guided_manual_failure(self):
        trace = Trace(self.folder)
        guide = GuidedTest(trace)
        guide.begin()
        guide.fail("Unexpected blank report")
        self.assertEqual(guide.state["status"], "FAIL")
        self.assertEqual(guide.state["results"][0]["result"], "MANUAL_FAIL")


if __name__ == "__main__":
    unittest.main()
