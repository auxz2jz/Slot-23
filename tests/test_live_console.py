"""Headless tests for durable display sources and Windows/WSL output bridges."""
import tempfile
from pathlib import Path
import unittest

from universal_decompiler.diagnostics import Trace
from universal_decompiler.live_console import console_format, console_source, SOURCE_FILTER
from universal_decompiler.tool_output import ToolOutputBridge, sanitize_tool_text


class LiveConsoleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.trace = Trace(Path(self.temp.name))

    def test_live_observer_and_replay(self):
        emitted = []
        def callback(event):
            emitted.append(event)
        self.trace.subscribe(callback)
        eid = self.trace.event('STATE_TRANSITION', 'SCAN_PROGRESS', phase='hashing')
        self.trace.unsubscribe(callback)
        self.trace.event('OPERATION_RESULT', 'SCAN_DONE')
        self.assertEqual([e['eventId'] for e in emitted], [eid])
        self.assertEqual(len(self.trace.recent_events()), 3)  # START + scan + done
        self.assertIn('SCAN_PROGRESS', console_format(emitted[0]))

    def test_source_labels(self):
        self.assertEqual(console_source({'details': {'source': 'LINUX_WSL'}}), 'LINUX_WSL')
        self.assertEqual(console_source({'details': {'source': 'WINDOWS'}}), 'WINDOWS')
        self.assertEqual(console_source({'details': {}}), 'APP')
        self.assertEqual(SOURCE_FILTER['Linux / WSL'], 'LINUX_WSL')

    def test_windows_and_linux_stdout_stderr_persisted(self):
        for source in ('WINDOWS', 'LINUX_WSL'):
            bridge = ToolOutputBridge(self.trace, source=source, stream='stdout', correlation_id='operation-1')
            bridge.feed('Loading ')
            bridge.feed('symbols\nComplete')
            bridge.finish()
            error = ToolOutputBridge(self.trace, source=source, stream='stderr', correlation_id='operation-1')
            error.feed('unable to load debug symbols\n')
            events = [e for e in self.trace.recent_events() if e.get('details', {}).get('source') == source]
            self.assertEqual([e['category'] for e in events], ['TOOL_STDOUT', 'TOOL_STDOUT', 'TOOL_STDERR'])
            self.assertEqual(events[0]['details']['text'], 'Loading symbols')
            self.assertIn(source.replace('LINUX_WSL', 'LINUX/WSL'), console_format(events[0]))
            self.assertEqual(events[1]['details']['text'], 'Complete')
            self.assertEqual(events[2]['details']['text'], 'unable to load debug symbols')

    def test_truncated_sensitive_output_and_invalid_source(self):
        trace = self.trace
        with self.assertRaises(ValueError):
            ToolOutputBridge(trace, source='OTHER', stream='stdout', correlation_id='1')
        bridge = ToolOutputBridge(trace, source='LINUX_WSL', stream='stderr', correlation_id='1', max_line_bytes=16)
        bridge.feed('A'*10000 + '\n')
        events = [e for e in trace.recent_events() if e['category'] == 'TOOL_STDERR']
        self.assertEqual(len(events), 1)
        self.assertTrue(events[0]['details']['lineTruncated'])
        self.assertEqual(events[0]['details']['text'], 'A'*16)
        self.assertIn('[REDACTED_PATH]', sanitize_tool_text('Access denied: C:\\Users\\Bob\\Documents\\a.txt'))
        self.assertIn('[REDACTED_PATH]', sanitize_tool_text('/home/bob/private/path'))
        self.assertNotIn('xyz123', sanitize_tool_text('Authorization: Bearer xyz123'))


if __name__ == '__main__':
    unittest.main()
