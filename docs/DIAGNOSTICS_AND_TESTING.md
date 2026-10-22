# Diagnostics and guided testing — actual Stage 1 coverage

The master `DIAGNOSTICS_STANDARD.md` and `GUIDED_TESTING_STANDARD.md` are authoritative. This maps **only currently implemented controls**, not mock buttons.

| User control | Request / measured result (not merely click) | Failure signal | Guided verification |
|---|---|---|---|
| Open File | File selected, basename present | Cancel; invalid file found at scan | Test T1: choose real Windows EXE |
| Scan | `ANALYZE_SUCCEEDED` after valid parse/hash; report properties recorded | `SCAN_FAILED`; error type and sanitized stack frames recorded | T1 automatic: PE format, known architecture, SHA-256 |
| Save Report | Write TXT and re-read to verify nonzero output with matching SHA-256 | `SAVE_FAILED` | T2 automatic validated output |
| Export Diagnostics | ZIP exists, nonempty, local events JSONL present | `EXPORT_FAILED` | Manual confirmation and archived results |
| Live Diagnostics | Display queued Trace events (including scan phase/watchdog/error) and replay durable recent events; filter Application, Windows, Linux / WSL; Copy Visible; Clear View only | UI queue overflow drops display entries, persisted trace remains authoritative | Manual: confirm active scan messages, filtering and copy/clear |
| External output bridge (future tools) | `WINDOWS` and `LINUX_WSL` stdout/stderr chunks are bounded, privacy-scrubbed and persisted as `TOOL_STDOUT`/`TOOL_STDERR` | Truncation recorded (`lineTruncated`), no tool processes launched in Stage 1 | Synthetic stream bridge tests; actual WSL and external tools pending |
| Test This Version | Persistent test session, step results `AUTO_VERIFIED` or `MANUAL_FAIL` | User `Expected Behavior Failed`, unexpected UI error | T1/T2 guided workflow |

- Local log: `%LOCALAPPDATA%\\UniversalDecompiler\\events.jsonl` on Windows; rotating bounded current and previous files.
- Active operation recovery marker: `%LOCALAPPDATA%\UniversalDecompiler\active_operation.json` (operation ID and last known phase; no original binary content or full path).
- Unexpected termination marker: `%LOCALAPPDATA%\UniversalDecompiler\active_session.json` (flags unclean exit on next launch).
- During scans, a background watchdog records **suspected** no-progress or unresponsive-UI events even if the Tk UI stops processing events; it does not force-terminate operations. SHA-256 hashing emits periodic progress heartbeats.
- Python uncaught errors and Tk callback exceptions record redacted traceback locations (function, source basename, line, exception type). No raw exception message or input file path is included by default.
- After an unexpected stop or forced close, reopen the application and use **Export Diagnostics**; it will include the previous event logs and unfinished-operation marker when present. If reopening fails, the files in this directory remain available for manual support.
- Local guided session: `%LOCALAPPDATA%\\UniversalDecompiler\\guided_test.json` on Windows. Persists restart.
- The test does not auto-pass from a button click; the scan and report output must be validated.
- Diagnostics include UTC timestamps, session/event/correlation/test IDs, sequence, elapsed monotonic time, category, result and safe metadata.
- Diagnostic archive includes summary, current/previous events, and guided-test results. **It does not include the scanned binary or original file paths.** User test notes may be sensitive; inspect before sharing.
- Known limitations: live console and stream bridging tested locally under Linux/Xvfb but not physically validated on Windows; no actual Linux/WSL tools are launched; user interface could not be visually tested on Windows in the preparation environment. Watchdog events report *suspected stalls*, not guaranteed causes. A hard OS kill, power failure, native-process fault, or storage failure may prevent the final error from being written. There is not yet an active cancel command or a separate external-process watchdog; these must be added and tested with future disassembly/decompilation workers. Logs do not include sensitive source paths, source bytes or unrestricted exception messages.
- Future decompilation stages must instrument every child process/phase with start/progress/completion/failure events, resource/stall monitoring, source file association by anonymized identifier, and correlation IDs; do not consider a new stage complete without diagnostic export and guided failure-path tests.

## Guided manual test (v0.1.1 candidate)

1. Click **Test This Version**; note T1. Click **Open File**, choose a known Windows `.exe` (not an arbitrary unknown downloaded executable), then click **Scan**. **Expected:** Windows Portable Executable, recognizable architecture, SHA-256. The app auto-records T1 when real properties are detected.
2. Click **Save Report**, choose a location. **Expected:** a nonempty text report with the same file SHA-256. The app auto-records T2 only after validating the output file.
3. Reopen **Test This Version** and inspect PASS, or use **Expected Behavior Failed** to record the first failing step. Use **Export Diagnostics** if a problem occurred.
4. Test recovery manually: start a legitimate large-file scan and force-close the app while it is busy. Reopen the app; use **Export Diagnostics** and confirm the `PREVIOUS_OPERATION_UNFINISHED` event and `active_operation.json` appear. **Do not terminate/modify the source binary itself.**
5. Record the *user's* physical confirmation in project memory before promoting any version to VERIFIED.

## Developer unit tests

`python -m unittest discover -s tests -v` covers synthetic PE x64, ELF ARM64, malformed PE/ELF, unknown raw binary, compressed container magic, candidate firmware signatures, SHA-256, structured diagnostics, ZIP export and guided-state persistence.

The headless automated suite now also covers watchdog event deduplication, interrupted operation recovery, clean/unclean session markers, sanitized error frames, and unhandled thread errors.

## Live console verification (v0.1.2; manual Windows testing still needed)

1. Open the app and verify **Live Diagnostics** appears below the hex panel and can be resized by dragging the separator.
2. Select a known PE executable and click **Scan**. Verify `OPEN_FILE`, `SCAN`, `SCAN_PROGRESS`, `ANALYZE_SUCCEEDED` appear with timestamps; an actual failure instead records `SCAN_FAILED`.
3. Choose **Application**, **Windows**, **Linux / WSL**, then **All** in the Source dropdown. Stage 1 produces only Application events; the others may correctly be empty until external engines are integrated.
4. Click **Copy Visible** and paste into Notepad. Click **Clear View** and confirm lines disappear **from the screen only**. Scan again; new log lines appear.
5. Click **Export Diagnostics**, inspect `events.jsonl`, confirm past events (including the ones cleared from view) remain in the archive. Check that original binary content is absent.
6. For future external tool integration: feed synthetic stdout and stderr using the `ToolOutputBridge` and verify both platform-specific source labels. Do not use unknown/untrusted executable files as commands.

## Output bridge contract

Future trusted Windows/WSL tool runners must preserve operation ID and capture stdout and stderr separately as streamed text, call `ToolOutputBridge(..., source="WINDOWS" | "LINUX_WSL", stream="stdout" | "stderr", correlation_id=...)`, call `feed(chunk)` for each chunk and `finish()` at EOF, then persist exit status as an `OPERATION_RESULT` event. **No executable runner is shipped yet**, no automatic WSL detection/installation, and the console is not an interactive shell. Always run external tools with a reviewed command/argument array, never a shell string or the analyzed input program; add timeout/stall monitoring and secure subprocess lifecycle before turning them on. Best-effort output redaction cannot eliminate every sensitive value; user reviews exports.
