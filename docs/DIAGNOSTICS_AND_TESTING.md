# Diagnostics and guided testing — actual Stage 1 coverage

The master `DIAGNOSTICS_STANDARD.md` and `GUIDED_TESTING_STANDARD.md` are authoritative. This maps **only currently implemented controls**, not mock buttons.

| User control | Request / measured result (not merely click) | Failure signal | Guided verification |
|---|---|---|---|
| Open File | File selected, basename present | Cancel; invalid file found at scan | Test T1: choose real Windows EXE |
| Scan | `ANALYZE_SUCCEEDED` after valid parse/hash; report properties recorded | `SCAN_FAILED`; error type recorded | T1 automatic: PE format, known architecture, SHA-256 |
| Save Report | Write TXT and re-read to verify nonzero output with matching SHA-256 | `SAVE_FAILED` | T2 automatic validated output |
| Export Diagnostics | ZIP exists, nonempty, local events JSONL present | `EXPORT_FAILED` | Manual confirmation and archived results |
| Test This Version | Persistent test session, step results `AUTO_VERIFIED` or `MANUAL_FAIL` | User `Expected Behavior Failed`, unexpected UI error | T1/T2 guided workflow |

- Local log: `%LOCALAPPDATA%\\UniversalDecompiler\\events.jsonl` on Windows; rotating bounded current and previous files.
- Local guided session: `%LOCALAPPDATA%\\UniversalDecompiler\\guided_test.json` on Windows. Persists restart.
- The test does not auto-pass from a button click; the scan and report output must be validated.
- Diagnostics include UTC timestamps, session/event/correlation/test IDs, sequence, elapsed monotonic time, category, result and safe metadata.
- Diagnostic archive includes summary, current/previous events, and guided-test results. **It does not include the scanned binary or original file paths.** User test notes may be sensitive; inspect before sharing.
- Known limitations: user interface could not be visually tested on Windows in the preparation environment; watchdog/cancellation and richer crash artifacts are future work as slow/background operations expand. Caught scan failures omit raw path text intentionally.

## Guided manual test (v0.1.0)

1. Click **Test This Version**; note T1. Click **Open File**, choose a known Windows `.exe` (not an arbitrary unknown downloaded executable), then click **Scan**. **Expected:** Windows Portable Executable, recognizable architecture, SHA-256. The app auto-records T1 when real properties are detected.
2. Click **Save Report**, choose a location. **Expected:** a nonempty text report with the same file SHA-256. The app auto-records T2 only after validating the output file.
3. Reopen **Test This Version** and inspect PASS, or use **Expected Behavior Failed** to record the first failing step. Use **Export Diagnostics** if a problem occurred.
4. Record the *user's* physical confirmation in project memory before promoting any version to VERIFIED.

## Developer unit tests

`python -m unittest discover -s tests -v` covers synthetic PE x64, ELF ARM64, malformed PE/ELF, unknown raw binary, compressed container magic, candidate firmware signatures, SHA-256, structured diagnostics, ZIP export and guided-state persistence.
