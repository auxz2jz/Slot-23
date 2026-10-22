# Codex handoff — concise recovery entry point

- Project/repo: `auxz2jz/Slot-23`; global rules: `auxz2jz/master-instruction-library/INSTRUCTION_INDEX.md` then mandatory files (see `AGENTS.md`).
- Phase: Stage 1 identification; v0.1.2, **CANDIDATE**. Last **user-verified** baseline: **NONE**.
- Current task: `UD-S1-001C` live diagnostic console completed locally (20 automated tests pass and Linux/Xvfb smoke test); earlier `UD-S1-001D` diagnostic hardening completed locally (16 automated tests passed); earlier `UD-S1-001` code/docs prepared and local targeted tests recorded in the completion report. **Do not call Windows behavior verified.**
- Current branch: `main`; source is the repository; inspect Git actual HEAD rather than assuming any SHA listed in chat.
- Source: `universal_decompiler/analyzer.py` scanner, `app.py` Tkinter desktop, `live_console.py` resizable, filtered live UI and `tool_output.py` bounded Windows/WSL output bridge (future tools only), `diagnostics.py` local trace/guided tests, scan watchdog, interrupted-run marker and sanitized error frames; `run_windows.bat`, synthetic tests.
- Exact local test command: `python -m unittest discover -s tests -v` (Windows: `py -3 -m unittest discover -s tests -v`).
- Not done: actual Windows/WSL tool runner integration (Stage 1 only supports scanner and simulated output streams); Windows launch/visual testing and user physical verification; packaging to `.exe`; any true disassembly or decompilation.
- Limit: Python exceptions and suspected scan stalls are recorded; native hard crashes, power loss, and future decompilation subprocesses are not fully covered yet. Export ZIP after restart; watchdog does not cancel/terminate a stuck scan.
- Exact next action: user runs `run_windows.bat` on Windows and follows **Test This Version**, inspects **Live Diagnostics** while scanning and verifies **Export Diagnostics**; evaluate first failed operation, diagnostics and screenshot before any code change. If user requests Codex continuation, read the latest results and address only the next authorized task.
- Next task ID once authorized: `UD-S1-002` Windows GUI verification. Recommended model/reasoning: **Medium** for routine launch/build/test; escalate to High only for a difficult reproducible technical defect. Checkpoint after test result.
- Usage limits: unknown; do not guess account usage or promise automatic pausing/resumption.
- Safety: read-only, never execute unknown binaries, write private input contents, or flash hardware.
