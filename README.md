# Universal Decompiler — Stage 1 (Windows desktop candidate)

**Status:** v0.1.2 **CANDIDATE**, **not user-verified**. This is the first step only, not a working decompiler yet.

**Repository:** [auxz2jz/Slot-23](https://github.com/auxz2jz/Slot-23)  
**Rules:** [Master Instruction Library](https://github.com/auxz2jz/master-instruction-library) (read `INSTRUCTION_INDEX.md` first; see `AGENTS.md`).

## What it does right now

- Runs as a Windows-friendly desktop application, built with Python's standard-library Tkinter UI.
- Opens local files read-only; **does not execute the input binary**.
- Detects ordinary Windows PE executables (including architecture and sections), ELF headers, and a few compression/filesystem/container signatures.
- Computes SHA-256 and presents a hex/ASCII preview and signature/structure candidates.
- Includes a **visible, resizable Live Diagnostics console** during Stage 1. It shows time-stamped application events in real time; sources can be filtered to Application, Windows, or Linux / WSL. It supports Copy Visible and Clear View (clear never deletes saved logs).
- Saves a plain-text report; optionally exports local structured diagnostics (JSONL in ZIP). Background scan watchdog tracks suspected scan stalls, unresponsive UI, sanitized Python error frames and interrupted runs, with recovery after restart.
- Contains an output bridge for recording **stdout and stderr from future trusted Windows or Linux/WSL tools** in the same console and diagnostic ZIP. No external analysis subprocess is launched in Stage 1; WSL and Linux tool integrations remain future work.
- Provides a resumable **Test This Version** guided test for opening/scanning a PE and saving a validated report.
- Uses only the Python standard library. No subscriptions, online API calls, or elevated privileges needed.

**Limits:** Does **not** decompile, disassemble, execute, decrypt, unpack, patch, or reflash firmware. Raw `.bin` may have **unknown architecture**. A matching magic string is **only a candidate**, not proof of a genuine partition. Exact chips are not inferred from common CPU architecture alone. Only the first 4 MiB are signature-scanned; SHA-256 covers the full file.

## Run it on Windows (source version)

1. Install Python **3.11+** for Windows from python.org, with Tk/Tcl included.
2. Download/clone this repository.
3. Double-click `run_windows.bat` (or in terminal use `py -3 -m universal_decompiler.app`).
4. Click **Open File** and select a file you own or are authorized to inspect.
5. Click **Scan**. Inspect its detected type and save a report if useful.
6. Watch **Live Diagnostics** at the bottom. Drag its divider to make it taller, and choose **Application / Windows / Linux / WSL** from Source. Stage 1 generates application events; the Windows and Linux/WSL source filters will become populated when those external engines are integrated. **Clear View** does not delete saved logs. **Copy Visible** copies the currently displayed lines.
7. Click **Test This Version** to follow the guided two-step PE test. Export diagnostics if anything fails.
8. If a scan freezes, close/reopen the app when possible, then click **Export Diagnostics**. If the GUI will not reopen, retrieve the files from `%LOCALAPPDATA%\UniversalDecompiler`. The diagnostics do not include the analyzed binary; review logs/tester notes before sharing.

There is **no prebuilt Windows `.exe` or installer** in this milestone. Packaging using PyInstaller on an actual Windows machine is a **later atomic task**; a Linux-built executable is not a Windows executable.

## Developer quick check

From the repository root:

```powershell
py -3 -m unittest discover -s tests -v
py -3 -m universal_decompiler.app
```

Tests use synthetic PE/ELF data and do not use proprietary files. CI and user verification on Windows remain future work. GUI rendering and stream bridging have been smoke-tested under Linux/Xvfb; this is not a Windows verification. Watchdog detections are best-effort: hard process crashes, power outages, native faults, and all future decompilation worker failures are not guaranteed to leave complete evidence. Never upload unlicensed/private firmware or diagnostic archives without reviewing their contents.

## Where to continue

- `AGENTS.md` — mandatory external global-rule entry point.
- `docs/PROJECT_MEMORY.md` — verified/candidate state, decisions, known limitations.
- `docs/ROADMAP.md` — next bounded steps and stage overview.
- `docs/DIAGNOSTICS_AND_TESTING.md` — real controls, coverage map, test actions.
- `docs/CODEX_HANDOFF.md` — exact recovery/next action for Codex.

## Live diagnostics and external tools

- `universal_decompiler/live_console.py` is a **read-only** graphical log viewer. It subscribes to the durable `Trace` service and displays worker-thread events safely on Tk's UI thread.
- `universal_decompiler/tool_output.py` provides `ToolOutputBridge`: future trusted tool integrations can feed **stdout/stderr** chunks with source `WINDOWS` or `LINUX_WSL`, preserving a shared correlation ID. Tool commands cannot be typed or executed in the diagnostic console, and analyzed executables are **never** run.
- No Linux installation is required for the Stage 1 scanner. Later Linux-only analysis tools may run through WSL2, if available; this is **not wired to an external tool yet**.
- Tool output is truncated and redacted on a best-effort basis before local persistence. Because arbitrary external stdout/stderr may contain private information, **review ZIP contents before sharing**. Export is manual only; nothing is uploaded automatically.
- UI queue and visible history are bounded; full retained diagnostics use a rotating current and previous JSONL file. The visible **Clear View** button affects only the display, not the saved evidence.
