# Universal Decompiler — Stage 1 (Windows desktop candidate)

**Status:** v0.1.1 **CANDIDATE**, **not user-verified**. This is the first step only, not a working decompiler yet.

**Repository:** [auxz2jz/Slot-23](https://github.com/auxz2jz/Slot-23)  
**Rules:** [Master Instruction Library](https://github.com/auxz2jz/master-instruction-library) (read `INSTRUCTION_INDEX.md` first; see `AGENTS.md`).

## What it does right now

- Runs as a Windows-friendly desktop application, built with Python's standard-library Tkinter UI.
- Opens local files read-only; **does not execute the input binary**.
- Detects ordinary Windows PE executables (including architecture and sections), ELF headers, and a few compression/filesystem/container signatures.
- Computes SHA-256 and presents a hex/ASCII preview and signature/structure candidates.
- Saves a plain-text report; optionally exports local structured diagnostics (JSONL in ZIP). Background scan watchdog tracks suspected scan stalls, unresponsive UI, sanitized Python error frames and interrupted runs, with recovery after restart.
- Provides a resumable **Test This Version** guided test for opening/scanning a PE and saving a validated report.
- Uses only the Python standard library. No subscriptions, online API calls, or elevated privileges needed.

**Limits:** Does **not** decompile, disassemble, execute, decrypt, unpack, patch, or reflash firmware. Raw `.bin` may have **unknown architecture**. A matching magic string is **only a candidate**, not proof of a genuine partition. Exact chips are not inferred from common CPU architecture alone. Only the first 4 MiB are signature-scanned; SHA-256 covers the full file.

## Run it on Windows (source version)

1. Install Python **3.11+** for Windows from python.org, with Tk/Tcl included.
2. Download/clone this repository.
3. Double-click `run_windows.bat` (or in terminal use `py -3 -m universal_decompiler.app`).
4. Click **Open File** and select a file you own or are authorized to inspect.
5. Click **Scan**. Inspect its detected type and save a report if useful.
6. Click **Test This Version** to follow the guided two-step PE test. Export diagnostics if anything fails.
7. If a scan freezes, close/reopen the app when possible, then click **Export Diagnostics**. If the GUI will not reopen, retrieve the files from `%LOCALAPPDATA%\UniversalDecompiler`. The diagnostics do not include the analyzed binary; review logs/tester notes before sharing.

There is **no prebuilt Windows `.exe` or installer** in this milestone. Packaging using PyInstaller on an actual Windows machine is a **later atomic task**; a Linux-built executable is not a Windows executable.

## Developer quick check

From the repository root:

```powershell
py -3 -m unittest discover -s tests -v
py -3 -m universal_decompiler.app
```

Tests use synthetic PE/ELF data and do not use proprietary files. CI and Windows visual testing remain future work. Watchdog detections are best-effort: hard process crashes, power outages, native faults, and all future decompilation worker failures are not guaranteed to leave complete evidence. Never upload unlicensed/private firmware or diagnostic archives without reviewing their contents.

## Where to continue

- `AGENTS.md` — mandatory external global-rule entry point.
- `docs/PROJECT_MEMORY.md` — verified/candidate state, decisions, known limitations.
- `docs/ROADMAP.md` — next bounded steps and stage overview.
- `docs/DIAGNOSTICS_AND_TESTING.md` — real controls, coverage map, test actions.
- `docs/CODEX_HANDOFF.md` — exact recovery/next action for Codex.
