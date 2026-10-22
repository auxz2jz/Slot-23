# Project memory — canonical current state

- Project: Universal Decompiler (Windows-oriented desktop application), repo `auxz2jz/Slot-23`.
- Global instructions: `auxz2jz/master-instruction-library`; start at `INSTRUCTION_INDEX.md`.
- Date started: 2026-10-21 (America/Los_Angeles).
- Phase: Stage 1 — binary identification.
- Version: v0.1.0 (first development candidate; **NOT user-verified**).
- Last user-verified baseline: **None yet**. Do not mark a baseline VERIFIED until the user physically tests it.
- Latest candidate: v0.1.0 source in GitHub repository.
- Scope authorized: first-stage binary identification, Windows application setup, diagnostics/testing/recovery scaffold; NOT actual decompilation yet.
- Implementation: Python 3.11+ and Tkinter built-in, offline, read-only. No external runtime packages for source launch.
- Scanner: PE COFF architecture/section/entry-point identification, ELF header identification, common container and embedded filesystem magic candidates, SHA-256 and hex preview.
- Diagnostic design: bounded local JSONL events, per-operation IDs, user action versus actual result, explicit ZIP export; two-step resumable guided test.
- Security: never run user binaries; no firmware writing/flashing; no automatic file uploads; do not log full input paths or file contents.
- Known limitations: no PE imports/exports parsing; incomplete firmware format coverage; raw architecture generally unknown; signature search only first 4 MiB; no extraction/decryption/disassembly/decompilation; GUI/Windows packaging not physically tested here; no Windows EXE included.
- Known bugs/failures: None established by user; see tests/handoff for developer verification and limitations.
- Earlier project files/results: conversation-approved UI mock only; no user-supplied binary samples for this project.
- Current task: `UD-S1-001` first-stage candidate, status **CANDIDATE pending Windows user test**.
- Exact next action: user tests v0.1.0 on Windows using `run_windows.bat` and **Test This Version**; collect failed step/diagnostics if any. Then `UD-S1-002` after authorization.
- Git checkpoint: refer to actual latest commit in Slot-23; do not guess or hardcode SHA before push.
