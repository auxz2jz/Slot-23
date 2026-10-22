# Roadmap — atomic, evidence-based milestones

Only the **first milestone** below is authorized in this turn. All further implementation awaits a new user request. Each task is designed to be independently verifiable; split further if its actual scope grows.

## Stage 1: Binary identification

| ID | Objective / dependencies | Completion criteria / verification | Status | Recommended reasoning |
|---|---|---|---|---|
| UD-S1-001 | Establish Windows-friendly application and read-only Stage 1 scanner; global rules and handoff, diagnostics, guided tests. No external binary needed. | Source files and docs committed; synthetic PE/ELF/unknown fixture tests pass locally; Windows GUI manual test remains pending. | CANDIDATE (not user-verified) | Medium; High only for unexplained binary parser defects |
| UD-S1-002 | Verify UI on a real Windows computer; dependencies: v0.1.0, user's test/diagnostics. | Launch, PE scan, report save, guided test, diagnostics verified on Windows; record physical baseline. | NOT AUTHORIZED YET | Low/Medium; escalate if reproducible failures |
| UD-S1-003 | Package a Windows `.exe` using reproducible Windows build steps; depends on Windows tests. | EXE builds on Windows, starts, and passes user-guided tests. | NOT AUTHORIZED YET | Medium |
| UD-S1-004 | Add validated PE/ELF import/export metadata and more format fixtures, bounded safeguards. | New targeted parser tests and Windows manual verification. | NOT AUTHORIZED YET | Medium |
| UD-S1-005 | Add modular firmware signature plugins and limited extraction to a sandbox. | Safe fixture extraction and explicit limits verified. | NOT AUTHORIZED YET | High |

## Longer-term (not implemented or authorized yet)

- Stage 2: Architecture-specific disassembly (e.g., Ghidra/Capstone integration, not reinventing instruction decoding blindly).
- Stage 3: Shared intermediate representation and control/data-flow analysis.
- Stage 4: Function reconstruction and C-like decompilation.
- Stage 5: Source/export workflows and human verification.

The product should accept Windows EXEs and embedded firmware eventually, but genuine decompilation cannot recover the exact original source or guarantee recompilation.
