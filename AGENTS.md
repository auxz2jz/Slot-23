# Project Instructions: Universal Decompiler

**Read and follow the canonical Master Instruction Library, do not invent a second global instruction system.**

Canonical source: https://github.com/auxz2jz/master-instruction-library

Required startup order:
1. Read `INSTRUCTION_INDEX.md` in the master repository.
2. Read `CORE_DEVELOPMENT_RECOVERY_RULES.md`, `DIAGNOSTICS_STANDARD.md`, and `GUIDED_TESTING_STANDARD.md` there.
3. Because Codex/repository coding agents are expected, also read `CODEX_USAGE_EFFICIENCY_STANDARD.md` there.
4. Read `CROSS_PLATFORM_COLLABORATION_STANDARD.md` if Android or multi-platform workers are introduced.
5. Read local `docs/PROJECT_MEMORY.md`, `docs/ROADMAP.md`, `docs/DIAGNOSTICS_AND_TESTING.md`, and `docs/CODEX_HANDOFF.md`.
6. Inspect relevant source/tests, verify Git status and last **user-physically-verified** baseline before edits.
7. Work on **one bounded task ID at a time**, use targeted verification, checkpoint/handoff, and never claim unverified code is VERIFIED.

User-authorized scope **for this milestone only**: Stage 1 local binary identification desktop candidate. Do not advance automatically into disassembly, decompilation, patching, execution, or firmware flashing. Preserve original files read-only. Never run unknown user-supplied executables. No network upload of binaries. Preserve diagnostics privacy and guided tests.

If external rules cannot be retrieved: record the blocker; do not silently replace or paraphrase the canonical rules. On conflicts apply order in the master index and document material conflicts in project memory.
