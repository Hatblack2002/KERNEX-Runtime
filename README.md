# KERNEX Runtime

KERNEX is a research project exploring a native Android ARM64 runtime for selected x86/x86-64 PC software, with a focus on measurable correctness, low overhead, and demand-driven compatibility.

## Current status

**Early research scaffold.** The repository now has a bounds-checked PE32/PE32+ header and section parser, import metadata reader, a bounded PE image-layout mapper, and a limited x86-32 decoder/interpreter. GitHub Actions has verified the portable C++17 tests on Linux x86-64 and ARM64, and the stress tests under AddressSanitizer and UndefinedBehaviorSanitizer.

The image mapper copies headers and file-backed section bytes into a zero-initialized buffer at their virtual addresses. It rejects oversized allocations, out-of-range entry points, invalid section ranges, and overlapping virtual sections. It is only a mapping primitive: it does **not** apply base relocations, resolve imports, initialize TLS, enforce per-section memory permissions, emulate Windows APIs, translate graphics, or execute a PE application end-to-end. There is no Android APK or app-compatibility claim at this stage.

## Current milestone

- Build the portable C++17 scaffold on x86-64 and ARM64 CI runners.
- Emit a machine-readable build environment report.
- Parse PE32 and PE32+ headers and section tables with bounds checks.
- Translate file-backed RVAs safely.
- Extract bounded PE import DLL names and metadata for import, TLS, and delay-import directories.
- Map PE headers and section data into a bounded, zero-filled image-layout buffer.
- Decode and interpret a deliberately limited x86-32 instruction subset, including register-immediate MOV, NOP, INT3, PUSH/POP, LEAVE, RET, relative CALL/JMP, and short conditional branches.
- Exercise malformed PE files, truncation, decoder opcode space, deterministic mutations, and memory/control-flow boundaries in CI.
- Keep hypotheses and experimental results explicitly separate.

## Build locally

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/kernex_envprobe
./build/kernex_peinfo path/to/program.exe
```

## Project principles

1. Correctness before optimization.
2. No claim of support without reproducible tests.
3. Runtime compatibility is implemented incrementally from observed program requirements.
4. No game binaries, secrets, device serials, or personal paths in committed test artifacts.
5. Researching existing implementations is allowed; code reuse must respect each project's license.
6. A parser or mapper test suite is evidence of tested cases, not proof of absolute safety or application compatibility.

See [spec/hypotheses.md](spec/hypotheses.md) for falsifiable hypotheses and evidence policy.
