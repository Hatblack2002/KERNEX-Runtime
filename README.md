# KERNEX Runtime

KERNEX is a research project exploring a native Android ARM64 runtime for selected x86/x86-64 PC software, with a focus on measurable correctness, low overhead, and demand-driven compatibility.

## Current status

**Early research scaffold.** The repository now has a bounds-checked PE32/PE32+ header and section parser, import metadata reader, a bounded PE image-layout mapper, and a limited x86-32 decoder/interpreter. GitHub Actions has verified the portable C++17 tests on Linux x86-64 and ARM64, the stress tests under AddressSanitizer and UndefinedBehaviorSanitizer, and an Android NDK arm64-v8a cross-build of the native utilities. The Android job compiles native binaries only; it does not build an APK or verify execution on a device.

The image mapper copies headers and file-backed section bytes into a zero-initialized buffer at their virtual addresses. It rejects oversized allocations, out-of-range entry points, invalid section ranges, and overlapping virtual sections. The mapper also supports bounded PE32 HIGHLOW and PE32+ DIR64 base relocations, tracks the current loaded base, and applies relocations relative to that current base so repeated rebases to the same address are idempotent. A separate preparation pipeline now maps the image, optionally rebases it, and binds regular import address table entries through a caller-provided resolver; the resolver must supply guest/runtime addresses and is not a Windows API implementation. TLS initialization, delay-import processing, per-section memory permissions, Windows API semantics, graphics translation, and real application startup remain unsupported. There is no Android APK or app-compatibility claim at this stage.

## Current milestone

- Build the portable C++17 scaffold on x86-64 and ARM64 CI runners.
- Cross-compile native utility targets for Android arm64-v8a using the Android NDK.
- Emit a machine-readable build environment report.
- Parse PE32 and PE32+ headers and section tables with bounds checks.
- Translate file-backed RVAs safely.
- Extract bounded PE import DLL names and metadata for import, TLS, and delay-import directories.
- Map PE headers and section data into a bounded, zero-filled image-layout buffer.
- Apply validated PE32 HIGHLOW and PE32+ DIR64 base relocations when the image is rebased.
- Prepare a mapped image through a single pipeline: map, optionally relocate, and transactionally bind regular import address table slots through an explicit caller-provided symbol resolver.
- Decode and interpret a deliberately limited x86-32 instruction subset, including register-immediate MOV, ModRM/SIB-based 32-bit MOV and ALU operations, absolute and base/index/displacement memory operands, accumulator ADD/SUB/CMP immediates, signed PUSH imm8, short and near conditional branches, basic arithmetic flags, NOP, INT3, PUSH/POP (including the architectural POP ESP special case), LEAVE, RET, relative CALL/JMP, and short conditional branches. Unsupported instructions fail closed; this is not a complete x86 decoder and does not provide full Windows API compatibility.
- Execute mapped PE32 entrypoints with guest virtual addresses, a bounded image-plus-stack address window, a synthetic return sentinel, and an instruction budget; falling off the code buffer is an error, not successful termination. This is a test harness, not general Windows process startup.
- Exercise malformed PE files, truncation, decoder opcode space, deterministic mutations, memory/control-flow boundaries, ALU flags, ModRM/SIB addressing, and 20,000 bounded deterministic random interpreter programs in CI.
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
