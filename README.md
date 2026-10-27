# KERNEX Runtime

KERNEX is a research project exploring a native Android ARM64 runtime for selected x86/x86-64 PC software, with a focus on measurable correctness, low overhead, and demand-driven compatibility.

## Current status

**Early research scaffold.** A bounds-checked PE header/section parser and the `peinfo` inspection utility have been added, with synthetic parser tests. CI execution has not yet been confirmed. No PE loader, x86 interpreter, dynamic binary translator, Windows API compatibility layer, or graphics translator is implemented.

## Current milestone

- Build the portable C++17 scaffold on x86-64 and ARM64 CI runners.
- Emit a machine-readable build environment report.
- Parse PE32 and PE32+ headers and section tables with bounds checks.
- Reject truncated files and section data that extends beyond the input.
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
6. A parser test suite is evidence of tested cases, not proof of absolute safety.

See [spec/hypotheses.md](spec/hypotheses.md) for the initial falsifiable hypotheses.