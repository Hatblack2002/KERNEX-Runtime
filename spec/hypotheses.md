# Initial hypotheses and evidence policy

**Status: parser, import metadata reader and callback-driven IAT binder, combined PE preparation pipeline, bounded PE image mapper with PE32 HIGHLOW / PE32+ DIR64 relocation support, limited decoder, and limited interpreter exist.** CI exercises Linux x86-64, Linux ARM64, Android NDK arm64-v8a cross-compilation, and ASan/UBSan stress tests. Passing these tests does not establish Android APK packaging, on-device execution, or Windows application compatibility.

## H0 — Declared x86-32 subset
A small interpreter can execute a declared baseline of simple x86-32 instructions with bounded memory access and deterministic failure for unsupported instructions.

- Implemented subset: NOP, INT3 trap, register-immediate MOV, PUSH immediate/register, POP register (including POP ESP semantics), LEAVE, RET, relative CALL/JMP, and short conditional branches.
- Implemented integration: a synthetic PE32 image is mapped and its entry point runs through the x86-32 interpreter with a synthetic return sentinel, separate stack, and instruction budget.
- Experiment: run deterministic state-transition and mapped-entrypoint tests on x86-64 and ARM64 hosts, including ASan/UBSan.
- Pass condition: build and tests pass on both architectures; invalid instructions and out-of-range memory/control flow fail deterministically.
- Does not prove: real Windows application startup, import/API dispatch, self-modifying code coherence, exceptions, floating point, SIMD, x86-64 execution, or acceptable performance.

## H1 — Portable scaffold
The same C++17 baseline can build and pass its test suite on x86-64 and ARM64 CI runners.

- Experiment: run the repository CI workflow on both architectures, cross-compile native targets with the Android NDK for arm64-v8a, and run malformed-input tests under sanitizers.
- Pass condition: configure, build, and all registered tests succeed on both; ASan/UBSan reports no issue during the stress suite.
- Evidence: see the successful GitHub Actions run linked from the repository's Actions tab.
- Does not prove: Android APK packaging, on-device execution, DBT correctness, or performance.

## H2 — Bounded PE image mapping
A validated PE file can be mapped into an image-layout byte buffer without reading or writing outside the input file or declared image bounds.

- Implemented behavior: bounded image allocation, header copy, section raw-data copy to virtual addresses, zero-filled virtual tails, rejection of out-of-range entry points, invalid section spans, and overlapping section ranges; validated PE32 HIGHLOW and PE32+ DIR64 relocation application when rebasing. The current loaded base is tracked, same-base relocation is idempotent, and rebasing back to the preferred base is covered by regression tests.
- Experiment: synthetic PE fixture tests plus ASan/UBSan and cross-architecture CI.
- Pass condition: all valid-fixture mapping assertions pass and malformed ranges are rejected.
- Does not prove: complete relocation-type coverage, a production Windows API/module resolver, TLS initialization, section permission enforcement, or successful execution of a Windows program.

## H3 — Explicit import binding
A host-provided resolver can populate a mapped image's IAT without partial writes when a symbol cannot be resolved.

- Implemented behavior: named and ordinal imports retain IAT RVAs; the binder validates slots and PE32 address width and commits changes only if every symbol resolves. `runtime::prepare_image` composes mapping, optional rebasing, and regular-import binding into one checked pipeline.
- Experiment: synthetic import table, successful binding, resolver-failure atomicity, and combined preparation tests under x86-64, ARM64, and ASan/UBSan.
- Does not prove: Windows API semantics, module loading, forwarded exports, delay-load handling, or successful program startup.

## H4 — Differential instruction testing
A reference interpreter and a dynamic translator can be tested against independent x86 hardware-derived vectors for a declared instruction subset.

- Experiment: create a vector generator on x86 and compare defined architectural state fields across implementations.
- Pass condition: zero unexplained differences for the supported subset.
- Caveat: undefined or implementation-dependent results must be masked and documented, not guessed.

## H5 — Demand-driven compatibility
Static PE import analysis plus runtime instrumentation can identify a useful initial subset of compatibility APIs.

- Experiment: compare import analysis with instrumented API and COM-vtable traces on legally analyzable test programs.
- Pass condition: publish measured coverage and explicit blind spots.
- Caveat: the import table alone does not enumerate dynamic lookups or COM virtual calls.

## Evidence labels

- **[PROPOSED]** design not yet implemented.
- **[EXPERIMENT]** test planned or running; results not yet established.
- **[MEASURED]** backed by committed raw results, environment metadata, and reproduction steps.
- **[REJECTED]** disproved or superseded, with rationale recorded.

Never label an experiment as measured before its artifacts exist.
