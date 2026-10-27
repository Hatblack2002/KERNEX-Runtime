# Initial hypotheses and evidence policy

**Status: parser, import metadata reader, bounded PE image mapper, limited decoder, and limited interpreter exist.** CI currently exercises Linux x86-64, Linux ARM64, and ASan/UBSan stress tests. Passing these tests does not establish Android NDK integration or Windows application compatibility.

## H0 — Declared x86-32 subset
A small interpreter can execute a declared baseline of simple x86-32 instructions with bounded memory access and deterministic failure for unsupported instructions.

- Implemented subset: NOP, INT3 trap, register-immediate MOV, PUSH immediate/register, POP register, LEAVE, RET, relative CALL/JMP, and short conditional branches.
- Experiment: run deterministic state-transition tests on x86-64 and ARM64 hosts.
- Pass condition: build and tests pass on both architectures; invalid instructions and out-of-range memory/control flow fail deterministically.
- Does not prove: broad x86 compatibility, Windows API support, self-modifying code, exceptions, floating point, SIMD, or acceptable performance.

## H1 — Portable scaffold
The same C++17 baseline can build and pass its test suite on x86-64 and ARM64 CI runners.

- Experiment: run the repository CI workflow on both architectures and run malformed-input tests under sanitizers.
- Pass condition: configure, build, and all registered tests succeed on both; ASan/UBSan reports no issue during the stress suite.
- Evidence: see the successful GitHub Actions run linked from the repository's Actions tab.
- Does not prove: Android NDK compatibility, DBT correctness, or performance.

## H2 — Bounded PE image mapping
A validated PE file can be mapped into an image-layout byte buffer without reading or writing outside the input file or declared image bounds.

- Implemented behavior: bounded image allocation, header copy, section raw-data copy to virtual addresses, zero-filled virtual tails, rejection of out-of-range entry points, invalid section spans, and overlapping section ranges.
- Experiment: synthetic PE fixture tests plus ASan/UBSan and cross-architecture CI.
- Pass condition: all valid-fixture mapping assertions pass and malformed ranges are rejected.
- Does not prove: relocations, import binding, TLS initialization, section permission enforcement, or successful execution of a Windows program.

## H3 — Differential instruction testing
A reference interpreter and a dynamic translator can be tested against independent x86 hardware-derived vectors for a declared instruction subset.

- Experiment: create a vector generator on x86 and compare defined architectural state fields across implementations.
- Pass condition: zero unexplained differences for the supported subset.
- Caveat: undefined or implementation-dependent results must be masked and documented, not guessed.

## H4 — Demand-driven compatibility
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
