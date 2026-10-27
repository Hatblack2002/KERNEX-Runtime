# Initial hypotheses and evidence policy

**Status: proposed; no runtime implementation or performance results exist yet.**

## H1 — Portable scaffold
The same C++17 baseline can build and pass its smoke tests on x86-64 and ARM64 CI runners.

- Experiment: run the repository CI workflow on both architectures.
- Pass condition: configure, build, and tests succeed on both.
- Does not prove: ARM64 Android compatibility, DBT correctness, or performance.

## H2 — Differential instruction testing
A reference interpreter and a dynamic translator can be tested against independent x86 hardware-derived vectors for a declared instruction subset.

- Experiment: create a vector generator on x86 and compare defined architectural state fields across implementations.
- Pass condition: zero unexplained differences for the supported subset.
- Caveat: undefined or implementation-dependent results must be masked and documented, not guessed.

## H3 — Demand-driven compatibility
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