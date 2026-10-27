# PE parser v0.1 contract

**Status: implemented in source; CI/device execution not yet confirmed.**

## Scope
- Validate the DOS MZ signature and read `e_lfanew` with bounds checks.
- Validate the PE signature and COFF header.
- Recognize PE32 (`0x10b`) and PE32+ (`0x20b`) optional headers.
- Extract machine, section count, characteristics, entry-point RVA, image base, alignments, image/header sizes, and section metadata.
- Validate optional-header and section-table bounds.
- Reject any non-empty section raw-data range that exceeds the input file.
- Translate RVAs to file offsets only when the complete requested range is backed by header or section bytes in the file; reject unmapped RVAs and zero-filled virtual tails.
- Extract import, TLS, and delay-import directory RVA/size pairs, validating that the declared directory count fits inside the optional header.
- Walk the bounded import descriptor table and extract DLL module names, requiring a null descriptor terminator and file-backed, terminated ASCII names.

## Explicit non-goals
This parser does not yet load or map an image, apply relocations, validate every PE semantic constraint, resolve imported symbols/thunks, inspect TLS callbacks or load-config directories, or execute the file. A syntactically parseable PE is not necessarily loadable or safe to execute.

## Error contract
Invalid or truncated input returns a structured failure and a diagnostic string. Parsing must not read outside the supplied byte vector. The CLI exits 0 on successful parsing, 1 on invalid/unsupported PE, and 2 on command-line or file-open errors.

## Test contract
Synthetic fixtures check a valid PE32 header/section, empty input, invalid PE signature, truncated input, and section raw-data bounds. Synthetic tests cover PE32 and PE32+, import/TLS/delay-import directory metadata, RVA translation, malformed directory counts, and invalid section ranges. Still needed: descriptor/thunk parsing, integer-boundary fuzzing, and differential comparisons with independent parsers.

## JSON output
The CLI emits only parsed metadata. Section names are sanitized to printable safe characters so malformed names cannot break JSON string syntax. Do not pass untrusted output to a shell or treat metadata as trusted instructions.
