# PE parser v0.1 contract

**Status: implemented in source; CI/device execution not yet confirmed.**

## Scope
- Validate the DOS MZ signature and read `e_lfanew` with bounds checks.
- Validate the PE signature and COFF header.
- Recognize PE32 (`0x10b`) and PE32+ (`0x20b`) optional headers.
- Extract machine, section count, characteristics, entry-point RVA, image base, alignments, image/header sizes, and section metadata.
- Validate optional-header and section-table bounds.
- Reject any non-empty section raw-data range that exceeds the input file.

## Explicit non-goals
This parser does not yet load or map an image, apply relocations, validate every PE semantic constraint, inspect imports/delay imports/TLS/load-config directories, or execute the file. A syntactically parseable PE is not necessarily loadable or safe to execute.

## Error contract
Invalid or truncated input returns a structured failure and a diagnostic string. Parsing must not read outside the supplied byte vector. The CLI exits 0 on successful parsing, 1 on invalid/unsupported PE, and 2 on command-line or file-open errors.

## Test contract
Synthetic fixtures check a valid PE32 header/section, empty input, invalid PE signature, truncated input, and section raw-data bounds. Future tests must add PE32+, ordinal/import directories, integer-boundary cases, fuzzing, and differential comparisons with independent parsers.

## JSON output
The CLI emits only parsed metadata. Section names are sanitized to printable safe characters so malformed names cannot break JSON string syntax. Do not pass untrusted output to a shell or treat metadata as trusted instructions.
