# Fields layout simplification

Based on sniper-cbor-integration. This delta only changes UI labels and focused tests.
- Format appears once in the selector; No schema / Read only remain visible.
- Unknown format starts with the selector without repeated explanatory paragraphs.
- Apply label shortened; safe numeric ranges, byte limits and UTF-8 requirement remain visible when editing.
- No parser, mutation, stale-source or framing logic changed.
- 969 selected tests and JS syntax passed. Browser screenshot verification and Rust/native tests not performed by this change.
