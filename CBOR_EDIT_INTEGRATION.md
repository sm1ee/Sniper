# CBOR scalar editing candidate

Based on sniper-fields-minimal; no remote changes. Request editing requires Raw, complete Base64 body, exact unique application/cbor and no non-identity Content-Encoding. Response remains read-only.

Supported: unsigned/negative integers within original width and sign major type, booleans, definite text/byte strings as hex (UTF-8 required for text). 64KiB replacement cap. Map keys and their descendants, tag children, indefinite strings/chunks, floats, simple/null and containers are not exposed for editing. Untouched bytes/duplicate key occurrences and surrounding indefinite containers stay intact.

Shared owner/revision/full draft/body checks and existing framing/CodeMirror undo apply paths remain in use. Input limits, lazy hex and per-pane paging remain unchanged. Types and exact bounds shown only when editing.

Validation: explicit PROTOBUF_TEST_MANIFEST.txt 982/982 passed, JS syntax passed. Includes actual Replay setter/CodeMirror fixture for Content-Length auto-on/off, undo/redo and stale apply. Browser UI, native Rust build and actual transmission are not yet validated. Cargo is unavailable in this environment.
