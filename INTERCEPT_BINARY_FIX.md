# Intercept binary body preservation

Response Intercept now keeps Base64 as Base64 in the raw editor and decodes it only for length validation. This avoids CodeMirror newline normalization corrupting arbitrary byte payloads. Legacy UTF8 responses with an explicit known binary MIME are UTF8-encoded into Base64 before editing; the parser uses the original MIME/encoding even if the user changes headers. Response edited status compares in the editor newline domain, avoiding a false edit for untouched CRLF headers.

Request Intercept uses the shared binary MIME classification before its UTF8 heuristic. Its frontend also opts into safe Base64 rendering/parsing for legacy UTF8 held requests; other callers retain their existing build/parse contract. The held original MIME determines the encoding even after a header edit. Untouched migrated previews retain their truncated flag. Added native round-trip test covers protobuf, msgpack, CBOR and grpc+json UTF8-shaped bodies.

The new test file uses the shipped CodeMirror EditorState/history for binary response round trips, header/body changes and undo/redo, malformed Base64 rejection, legacy conversion, and the production response-forward function with mocked transport. The explicit manifest additionally includes relevant Intercept lifecycle and raw separator regression suites.

No actual traffic was forwarded. Rust tests/build/rustfmt and native runtime are not run: no Rust toolchain is installed. Browser screenshot validation remains separate. Unknown or mislabeled binary MIME remains subject to existing text behavior. Existing drafts created by an older app may not match the new representation; do not treat in-memory old-editor text as a new Base64 draft.
