# gRPC envelope inspection candidate

Base: the CBOR editing candidate rooted at main e388b68.
This adds a read-only body envelope view, NOT gRPC transport support.

- Explicit application/grpc, application/grpc+proto, application/grpc+json MIME exposes Fields.
- Other/ambiguous MIME requires manual Hex → Fields selection. gRPC-Web is not classified as native gRPC, and explicit manual gRPC selection also refuses it.
- Message number selects one envelope payload. Counts and body bytes are bounded.
- Only uncompressed native proto payloads are passed to the schema-less Protobuf reader.
- JSON, untyped manual payloads, and compressed messages remain opaque byte previews.
- Offsets are body-relative. Source bytes are never modified. No gRPC editing.
- Truncated captures are refused before parsing; malformed envelopes give errors.
- The view does not validate grpc-encoding, RPC success, trailers, or stream transport.
- Existing proxy buffering/trailer limitations remain unchanged.
- Focused and selected manifest tests: 1001 passed.
- Rust/native runtime, browser QA and real transport are not verified by this implementation task.
