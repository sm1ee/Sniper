# Minimal explicit wire editing

Based on the reviewed density frontend. Only Replay Request, a complete Base64 body,
a single application/protobuf or application/x-protobuf Content-Type, no content
compression, and Raw selected before opening Fields enable edit buttons. Response
is always read-only. The user explicitly chooses Edit on one occurrence; no schema
interpretation is inferred. Supported operations are unsigned varint decimal and
raw hex bytes for LEN/fixed32/fixed64. Groups have no Edit button.

The UI captures owner, input revision and entire draft; it checks them again along
with exact body bytes. The provider repeats owner/revision/draft/Raw checks. Editing
uses existing parseEditableRawRequest framing validation and auto Content-Length
policy before modifying state. Base64 encoding remains Base64, so undo does not
silently change encoding. Existing CodeMirror transaction setter preserves undo.
Body size changes with auto Content-Length disabled can fail validation; Cancel and
reopen to retry. UTF8-to-Base64 conversion is deliberately not implemented because
undo and captured encoding ownership need a separate design.

No gRPC envelope/compression, schema import, signed types, strings or inferred LEN
message descent UI. Core engine supports nested explicit paths; this UI displays
only top-level and group-contained fields. Response mutation and real network
sending were not tested or performed.

Validation: 57 focused tests and 906 selected tests passed; JS syntax passed.
Rust build/native app/actual HTTP asset delivery remain unverified. Browser QA is coordinated separately. CodeMirror undo/redo, auto-length on/off and stale edit/revert are exercised with the real bundled CodeMirror state/history fixture.

Raw hex editing is limited to 64 KiB per selected field, and hex text is generated
lazily only when Edit is clicked. Group rows never materialize entire hex strings.
