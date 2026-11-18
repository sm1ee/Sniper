# Binary request bodies edited as Burp does

**Goal:** a request body that is not text (a multipart upload with a file, protobuf) is shown and edited one character per byte, as Burp's Raw view does, and every byte the user did not touch is sent unchanged.

**Why:** today such a body is Base64 in Replay and Intercept, so changing `filename="a.png"` to `shell.php` means decoding and re-encoding by hand. Editing a text multipart body also loses its CRLF line endings, because CodeMirror keeps only "\n".

## Decisions

- Storage stays as it is: `tab.requestText`, workspace files, the CLI and the API still carry a binary body as Base64. Only the editor shows it as bytes, and converts back on every edit. Old saved tabs and CLI-made tabs need no migration.
- A character up to U+00FF is that byte. A character above it can only have been typed, and is sent as UTF-8.
- CodeMirror forgets whether a line break was CRLF, CR or LF. An editor that edits a raw request remembers each original break as a mark over its newline, maps the marks through edits, and writes them back. A break the user types takes the ending of the next break, or of the one before it after the last break. Undo and Redo put back the marks of the text they return to (CodeMirror's `invertedEffects`, added to the bundle's exports).
- Fuzzer positions inside a binary body came after this plan: [2026-11-18-fuzzer-binary-positions.md](2026-11-18-fuzzer-binary-positions.md).

## Tasks

1. Exact line endings for raw-request editors (`web/app.js` CodeMirror wrapper): `createLineEndingTracker()` (a field of marks over each break), `SniperCodeView.getText()` for the exact text while `getContent()` stays the normalized document, and the change listener and Replay edit filter reading exact text. Test: `tests/editor-line-endings.test.cjs`, which runs the field on `CM.EditorState` in Node.
2. Replay shows a binary body as bytes: `binaryBodyText`, `binaryBodyBase64`, and the conversion at the Replay editor boundary (display, edit sync, edit filter, send). Test: `tests/binary-body-editing.test.cjs`.
3. Intercept request and response editors do the same through a `{ bytes }` option on the raw build and parse functions; the `edited` flag compares like with like. The native textarea fallback keeps Base64, because a textarea turns CR into LF.
4. cURL `-F` import builds a multipart body: text fields, and file parts with the file name and no contents, with a note.
5. Docs: README Replay row and the HTTP debugging guide.

Final: full Rust and node suites, `cargo fmt --check`, dynamic tests through the proxy into a loopback upstream that saves each request's raw bytes (Replay and Intercept edits of a binary multipart upload, a text multipart edit keeping CRLF, a cURL `-F` import), deploy to `~/Desktop/Sniper.app`.
