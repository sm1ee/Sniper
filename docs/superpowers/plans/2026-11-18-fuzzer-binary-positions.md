# Fuzzer positions in binary bodies

**Goal:** mark positions inside a body that is not text (a multipart upload with a file, protobuf) in the Fuzzer, from the editor and from `sniper-cli`, and send every byte outside the filled position unchanged.

**Why:** the Fuzzer shows such a body as Base64 and refuses positions in it. Burp marks positions with `§` in the bytes, so a 0xA7 byte in an uploaded file pairs up with another into a position nobody chose, and Intruder strips those bytes, which breaks the file (PortSwigger forum threads on images and mp4 uploads).

## Decisions

- Stored form, wherever a template lives (workspace `request_text`, the attack API, saved runs): a Base64 body keeps its positions between Base64 pieces, `<piece>§<original>§<piece>` or `$payload$`, each piece and each original Base64 by itself. `§` and `$` are not Base64, so no byte of the body can be read as a mark. A body without positions is plain Base64 as today: no migration.
- A payload goes into a binary body as its UTF-8 bytes, as it does in every other position. Base64 text spliced into the Base64 body (the old API behaviour, which the editor and the CLI could not reach) is gone.
- The editor shows the body one character per byte, as Replay does, and converts back on every edit. Byte A7 shows as a stand-in character drawn as a muted `§`, so it never pairs with a typed `§`. A typed pair of `§` is a position; a lone `§` is byte A7.
- A template whose body is not Base64 around its positions is refused before anything is sent.
- The size estimate counts a payload in a Base64 body twice: Base64 sends 4 bytes for every 3.
- CLI: `fuzzer run` reads these templates and sets Content-Length before the parser checks it, as the editor does (the server works it out again after each payload). `fuzzer set-template --body-position START:END`, repeatable, marks byte ranges of the body, so an agent marks a binary body without writing `§` bytes into it.

## Tasks

1. Server, `src/fuzzer.rs`: split a Base64 body into pieces and positions, fill them in `build_request`, refuse an undecodable body in `plan_attack`, the size estimate, and `base64_body_originals` for the CLI.
2. `web/fuzzer-workflow.js`: show and store a binary body, expand it for Preview, the size estimate, drop the "use header or query positions" warning.
3. `web/app.js`: the Fuzzer editor shows the bytes; edits and the marker actions (Add §, remove, Clear, Undo) work on the shown text and store it back; the stand-in decoration; Preview samples show bytes.
4. `src/bin/sniper-cli.rs`: the run parse and `--body-position`, with its call input and preview.
5. Docs: the Fuzzer guide and the operator skill.

Final: full Rust and node suites, `cargo fmt --check`, a run through the proxy into a loopback upstream that saves each request's raw bytes (a position in the file part of a binary multipart upload from the editor, and one set with `--body-position` from the CLI), deploy to `~/Desktop/Sniper.app`.
