# Read-only Fields integration

Base: sm1ee/Sniper e388b68f5c9b0b1efeeda4016ee98087277d663a (main, 0.3.4), fetched via official codeload archive. This independent directory is not a Git worktree; nothing pushed.

Request and Response have an explicit Fields button, with the existing editor mounted underneath an inspection overlay. The persistent Replay view mode and editable draft are not changed. Returning through Pretty/Raw/Hex restores the existing view workflow. Switching Replay draft owner closes the inspector, preventing old record data from carrying over. All displayed values use textContent. The request source is parsed from its current draft and never falls back to older base request data on parse errors. Response reads captured body bytes. No network, sending, schema import, editing or reserialization is performed by the inspector.

Wire success does not confirm format/schema. Unsigned is explicitly an interpretation, LEN remains hex bytes; no string/message guesses. Truncated preview rejected. 1MiB/10,000-field/depth64 decoder bounds and 200 rendered rows per page. Fixed values show original bytes and offsets. Empty wire message is allowed.

Tests: `node --test tests/protobuf-wire.test.cjs tests/protobuf-fields.test.cjs` = 36/36. `xargs node --test < PROTOBUF_TEST_MANIFEST.txt` = 882/882. `node --check web/app.js`, `web/protobuf-fields.js`, `web/protobuf-wire.js` pass. Manifest lists exact Replay/Protobuf tests, not entire suite. No Rust build, native runtime, network traffic or browser layout QA performed. Browser screenshot/flow validation is required before describing this as delivered app behavior.

Patch: /workspace/shared/sniper-protobuf-fields.patch. Existing Raw/Hex conversion semantics are unchanged, not repaired by this feature. Actual Protobuf edit/descriptor/gRPC support remains future work.

Review correction: explicit src/api.rs GET routes and JavaScript asset_response handlers added for both scripts, with source-level regression checks. Cargo is unavailable on this executor, so native serving is not runtime verified.

Review correction: removed two unrelated global CSS-token replacements. The CSS change is only the appended Fields block. Unchanged source/owner preserves inspector DOM, page and scroll across sync or opposite-pane view changes; changed source refreshes to the first page. Regression covers unchanged sync, reopening, changed body and changed owner.
