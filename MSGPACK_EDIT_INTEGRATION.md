# MessagePack restricted scalar editing

Based on sniper-msgpack-mime. Request editing requires Raw mode, complete Base64 body, one matching explicit MessagePack Content-Type, and no compression. Response remains read-only.

Integer decimal, bool true/false, and string/binary raw hex edits are supported. Original marker width is retained; overflow is rejected. Map keys, containers, floats, nil and extensions are not editable. Occurrence paths preserve duplicate/non-string keys; nested map key branches are excluded. Strings must remain valid UTF-8. Selected bytes are converted to hex only on demand, up to 64KiB. Input/output limits remain 1MiB.

Apply rechecks owner, revision, full draft, format and source bytes, then uses the existing Replay framing and CodeMirror edit path. Cancel/Escape and successful Apply restore relevant position/focus through the existing UI logic.

Validation: 946 explicit manifest tests passed. Includes engine tests and DOM interaction tests, wrong width refusal, duplicate value selection, stale revision, asset registrations and actual Replay setter/undo/redo with MessagePack. Rust/native and browser tests are not performed here. No remote changes or installation.
