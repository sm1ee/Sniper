# Binary Raw preservation candidate

Parent: sniper-fields-header-sync (e388b68 cumulative candidate).

Known binary MIME types now use Base64 in native editable records and capture previews, even when bytes are valid UTF-8. This avoids text-editor newline normalization.

Legacy UTF-8 Replay drafts with a binary MIME in their current or original headers are migrated to Base64 before entering CodeMirror. Request bytes are unchanged; baseRequest encoding/body and the displayed draft move together, cached byte views are invalidated and workspace persistence is scheduled. This is a presentation migration, not Base64 added to the network payload. The existing Base64 sender/parser decodes it back to original bytes. The migration resets that editor's old undo history to prevent undo restoring UTF-8 text under Base64 encoding. Subsequent editing, undo/redo, tab changes and serialization preserve Base64 state.

For all other UTF-8 drafts, header-only changes preserve original body newlines when the body differs only by editor normalization. Actual text-body edits remain normal text edits. Binary data with missing/misleading MIME cannot be identified reliably and is not automatically migrated. Already corrupted historical bytes cannot be recovered.

Tests: real CodeMirror fixture checks five MIME variants, header/path edits, exact decoded bytes, body edit/undo/redo, MIME change, tab switching, serialized workspace restoration, and ordinary text. Rust tests added for MIME classification and capture roundtrip.

Cargo/rustc are unavailable: Rust build/tests, rustfmt and native/runtime traffic tests remain unexecuted. No Content-Encoding logic or remote repository changed.
