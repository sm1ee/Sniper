# Fuzzer binary preservation

Based on the cumulative Intercept candidate (main e388b68). Legacy UTF-8 drafts with an existing base request and explicit binary MIME in current/original headers are converted before entering CodeMirror. The body bytes are UTF-8 encoded and represented as Base64; request framing/header text is left intact. The base request encoding is updated and workspace save scheduled.

Request editor history is reset at this conversion boundary. Header/query marker text is retained; a legacy binary body already containing section-sign payload delimiters is left unchanged, made read-only and rejected by the template parser rather than silently encoding away its markers. Reopen the original request to proceed. Actual Base64 body-marker handling retains the existing Fuzzer validation.

Tests use the shipped CodeMirror and production rendering/input functions, covering path/body edits, undo/redo, persisted state, source replacement and ownership. Rust/native execution and actual network sends are not verified. Mislabelled data without a recognizable current/original binary MIME is outside this migration.
