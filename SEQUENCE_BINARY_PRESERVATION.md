# Sequence binary draft preservation

Legacy UTF8 requests with a known binary MIME are migrated to Base64 before entering the textarea. Original body bytes, header variables, step identity and extraction configuration remain intact. Save/Run synchronization then uses the Base64 body encoding. Reload and step reordering do not reinterpret the converted body.

Body templates (`{{`) or fuzz markers (`§`) in legacy binary text are not silently encoded: the original draft is retained, editing is read-only and Run validation refuses it. Reopen the source request to rebuild the intended body safely. Invalid raw drafts are similarly preserved and blocked. Header variables remain supported.

Migration starts a new textarea document and does not preserve old browser-local undo history. MIME-misidentified inputs or already-corrupted data cannot be repaired by this change. Rust/native build, browser execution, actual transport and backend variable interpolation are not verified by these Node fixtures. The fixture explicitly simulates textarea newline normalization.

Invalid Base64 edits, including `{{body}}` or `§payload§`, show “Enter a valid Base64 body.” instead of a browser decoder exception. Executable Sequence fixtures verify blocked dispatch, retained last valid bytes, and successful Save/Run after correction. This is validation, not binary-body variable interpolation support.
