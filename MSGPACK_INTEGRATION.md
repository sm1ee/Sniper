# MessagePack Fields candidate

Based on local Protobuf edit-restore candidate, itself based on main e388b68. No remote writes, dependencies or native build.

Fields uses a unique exact Content-Type application/(x-)msgpack or application/(x-)protobuf as initial format; all other types require explicit selection without parsing. Explicit Body format select switches to MessagePack, including when parsing fails. Selection does not rewrite the editor, request encoding or bytes. MessagePack is always read-only. Returning to Protobuf preserves existing guarded editing semantics.

Map entries display ordered `[n].key` and `[n].value` rows instead of coercing keys into object properties. Indentation conveys parent context. Exact integer strings; invalid UTF-8 explicitly marked; extensions shown as opaque type IDs and bytes. Strings preview max160 UTF-16 code units, bytes max24; 200 rows/page, decoder 1MiB/10k nodes/depth64. Entire payload is not rendered into HTML; all values use textContent. Display is not semantic schema validation.

932/932 explicit manifest tests passed (previous910 plus22 MessagePack tests), syntax checks pass. Server route/include source assertions included. Browser screenshots, native compilation and actual backend asset serving have NOT been verified. No traffic sent.

Nested rows retain full occurrence ancestry. Visible path capped at200 characters; complete path available in title and aria-label.

Manual selection persists for the current owner and resets on owner change. MIME selection is not payload sniffing. Duplicate or unknown Content-Type is ambiguous.
