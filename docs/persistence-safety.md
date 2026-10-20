# Transaction snapshot safety

HTTP history snapshots copy bodies into a private temporary file before publishing
it. Publication replaces the body file and its in-memory offsets together. A
record changed since capture keeps its newer resident body; annotation-only edits
keep their current annotations while adopting the relocated body. A canceled save
waiter does not cancel an already-dispatched writer or release its serialization
permit early.

The metadata cache is optional. Its previous version is durably removed before
body replacement, and annotations are written into the body file itself. Missing,
unreadable, or mismatched source rows abort preparation rather than substituting
body-less metadata. Inserting another row with the same UUID also preserves any
unresolved older-body dependency; saves remain blocked rather than overwriting it
with an empty body. Journal cleanup is confirmed separately from ordinary save
success, so a cleanup warning does not imply that all disk cleanup completed.

Repeated transaction UUIDs are preserved without reordering or deduplicating rows
when the snapshot's journal and checkpoint are empty. Each repeated row is read
from its own body offset; unique IDs remain lazy. A repeated-ID snapshot combined
with nonempty journal data is ambiguous and is rejected with its original files
preserved. Such rare malformed saved data may previously have been silently
deduplicated. Recovery should review the original files or a known-good backup;
this check does not automatically rewrite identities or discard journal data.

These guarantees apply to the canonical writable session contexts coordinated by
`AppState`. Independently creating multiple writable contexts for the same storage
directory bypasses that lifecycle contract.
