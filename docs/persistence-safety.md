# Transaction snapshot safety

HTTP history snapshots copy bodies into a private temporary file, then swap in
the new body file and its in-memory offsets together.

- A record changed since capture keeps its newer body; an annotation-only edit
  keeps its annotations and adopts the moved body.
- Cancelling a save waiter neither stops a running writer nor frees its lock.
- The optional metadata cache is durably removed before the swap, and
  annotations are written into the body file.
- Missing, unreadable or mismatched source rows abort the snapshot. A new row
  that reuses a UUID keeps the older row's unresolved body dependency, so saves
  stay blocked rather than write an empty body.
- Repeated UUIDs are kept, in order, when the journal and checkpoint are empty.
  With journal data the snapshot is rejected and the files are left untouched.
  Older versions of Sniper may have silently deduplicated such data; recover
  from those files or a known-good backup.
- Journal cleanup is confirmed apart from the save, so a successful save can
  still report unfinished disk cleanup.

This holds only for the writable session contexts that `AppState` manages; a
second writable context on the same storage directory bypasses it.
