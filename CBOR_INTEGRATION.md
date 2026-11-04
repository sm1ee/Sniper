# CBOR read-only Fields
Based on the contextual Fields candidate, itself based on main e388b68.
Only application/cbor automatically shows and selects CBOR; unknown MIME remains explicit through Hex → Fields.
CBOR is read-only, including requests. Tags are opaque; canonical encoding and map duplicate semantic validity are not checked.
Ordered map entries, full occurrence paths, indefinite chunks, scalar types, offsets and original bytes are preserved. 1 MiB, 10,000 nodes and depth 64 limits; 200 rows per page and bounded value previews.
968 selected Node tests pass. Rust/native asset delivery and actual frontend browser have not been executed for this candidate. No remote changes or real traffic.
