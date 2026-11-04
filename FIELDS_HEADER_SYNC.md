# Header-sensitive Fields cache
Headers are now part of the rendered source key (ordered name/value pairs, lowercased names).
Changing MIME, encoding, or duplicate headers invalidates interpretation/eligibility even when owner, body and revision remain identical. Equal header content retains the DOM.
DOM lifecycle tests cover native proto → JSON → proto, manual gRPC → web rejection, encoding-only edit eligibility changes, and duplicate MIME.
1003 selected tests passed. Browser/native/runtime unverified by this change.
