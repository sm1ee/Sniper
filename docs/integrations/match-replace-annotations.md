# Match & Replace annotations

A rule can replace traffic, add a capture note/color, or do both. For example,
choose **Response / Body**, search regex `flag\{[^}]+\}`, turn **Replace** off,
and set note `flag 탐지` and yellow. Notes are literal: no scripts, variables or
replacement-group expansion run in them.

Changing Replace keeps the rule's activity and replacement text. On stays local
when the mode differs from the saved/submitted rule or a relevant Off write is
pending. Off submits the saved rule's deactivation without newer editor changes.
Full Save waits for pending rule writes; nothing is sent automatically afterward.

Annotation-only rules do not rewrite forwarded bytes or entity headers; the
proxy's existing HTTP framing behavior still applies. They do not create an original/modified-traffic badge. Automatic notes are system notes,
not the operator's `user_note`. Colors use the existing History color filter and
marked-request count; note-only actions do not count as manual marks.

## Rule JSON

Existing `capture auto-replace list/set` and `/api/match-replace` use these optional
fields alongside the existing rule fields:

- `annotation_only_enabled`: omitted/null keeps legacy replacement mode, whose
  On switch is `enabled`. `true` or `false` selects active/inactive annotation-only
  mode; in either case `enabled` must be `false`.
- `annotation_note`: optional literal text, at most 1,024 UTF-8 bytes. All configured
  notes together may contain at most 32,768 bytes. Empty means no note; nonempty
  whitespace-only text is rejected.
- `annotation_color`: optional `red`, `orange`, `yellow`, `green`, `blue` or `purple`.

The existing 500-rule and 8MiB configuration limits remain. Empty search matches
nothing. An annotation-only rule with neither note nor color is inert. Mixed
replacement+annotation rules use legacy replacement mode; an empty replacement
still deletes matching text when Replace is on.

Every serialized annotation-only rule has `enabled:false`, so an old binary
cannot silently execute its replacement. An old typed client may discard the
new fields; that round-trip reloads as a **disabled replacement rule**, not an
active annotation rule. Old software does not understand or retain annotation
mode. Contradictory raw API input is rejected; contradictory saved state is
restored with both activation authorities off.

## Ordering and manual changes

Rules are frozen once per request/response evaluation stage. Matches are resolved
in saved order, once per rule ID per stage; the first matching annotation-bearing
occurrence wins for a repeated ID. The last resolved color wins, with response
colors following request colors. Byte replacement traversal keeps its existing
order, including repeated IDs.

A late streamed completion may update automatic color only while no manual
annotation revision exists. Manual color edits, explicit clears, and even
note-only edits protect the current color from late automation. User notes are
never overwritten. Automatic effects are persisted with the capture; editing
rules does not revisit old captures.

## Streaming coverage

Annotation-only response rules do not force full buffering. Body conditions on a
stream run only after explicit completion and only on complete, untruncated
retained text. Truncated prefixes, interrupted streams, invalid UTF-8 and
unavailable decoding cannot produce a body match. A fixed system note reports
when an applicable body condition could not be inspected; header matches still
work. Header/body colors resolve in rule order, not arrival order.

Already-buffered traffic can use its complete available text under existing
buffer/decoder limits, even beyond the display preview. Existing decoding policy
and replacement fallback are unchanged; annotation matching does not treat failed
or unsupported decoding's raw fallback as decoded text. Known-bodyless responses
are distinct from malformed empty encoded content. These rules are not a claim
of complete decoding or inspection of every response.

If an earlier replacement actually changes a Content-Encoding header name/value,
later body annotation checks in that stage are skipped with the same coverage
indication. No-op or rejected header replacements do not invalidate eligibility.
Header/path matches remain available. This conservative guard does not re-decode
or change the existing replacement engine's body representation.
