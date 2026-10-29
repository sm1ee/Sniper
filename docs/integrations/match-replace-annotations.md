# Match & Replace annotations

A rule can replace traffic, mark matching captures with a note and color, or do
both. For example, to flag CTF flags in responses: **Response / Body**, regex
`flag\{[^}]+\}`, turn **Replace** off, then under **Note and color** set the
note `flag 탐지` and yellow.

- Notes are literal text. No scripts, variables or regex groups expand in them.
- A rule that only annotates never changes the bytes sent or received, and does
  not mark the capture as modified.
- Rule notes are system notes, kept apart from your own note on a capture.
  Colors work with the History color filter and the marked-request count.
- Rules apply to new traffic. Editing a rule does not revisit old captures.

## Rule JSON

`capture auto-replace list/set` and `/api/match-replace` take three optional
fields beside the existing ones:

- `annotation_only_enabled`: omitted or `null` for a replacement rule, whose On
  switch is `enabled`. `true` or `false` makes the rule annotation-only, on or
  off, and `enabled` must then be `false`. Older Sniper versions therefore read
  it as a disabled rule rather than running its replacement.
- `annotation_note`: at most 1,024 UTF-8 bytes, 32,768 across all rules. Text
  that is only whitespace is rejected.
- `annotation_color`: `red`, `orange`, `yellow`, `green`, `blue` or `purple`.

A rule with a note or color and Replace on is a replacement rule, and an empty
replacement still deletes the matched text. An annotation-only rule with neither
a note nor a color does nothing. An empty search matches nothing.

## Order

Rules run in saved order. The last matching color wins, and response colors come
after request colors. Once you set or clear a capture's color, or edit its note,
rules no longer change its color. Your own notes are never overwritten.

## Streamed responses

Annotation-only rules do not make Sniper buffer a streamed response. Their body
conditions run when the stream completes, on the complete retained text. A body
that was truncated, cut off, not valid UTF-8 or not decodable does not match,
and a system note says it was not checked; header conditions still apply. The
same happens when an earlier replacement changed `Content-Encoding`. Buffered
responses are checked on their full text, within the usual decoding limits.
