# Contextual Fields visibility

Based on the MessagePack edit integration candidate (main e388b68 cumulative).

- Fields is hidden in markup until source hydration.
- Each Request/Response pane shows Fields for an unambiguous supported MIME.
- Otherwise Hex is the explicit manual entry point; Fields appears there without guessing body bytes.
- An open Fields pane keeps its switch visible; returning to Raw/Pretty hides it again for unsupported MIME.
- Owner changes, WebSocket/no owner, MIME duplicates and per-pane changes are handled independently.
- Native buttons retain keyboard/touch accessibility; no context-menu-only control.

Validation: selected manifest 949/949, JavaScript syntax passed. Browser/native verification remains separate. No remote changes.

Actual CodeMirror input/undo/redo test covers MIME visibility with no response or notice. Input sync now explicitly refreshes Fields; the new test failed before the fix and passes after it.
