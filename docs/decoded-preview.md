# Decoded value preview

Hover over an encoded token in an HTTP text editor for 300 ms to see a
read-only decoded preview, with each decoding layer labeled. Move the pointer
into the tooltip to select text; Escape, moving away, scrolling or editing
closes it.

From the keyboard, put the cursor in a token (or select the exact value), Tab to
the editor's **Decode** button and press Enter or Space. While the button has
focus, the arrow, Page Up/Down and Home/End keys scroll a long preview.

## What it decodes

- URL percent encoding, including UTF-8. `+` stays `+`, because form encoding
  depends on the field.
- Canonical Base64 and Base64URL of at least eight characters, padded or not.
  JWT header and payload segments decode one at a time; signatures are not
  checked.
- Up to three nested layers, such as URL-encoded Base64.

Malformed input, invalid UTF-8, control characters, whitespace-only output and
binary data get no preview. Short Base64, hex, HTML entities, JavaScript
escapes, compressed data and wrapped Base64 are not attempted. Input is limited
to 4,096 UTF-16 code units and each result to 2,048; longer values are rejected,
not cut.

## Where it works

- HTTP History request and response, including Raw, Pretty and Modified
- HTTP Replay and HTTP Intercept request and response
- Findings request and response detail
- Fuzzer request and result detail
- WebSocket History handshake text

Hex, diff and rendered views, WebSocket frames, the WebSocket Replay header
field, plain-text fallbacks, Map/Recon views and Decoder inputs have no preview.

Decoded text is inserted as `textContent`, never HTML. The preview does not
change the source or captured bytes, send requests, save or log values, or run
decoded code.

`node --test tests/encoded-preview-*.test.cjs` runs the decoding and event
tests; they do not cover WebKit/WebView2 layout or screen readers.
