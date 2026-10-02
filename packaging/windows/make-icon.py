#!/usr/bin/env python3
"""Builds packaging/windows/sniper.ico from the macOS icon set.

Each size is stored as a PNG inside the ICO (supported since Windows Vista), so
the 256px image stays sharp in Explorer's large-icon view. Run from the repository
root: python3 packaging/windows/make-icon.py
"""
import struct
from pathlib import Path

ICONSET = Path("packaging/macos/AppIcon.iconset")
# size -> source. 48px has no counterpart in the macOS set; scale 64px down with
# `sips -z 48 48 icon_32x32@2x.png --out icon_48.png` and put it beside this script.
SOURCES = {
    16: ICONSET / "icon_16x16.png",
    32: ICONSET / "icon_32x32.png",
    48: Path("packaging/windows/icon_48.png"),
    64: ICONSET / "icon_32x32@2x.png",
    128: ICONSET / "icon_128x128.png",
    256: ICONSET / "icon_128x128@2x.png",
}

images = [(size, path.read_bytes()) for size, path in SOURCES.items()]
header = struct.pack("<HHH", 0, 1, len(images))
offset = len(header) + 16 * len(images)
entries, payload = b"", b""
for size, data in images:
    edge = 0 if size == 256 else size  # 0 means 256 in an ICO directory entry
    entries += struct.pack("<BBBBHHII", edge, edge, 0, 0, 1, 32, len(data), offset + len(payload))
    payload += data
Path("packaging/windows/sniper.ico").write_bytes(header + entries + payload)
print(f"wrote packaging/windows/sniper.ico with sizes {[size for size, _ in images]}")
