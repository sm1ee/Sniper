#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

APP_NAME="${APP_NAME:-Sniper}"
VERSION="${VERSION:-$(awk -F '\"' '/^version = / { print $2; exit }' Cargo.toml)}"
APP_BUNDLE="$ROOT_DIR/dist/${APP_NAME}.app"
DMG_PATH="$ROOT_DIR/dist/${APP_NAME}-${VERSION}.dmg"
DMG_TMP="$ROOT_DIR/dist/${APP_NAME}-tmp.dmg"
STAGING_DIR="$ROOT_DIR/dist/dmg-root"
BG_IMG="$ROOT_DIR/packaging/macos/dmg-background.png"
VOLUME_NAME="$APP_NAME"

if [[ ! -d "$APP_BUNDLE" ]]; then
  "$ROOT_DIR/packaging/macos/make-app.sh"
fi

# Detach any leftover Sniper volumes
for vol in /Volumes/"$VOLUME_NAME"*; do
  hdiutil detach "$vol" 2>/dev/null || true
done

rm -rf "$STAGING_DIR" "$DMG_PATH" "$DMG_TMP"
mkdir -p "$STAGING_DIR/.background"
cp -R "$APP_BUNDLE" "$STAGING_DIR/"
ln -s /Applications "$STAGING_DIR/Applications"

if [[ -f "$BG_IMG" ]]; then
  cp "$BG_IMG" "$STAGING_DIR/.background/background.png"
fi

VOLUME_ICON="$ROOT_DIR/packaging/macos/AppIcon.icns"
if [[ -f "$VOLUME_ICON" ]]; then
  cp "$VOLUME_ICON" "$STAGING_DIR/.VolumeIcon.icns"
  SetFile -c icnC "$STAGING_DIR/.VolumeIcon.icns" 2>/dev/null || true
  SetFile -a C "$STAGING_DIR" 2>/dev/null || true
fi

# Create read-write HFS+ DMG
hdiutil create \
  -volname "$VOLUME_NAME" \
  -srcfolder "$STAGING_DIR" \
  -ov \
  -fs HFS+ \
  -format UDRW \
  "$DMG_TMP"

# Mount
ATTACH_OUTPUT=$(hdiutil attach -readwrite -noverify -noautoopen "$DMG_TMP")
DEVICE=$(echo "$ATTACH_OUTPUT" | awk '/\/Volumes\// { print $1 }')
MOUNT_POINT=$(echo "$ATTACH_OUTPUT" | awk '/\/Volumes\// { for(i=NF;i>=1;i--) if($i ~ /^\/Volumes/) { s=$i; for(j=i+1;j<=NF;j++) s=s" "$j; print s; exit } }')
DISK_NAME=$(basename "$MOUNT_POINT")

echo "Mounted at: $MOUNT_POINT (device: $DEVICE)"
sleep 2

# Remove .fseventsd so it never shows up
rm -rf "$MOUNT_POINT/.fseventsd"
# Prevent fseventsd from recreating it
touch "$MOUNT_POINT/.fseventsd"
chmod 000 "$MOUNT_POINT/.fseventsd" 2>/dev/null || true

# Style with AppleScript — run twice to ensure Finder persists DS_Store
for pass in 1 2; do
  osascript <<APPLESCRIPT
tell application "Finder"
  tell disk "$DISK_NAME"
    open
    set current view of container window to icon view
    set toolbar visible of container window to false
    set statusbar visible of container window to false
    set bounds of container window to {200, 120, 860, 540}

    set theViewOptions to icon view options of container window
    set arrangement of theViewOptions to not arranged
    set icon size of theViewOptions to 128

    set background picture of theViewOptions to file ".background:background.png"

    set position of item "${APP_NAME}.app" to {165, 200}
    set position of item "Applications" to {495, 200}

    update without registering applications
    delay 3
    close
  end tell
end tell
APPLESCRIPT
  sleep 2
done

# Hide hidden files via SetFile if available
SetFile -a V "$MOUNT_POINT/.background" 2>/dev/null || true
SetFile -a V "$MOUNT_POINT/.fseventsd" 2>/dev/null || true
SetFile -a V "$MOUNT_POINT/.VolumeIcon.icns" 2>/dev/null || true

sync
sleep 1
hdiutil detach "$DEVICE" -quiet || hdiutil detach "$DEVICE" -force

# Convert to compressed read-only DMG
hdiutil convert "$DMG_TMP" -format UDZO -imagekey zlib-level=9 -o "$DMG_PATH"
rm -f "$DMG_TMP"

echo "Created DMG: $DMG_PATH"
