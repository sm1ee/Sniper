#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

APP_NAME="${APP_NAME:-Sniper}"
APP_BUNDLE="$ROOT_DIR/dist/${APP_NAME}.app"
CONTENTS_DIR="$APP_BUNDLE/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"
PLIST_TEMPLATE="$ROOT_DIR/packaging/macos/Info.plist"
PLIST_OUT="$CONTENTS_DIR/Info.plist"
ENTITLEMENTS="$ROOT_DIR/packaging/macos/entitlements.plist"
BIN_PATH="$ROOT_DIR/target/release/sniper-desktop"
VERSION="${VERSION:-$(awk -F '\"' '/^version = / { print $2; exit }' Cargo.toml)}"

rm -rf "$APP_BUNDLE"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"

cargo build --release --bin sniper-desktop

cp "$BIN_PATH" "$MACOS_DIR/$APP_NAME"
chmod +x "$MACOS_DIR/$APP_NAME"
sed "s/__SNIPER_VERSION__/$VERSION/g" "$PLIST_TEMPLATE" > "$PLIST_OUT"

if [[ -n "${APP_ICON:-}" && -f "${APP_ICON}" ]]; then
  cp "$APP_ICON" "$RESOURCES_DIR/AppIcon.icns"
  /usr/libexec/PlistBuddy -c "Add :CFBundleIconFile string AppIcon" "$PLIST_OUT" 2>/dev/null || \
    /usr/libexec/PlistBuddy -c "Set :CFBundleIconFile AppIcon" "$PLIST_OUT"
fi

SIGN_IDENTITY="${DEVELOPER_ID_APP:-${SIGN_IDENTITY:-}}"
if [[ -n "$SIGN_IDENTITY" ]]; then
  codesign --force --deep --timestamp --options runtime --entitlements "$ENTITLEMENTS" --sign "$SIGN_IDENTITY" "$APP_BUNDLE"
else
  codesign --force --deep --sign - "$APP_BUNDLE"
fi

echo "Created app bundle: $APP_BUNDLE"
