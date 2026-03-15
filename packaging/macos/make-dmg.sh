#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

APP_NAME="${APP_NAME:-Sniper}"
VERSION="${VERSION:-$(awk -F '\"' '/^version = / { print $2; exit }' Cargo.toml)}"
APP_BUNDLE="$ROOT_DIR/dist/${APP_NAME}.app"
DMG_PATH="$ROOT_DIR/dist/${APP_NAME}-${VERSION}.dmg"
STAGING_DIR="$ROOT_DIR/dist/dmg-root"

if [[ ! -d "$APP_BUNDLE" ]]; then
  "$ROOT_DIR/packaging/macos/make-app.sh"
fi

rm -rf "$STAGING_DIR" "$DMG_PATH"
mkdir -p "$STAGING_DIR"
cp -R "$APP_BUNDLE" "$STAGING_DIR/"
ln -s /Applications "$STAGING_DIR/Applications"

hdiutil create \
  -volname "$APP_NAME" \
  -srcfolder "$STAGING_DIR" \
  -ov \
  -format UDZO \
  "$DMG_PATH"

echo "Created DMG: $DMG_PATH"
