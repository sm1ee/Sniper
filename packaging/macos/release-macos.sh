#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

"$ROOT_DIR/packaging/macos/make-app.sh"

APP_NAME="${APP_NAME:-Sniper}"
VERSION="${VERSION:-$(awk -F '\"' '/^version = / { print $2; exit }' Cargo.toml)}"
APP_BUNDLE="$ROOT_DIR/dist/${APP_NAME}.app"

if [[ -n "${DEVELOPER_ID_APP:-}" && -n "${APPLE_ID:-}" && -n "${APPLE_TEAM_ID:-}" && -n "${APPLE_APP_PASSWORD:-}" ]]; then
  xcrun notarytool submit "$APP_BUNDLE" \
    --apple-id "$APPLE_ID" \
    --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_APP_PASSWORD" \
    --wait
  xcrun stapler staple "$APP_BUNDLE"
fi

"$ROOT_DIR/packaging/macos/make-dmg.sh"

DMG_PATH="$ROOT_DIR/dist/${APP_NAME}-${VERSION}.dmg"

if [[ -n "${DEVELOPER_ID_APP:-}" && -n "${APPLE_ID:-}" && -n "${APPLE_TEAM_ID:-}" && -n "${APPLE_APP_PASSWORD:-}" ]]; then
  xcrun notarytool submit "$DMG_PATH" \
    --apple-id "$APPLE_ID" \
    --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_APP_PASSWORD" \
    --wait
fi

echo "macOS release artifacts ready in $ROOT_DIR/dist"
