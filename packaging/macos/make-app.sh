#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

APP_NAME="${APP_NAME:-Sniper}"
UNIVERSAL_APP="${UNIVERSAL_APP:-0}"

validate_app_name() {
  local name="$1"
  if [[ -z "$name" || "$name" == "." || "$name" == ".." || "$name" == *"/"* || "$name" == *"\\"* || "$name" == *"'"* || "$name" == *"\""* || "$name" == *$'\n'* || "$name" == *$'\r'* || "$name" == *$'\t'* ]]; then
    echo "Invalid APP_NAME: must be a single safe app name" >&2
    exit 1
  fi
}

validate_app_name "$APP_NAME"

APP_BUNDLE="$ROOT_DIR/dist/${APP_NAME}.app"
# The headless server. Not "sniper": APFS is case-insensitive by default, so it
# would be the same file as the desktop app's "Sniper" beside it.
SERVER_NAME="sniper-server"
CONTENTS_DIR="$APP_BUNDLE/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"
PLIST_TEMPLATE="$ROOT_DIR/packaging/macos/Info.plist"
PLIST_OUT="$CONTENTS_DIR/Info.plist"
ENTITLEMENTS="$ROOT_DIR/packaging/macos/entitlements.plist"
CARGO_VERSION="$(awk -F '\"' '/^version = / { print $2; exit }' Cargo.toml)"
VERSION="${VERSION:-$CARGO_VERSION}"
if [[ "$VERSION" != "$CARGO_VERSION" ]]; then
  echo "VERSION=$VERSION does not match Cargo.toml version $CARGO_VERSION" >&2
  exit 1
fi
CARGO_BUILD_LOG="$(mktemp "${TMPDIR:-/tmp}/sniper-cargo-build.XXXXXX")"
trap 'rm -f "$CARGO_BUILD_LOG"' EXIT

sed_escape_replacement() {
  printf '%s' "$1" | sed -e 's/[\/&\\]/\\&/g'
}

xml_escape() {
  local value="$1"
  value="${value//&/&amp;}"
  value="${value//</&lt;}"
  value="${value//>/&gt;}"
  printf '%s' "$value"
}

plist_sed_replacement() {
  sed_escape_replacement "$(xml_escape "$1")"
}

rm -rf "$APP_BUNDLE"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"

cargo_bin_path() {
  local bin_name="$1"
  local path
  path="$(grep '"reason":"compiler-artifact"' "$CARGO_BUILD_LOG" \
    | grep "\"name\":\"$bin_name\"" \
    | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' \
    | tail -n 1 || true)"
  if [[ -z "$path" || ! -x "$path" ]]; then
    echo "Cargo did not produce an executable for $bin_name" >&2
    exit 1
  fi
  printf '%s\n' "$path"
}

build_native_binaries() {
  echo "Building release binaries..."
  if ! cargo build --locked --release --bin sniper-desktop --bin sniper-cli --bin sniper --message-format=json-render-diagnostics > "$CARGO_BUILD_LOG"; then
    cat "$CARGO_BUILD_LOG" >&2
    exit 1
  fi

  BIN_PATH="$(cargo_bin_path sniper-desktop)"
  cp "$BIN_PATH" "$MACOS_DIR/$APP_NAME"
  chmod +x "$MACOS_DIR/$APP_NAME"

  CLI_BIN_PATH="$(cargo_bin_path sniper-cli)"
  cp "$CLI_BIN_PATH" "$MACOS_DIR/sniper-cli"
  chmod +x "$MACOS_DIR/sniper-cli"

  SERVER_BIN_PATH="$(cargo_bin_path sniper)"
  cp "$SERVER_BIN_PATH" "$MACOS_DIR/$SERVER_NAME"
  chmod +x "$MACOS_DIR/$SERVER_NAME"
}

require_rust_target() {
  local target="$1"
  if ! rustup target list --installed | grep -qx "$target"; then
    echo "Rust target $target is required for UNIVERSAL_APP=1." >&2
    echo "Install it with: rustup target add $target" >&2
    exit 1
  fi
}

target_binary_path() {
  local target="$1"
  local bin_name="$2"
  local path="$ROOT_DIR/target/$target/release/$bin_name"
  if [[ ! -x "$path" ]]; then
    echo "Cargo did not produce an executable for $bin_name at $path" >&2
    exit 1
  fi
  printf '%s\n' "$path"
}

build_universal_binaries() {
  local arm_target="aarch64-apple-darwin"
  local intel_target="x86_64-apple-darwin"

  require_rust_target "$arm_target"
  require_rust_target "$intel_target"

  echo "Building universal release binaries..."
  cargo build --locked --release --target "$arm_target" --bin sniper-desktop --bin sniper-cli --bin sniper
  cargo build --locked --release --target "$intel_target" --bin sniper-desktop --bin sniper-cli --bin sniper

  /usr/bin/lipo -create \
    "$(target_binary_path "$arm_target" sniper-desktop)" \
    "$(target_binary_path "$intel_target" sniper-desktop)" \
    -output "$MACOS_DIR/$APP_NAME"
  chmod +x "$MACOS_DIR/$APP_NAME"

  /usr/bin/lipo -create \
    "$(target_binary_path "$arm_target" sniper-cli)" \
    "$(target_binary_path "$intel_target" sniper-cli)" \
    -output "$MACOS_DIR/sniper-cli"
  chmod +x "$MACOS_DIR/sniper-cli"

  /usr/bin/lipo -create \
    "$(target_binary_path "$arm_target" sniper)" \
    "$(target_binary_path "$intel_target" sniper)" \
    -output "$MACOS_DIR/$SERVER_NAME"
  chmod +x "$MACOS_DIR/$SERVER_NAME"
}

case "$UNIVERSAL_APP" in
  0)
    build_native_binaries
    ;;
  1)
    build_universal_binaries
    ;;
  *)
    echo "UNIVERSAL_APP must be 0 or 1" >&2
    exit 1
    ;;
esac

sed \
  -e "s/__SNIPER_VERSION__/$(plist_sed_replacement "$VERSION")/g" \
  -e "s/__APP_NAME__/$(plist_sed_replacement "$APP_NAME")/g" \
  "$PLIST_TEMPLATE" > "$PLIST_OUT"

BUNDLED_ICON="$ROOT_DIR/packaging/macos/AppIcon.icns"
APP_ICON="${APP_ICON:-$BUNDLED_ICON}"
if [[ -f "$APP_ICON" ]]; then
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
