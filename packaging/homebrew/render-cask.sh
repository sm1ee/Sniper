#!/usr/bin/env bash
# Renders the Homebrew cask for the DMG release-macos.sh built, as it goes into
# Casks/sniper.rb in sm1ee/homebrew-tap.
# Usage: packaging/homebrew/render-cask.sh [output.rb]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' "${ROOT}/Cargo.toml" | head -n 1)"
DMG="${ROOT}/dist/Sniper-${VERSION}-universal.dmg"
[[ -f "${DMG}" ]] || { echo "Missing ${DMG}; run packaging/macos/release-macos.sh first" >&2; exit 1; }
SHA="$(shasum -a 256 "${DMG}" | cut -d' ' -f1)"
OUT="${1:-/dev/stdout}"
sed -e "s/__VERSION__/${VERSION}/" -e "s/__SHA256__/${SHA}/" "${ROOT}/packaging/homebrew/sniper.rb" > "${OUT}"
