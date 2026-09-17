#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

APP_NAME="${APP_NAME:-Sniper}"
if [[ "$APP_NAME" != "Sniper" ]]; then
  echo "release-macos.sh only supports APP_NAME=Sniper; self-update pins the Sniper executable." >&2
  exit 1
fi
CARGO_VERSION="$(awk -F '\"' '/^version = / { print $2; exit }' Cargo.toml)"
VERSION="${VERSION:-$CARGO_VERSION}"
if [[ "$VERSION" != "$CARGO_VERSION" ]]; then
  echo "VERSION=$VERSION does not match Cargo.toml version $CARGO_VERSION" >&2
  exit 1
fi
RELEASE_TAG="v$VERSION"
GITHUB_RELEASE_REPO="${GITHUB_RELEASE_REPO:-${GITHUB_REPOSITORY:-sm1ee/Sniper}}"
ALLOW_ADHOC_RELEASE="${ALLOW_ADHOC_RELEASE:-0}"

canonical_github_repo() {
  local value="$1"
  value="${value%.git}"
  value="${value#git@github.com:}"
  value="${value#ssh://git@github.com/}"
  value="${value#https://github.com/}"
  value="${value#http://github.com/}"
  value="${value%/}"
  printf '%s' "$value" | tr '[:upper:]' '[:lower:]'
}

if [[ "$ALLOW_ADHOC_RELEASE" != "1" ]] && ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "Release artifacts must be built from a git worktree so origin/main and tag provenance can be verified." >&2
  echo "Set ALLOW_ADHOC_RELEASE=1 for local-only unsigned testing." >&2
  exit 1
fi

if [[ "$ALLOW_ADHOC_RELEASE" != "1" ]] && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  EXPECTED_RELEASE_REPO="$(canonical_github_repo "$GITHUB_RELEASE_REPO")"
  ORIGIN_RELEASE_REPO="$(canonical_github_repo "$(git remote get-url origin 2>/dev/null || true)")"
  if [[ -z "$ORIGIN_RELEASE_REPO" || "$ORIGIN_RELEASE_REPO" != "$EXPECTED_RELEASE_REPO" ]]; then
    echo "Release artifacts must be built with origin pointing at $GITHUB_RELEASE_REPO; origin is ${ORIGIN_RELEASE_REPO:-unavailable}." >&2
    echo "Set ALLOW_ADHOC_RELEASE=1 for local-only unsigned testing." >&2
    exit 1
  fi
  CURRENT_BRANCH="$(git symbolic-ref --quiet --short HEAD || true)"
  TRACKED_RELEASE_STATUS="$(git status --porcelain --untracked-files=no)"
  UNTRACKED_RELEASE_INPUTS="$(git ls-files --others --exclude-standard -- \
    Cargo.toml Cargo.lock README.md \
    build.rs .cargo rust-toolchain rust-toolchain.toml \
    src web packaging tests 2>/dev/null || true)"
  if [[ -n "$TRACKED_RELEASE_STATUS" || -n "$UNTRACKED_RELEASE_INPUTS" ]]; then
    echo "Release artifacts require a clean worktree." >&2
    if [[ -n "$TRACKED_RELEASE_STATUS" ]]; then
      printf '%s\n' "$TRACKED_RELEASE_STATUS" >&2
    fi
    if [[ -n "$UNTRACKED_RELEASE_INPUTS" ]]; then
      printf '%s\n' "$UNTRACKED_RELEASE_INPUTS" | sed 's/^/?? /' >&2
    fi
    echo "Commit/stash/remove these files first, or set ALLOW_ADHOC_RELEASE=1 for local-only testing." >&2
    exit 1
  fi
  UNTRACKED_LOCAL_FILES="$(git ls-files --others --exclude-standard 2>/dev/null || true)"
  if [[ -n "$UNTRACKED_LOCAL_FILES" ]]; then
    echo "Ignoring untracked files outside release inputs:" >&2
    printf '%s\n' "$UNTRACKED_LOCAL_FILES" | sed 's/^/?? /' >&2
  fi
  HEAD_COMMIT="$(git rev-parse HEAD)"
  REMOTE_MAIN_COMMIT=""
  if remote_main="$(git ls-remote origin refs/heads/main 2>/dev/null)"; then
    REMOTE_MAIN_COMMIT="$(printf '%s\n' "$remote_main" | awk 'NF >= 2 { print $1; exit }')"
  fi
  if [[ -z "$REMOTE_MAIN_COMMIT" ]]; then
    echo "Unable to verify origin/main before building release artifacts." >&2
    exit 1
  fi
  if [[ -n "$CURRENT_BRANCH" && "$CURRENT_BRANCH" != "main" ]]; then
    echo "Release artifacts must be built from the main branch or detached origin/main; current branch is ${CURRENT_BRANCH:-detached}." >&2
    echo "For local-only unsigned testing, set ALLOW_ADHOC_RELEASE=1." >&2
    exit 1
  fi
  if [[ "$HEAD_COMMIT" != "$REMOTE_MAIN_COMMIT" ]]; then
    echo "Release artifacts must be built from origin/main ($REMOTE_MAIN_COMMIT), not $HEAD_COMMIT." >&2
    exit 1
  fi
fi
if [[ "$ALLOW_ADHOC_RELEASE" != "1" ]] && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  HEAD_COMMIT="$(git rev-parse HEAD)"
  TAG_COMMIT=""
  if git rev-parse -q --verify "refs/tags/$RELEASE_TAG^{commit}" >/dev/null; then
    TAG_COMMIT="$(git rev-list -n 1 "$RELEASE_TAG")"
    echo "$RELEASE_TAG already exists locally at $TAG_COMMIT." >&2
    echo "Bump Cargo.toml before creating release artifacts for a new version." >&2
    exit 1
  fi
  REMOTE_TAG_COMMIT=""
  if remote_tag="$(git ls-remote --tags origin "$RELEASE_TAG" 2>/dev/null)"; then
    REMOTE_TAG_COMMIT="$(printf '%s\n' "$remote_tag" | awk 'NF >= 2 { print $1; exit }')"
    if [[ -n "$REMOTE_TAG_COMMIT" ]]; then
      echo "$RELEASE_TAG already exists on origin at $REMOTE_TAG_COMMIT." >&2
      echo "Bump Cargo.toml before creating release artifacts for a published version." >&2
      exit 1
    fi
  else
    echo "Unable to verify whether $RELEASE_TAG exists on origin." >&2
    if [[ "${ALLOW_EXISTING_RELEASE_VERSION:-0}" == "1" ]]; then
      echo "Continuing because ALLOW_EXISTING_RELEASE_VERSION=1 only overrides remote tag check failures." >&2
    else
      echo "Refusing to create release artifacts without a remote tag check. Set ALLOW_EXISTING_RELEASE_VERSION=1 to override only this check failure." >&2
      exit 1
    fi
  fi
  if command -v gh >/dev/null 2>&1 && [[ -n "$GITHUB_RELEASE_REPO" ]] \
    && gh release view "$RELEASE_TAG" --repo "$GITHUB_RELEASE_REPO" >/dev/null 2>&1; then
    echo "GitHub release $RELEASE_TAG already exists in $GITHUB_RELEASE_REPO." >&2
    echo "Bump Cargo.toml before creating release artifacts for a new commit." >&2
    exit 1
  fi
fi
REQUESTED_DMG_ARCH="${DMG_ARCH:-}"
BRIDGE_REQUIRES_UNIVERSAL=0
LEGACY_UPDATER_COMPAT="${LEGACY_UPDATER_COMPAT:-1}"
if [[ "$ALLOW_ADHOC_RELEASE" != "1" && "$LEGACY_UPDATER_COMPAT" != "0" && "${ALLOW_NON_UNIVERSAL_BRIDGE_RELEASE:-0}" != "1" ]]; then
  BRIDGE_REQUIRES_UNIVERSAL=1
  if [[ -n "$REQUESTED_DMG_ARCH" && "$REQUESTED_DMG_ARCH" != "universal" ]]; then
    echo "Sniper releases must use DMG_ARCH=universal while legacy v0.2.4 updater clients may select the latest DMG without arch filtering." >&2
    echo "Set LEGACY_UPDATER_COMPAT=0 only after legacy updater migration is intentionally complete." >&2
    exit 1
  fi
  REQUESTED_DMG_ARCH="universal"
fi
SIGN_IDENTITY="${DEVELOPER_ID_APP:-${SIGN_IDENTITY:-}}"
HAS_APPLE_CREDS=0
HAS_PARTIAL_APPLE_CREDS=0
if [[ -n "${APPLE_ID:-}" && -n "${APPLE_TEAM_ID:-}" && -n "${APPLE_APP_PASSWORD:-}" ]]; then
  HAS_APPLE_CREDS=1
elif [[ -n "${APPLE_ID:-}" || -n "${APPLE_TEAM_ID:-}" || -n "${APPLE_APP_PASSWORD:-}" ]]; then
  HAS_PARTIAL_APPLE_CREDS=1
fi

if [[ "$ALLOW_ADHOC_RELEASE" != "1" && -z "$SIGN_IDENTITY" ]]; then
  echo "Developer ID signing identity is required for release artifacts. Set DEVELOPER_ID_APP or SIGN_IDENTITY." >&2
  echo "For local-only unsigned testing, set ALLOW_ADHOC_RELEASE=1." >&2
  exit 1
fi

if [[ "$ALLOW_ADHOC_RELEASE" != "1" && "$HAS_APPLE_CREDS" == "1" ]]; then
  if [[ -z "$SIGN_IDENTITY" ]]; then
    echo "Apple notarization credentials were provided but no signing identity is configured." >&2
    exit 1
  fi
elif [[ "$ALLOW_ADHOC_RELEASE" != "1" ]]; then
  if [[ "$HAS_PARTIAL_APPLE_CREDS" == "1" ]]; then
    echo "Incomplete Apple notarization credentials. Set APPLE_ID, APPLE_TEAM_ID, and APPLE_APP_PASSWORD." >&2
    exit 1
  fi
  echo "Apple notarization credentials are required for signed release artifacts." >&2
  echo "Set APPLE_ID, APPLE_TEAM_ID, and APPLE_APP_PASSWORD." >&2
  exit 1
elif [[ "$HAS_PARTIAL_APPLE_CREDS" == "1" ]]; then
  echo "Ignoring incomplete Apple notarization credentials for explicit local-only release (ALLOW_ADHOC_RELEASE=1)." >&2
fi

mkdir -p "$ROOT_DIR/dist"
DMG_BUILD_MARKER="$(mktemp "$ROOT_DIR/dist/.release-dmg-marker.XXXXXX")"
APP_NOTARY_ZIP=""
cleanup_release_marker() {
  rm -f "$DMG_BUILD_MARKER"
  if [[ -n "$APP_NOTARY_ZIP" ]]; then
    rm -f "$APP_NOTARY_ZIP"
  fi
}
trap cleanup_release_marker EXIT

if [[ "$BRIDGE_REQUIRES_UNIVERSAL" == "1" || "$REQUESTED_DMG_ARCH" == "universal" ]]; then
  UNIVERSAL_APP=1 "$ROOT_DIR/packaging/macos/make-app.sh"
else
  "$ROOT_DIR/packaging/macos/make-app.sh"
fi

APP_BUNDLE="$ROOT_DIR/dist/${APP_NAME}.app"
if [[ "$ALLOW_ADHOC_RELEASE" != "1" && "$HAS_APPLE_CREDS" == "1" ]]; then
  APP_NOTARY_ZIP="$ROOT_DIR/dist/.${APP_NAME}-${VERSION}-app-notary.zip"
  rm -f "$APP_NOTARY_ZIP"
  /usr/bin/ditto -c -k --keepParent "$APP_BUNDLE" "$APP_NOTARY_ZIP"
  xcrun notarytool submit "$APP_NOTARY_ZIP" \
    --apple-id "$APPLE_ID" \
    --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_APP_PASSWORD" \
    --wait
  xcrun stapler staple "$APP_BUNDLE"
  /usr/sbin/spctl --assess --type execute "$APP_BUNDLE"
fi

if [[ -n "$REQUESTED_DMG_ARCH" ]]; then
  DMG_ARCH="$REQUESTED_DMG_ARCH" SKIP_BUILD=1 "$ROOT_DIR/packaging/macos/make-dmg.sh"
else
  SKIP_BUILD=1 "$ROOT_DIR/packaging/macos/make-dmg.sh"
fi

DMG_CANDIDATES=()
while IFS= read -r candidate; do
  DMG_CANDIDATES+=("$candidate")
done < <(find "$ROOT_DIR/dist" -maxdepth 1 -type f -name "${APP_NAME}-${VERSION}-*.dmg" -newer "$DMG_BUILD_MARKER" -print)

if [[ "${#DMG_CANDIDATES[@]}" -ne 1 ]]; then
  echo "Expected exactly one freshly built DMG for ${APP_NAME} ${VERSION}, found ${#DMG_CANDIDATES[@]}." >&2
  printf '  %s\n' "${DMG_CANDIDATES[@]}" >&2
  exit 1
fi

DMG_PATH="${DMG_CANDIDATES[0]}"
if [[ "$ALLOW_ADHOC_RELEASE" != "1" && "$LEGACY_UPDATER_COMPAT" != "0" && "$DMG_PATH" != *"-universal.dmg" && "${ALLOW_NON_UNIVERSAL_BRIDGE_RELEASE:-0}" != "1" ]]; then
  echo "Sniper legacy updater-compatible releases must upload a universal DMG because v0.2.4 clients are not arch-aware." >&2
  echo "Build/upload a universal DMG, or set LEGACY_UPDATER_COMPAT=0 if this is intentional." >&2
  exit 1
fi

if [[ "$ALLOW_ADHOC_RELEASE" != "1" && "$HAS_APPLE_CREDS" == "1" ]]; then
  xcrun notarytool submit "$DMG_PATH" \
    --apple-id "$APPLE_ID" \
    --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_APP_PASSWORD" \
    --wait
  xcrun stapler staple "$DMG_PATH"
elif [[ "$ALLOW_ADHOC_RELEASE" == "1" ]]; then
  echo "Skipping notarization for explicit local-only release (ALLOW_ADHOC_RELEASE=1)." >&2
fi

/usr/bin/hdiutil verify "$DMG_PATH"

# Same `<hash>  <name>` shape make-zip.ps1 writes for the Windows archive, so a
# downloader can check either artifact with `shasum -a 256 -c`. Releases are
# ad-hoc signed, so this is the only integrity check a downloader gets.
DMG_NAME="$(basename "$DMG_PATH")"
(
  cd "$ROOT_DIR/dist"
  shasum -a 256 "$DMG_NAME" > "$DMG_NAME.sha256"
  shasum -a 256 -c "$DMG_NAME.sha256"
)

echo "macOS release artifacts ready in $ROOT_DIR/dist"
