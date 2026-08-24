#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$ROOT/.." && pwd)"
VERSION="${SECRETCTL_RELEASE_VERSION:-$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$REPO_ROOT/Cargo.toml" | head -1)}"
ARTIFACT_DIR="$ROOT/build/release-$VERSION"
IDENTITIES="$(security find-identity -v -p codesigning 2>/dev/null || true)"

if ! grep -q 'Developer ID Application' <<<"$IDENTITIES"; then
    echo "error: a Developer ID Application signing identity is required" >&2
    exit 2
fi
if [ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=no)" ] && [ "${SECRETCTL_ALLOW_DIRTY_RELEASE:-0}" != "1" ]; then
    echo "error: release provenance requires a clean tracked worktree" >&2
    exit 2
fi

"$ROOT/build-app.sh" release
mkdir -p "$ARTIFACT_DIR"
cp -R "$ROOT/build/secretctl.app" "$ARTIFACT_DIR/secretctl.app"
cp "$ROOT/install.sh" "$ROOT/verify-release.sh" "$ARTIFACT_DIR/"
"$REPO_ROOT/packaging/generate_sbom.sh" "$ARTIFACT_DIR/sbom.cdx.json"
ditto -c -k --sequesterRsrc --keepParent "$ARTIFACT_DIR/secretctl.app" "$ARTIFACT_DIR/secretctl-$VERSION-macos.zip"

if [ -n "${SECRETCTL_NOTARY_PROFILE:-}" ]; then
    xcrun notarytool submit "$ARTIFACT_DIR/secretctl-$VERSION-macos.zip" \
        --keychain-profile "$SECRETCTL_NOTARY_PROFILE" --wait
    xcrun stapler staple "$ARTIFACT_DIR/secretctl.app"
    xcrun stapler validate "$ARTIFACT_DIR/secretctl.app"
fi

(
    cd "$ARTIFACT_DIR"
    shasum -a 256 "secretctl-$VERSION-macos.zip" sbom.cdx.json > SHA256SUMS
    jq -n \
      --arg version "$VERSION" \
      --arg commit "$(git -C "$REPO_ROOT" rev-parse HEAD)" \
      --arg rustc "$(rustc --version)" \
      --arg swift "$(swift --version | head -1)" \
      '{schema: "secretctl.release-provenance.v1", version: $version, source_commit: $commit, builders: {rust: $rustc, swift: $swift}, inputs: ["Cargo.lock", "macos/Package.swift"], artifacts: ["SHA256SUMS", "sbom.cdx.json"]}' \
      > provenance.json
)
codesign --verify --deep --strict "$ARTIFACT_DIR/secretctl.app"
"$ROOT/verify-release.sh" "$ARTIFACT_DIR"
echo "Release candidate: $ARTIFACT_DIR"
