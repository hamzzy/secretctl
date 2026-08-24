#!/usr/bin/env bash
set -euo pipefail

RELEASE_DIR="${1:-}"
[ -d "$RELEASE_DIR" ] || { echo "usage: $0 /path/to/release-directory" >&2; exit 2; }
(
    cd "$RELEASE_DIR"
    shasum -a 256 -c SHA256SUMS
    jq -e '.bomFormat == "CycloneDX" and (.components | length > 0)' sbom.cdx.json >/dev/null
    jq -e '.schema == "secretctl.release-provenance.v1" and (.source_commit | length == 40)' provenance.json >/dev/null
)
APP="$RELEASE_DIR/secretctl.app"
codesign --verify --deep --strict "$APP"
for REQUIRED in \
    Contents/Resources/bin/secretctl \
    Contents/Resources/bin/secretctld \
    Contents/Resources/bin/secretctl-native-host \
    Contents/Resources/extension/manifest.json; do
    [ -e "$APP/$REQUIRED" ] || { echo "error: release is missing $REQUIRED" >&2; exit 2; }
done
if [ "${SECRETCTL_REQUIRE_NOTARIZATION:-0}" = "1" ]; then
    spctl --assess --type execute --verbose=2 "$APP"
    xcrun stapler validate "$APP"
fi
echo "Release verification passed: $RELEASE_DIR"
