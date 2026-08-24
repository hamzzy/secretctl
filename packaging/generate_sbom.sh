#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="${1:-$ROOT/macos/build/sbom.cdx.json}"
VERSION="${SECRETCTL_RELEASE_VERSION:-$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)}"
mkdir -p "$(dirname "$OUTPUT")"

METADATA="$(mktemp)"
trap 'rm -f "$METADATA"' EXIT
HOST_TARGET="${SECRETCTL_SBOM_TARGET:-$(rustc -vV | sed -n 's/^host: //p')}"
cargo metadata --manifest-path "$ROOT/Cargo.toml" --locked --offline --format-version 1 \
    --filter-platform "$HOST_TARGET" > "$METADATA"
LOCK_HASH="$(shasum -a 256 "$ROOT/Cargo.lock" | awk '{print $1}')"

jq --arg version "$VERSION" --arg lock_hash "$LOCK_HASH" '
  {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    metadata: {
      component: {
        type: "application",
        name: "secretctl",
        version: $version,
        hashes: [{alg: "SHA-256", content: $lock_hash}]
      },
      properties: [{name: "secretctl:dependency-lock", value: "Cargo.lock"}]
    },
    components: ([.packages[] | {
      type: "library",
      name: .name,
      version: .version,
      purl: ("pkg:cargo/" + (.name | @uri) + "@" + (.version | @uri)),
      licenses: (if .license then [{expression: .license}] else [] end)
    }] | sort_by(.name, .version))
  }
' "$METADATA" > "$OUTPUT"

jq -e '.bomFormat == "CycloneDX" and (.components | length > 0)' "$OUTPUT" >/dev/null
echo "SBOM: $OUTPUT"
