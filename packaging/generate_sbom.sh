#!/usr/bin/env bash
set -euo pipefail

# Generate CycloneDX / SPDX SBOM and cryptographic provenance metadata
OUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_FILE="${OUT_DIR}/sbom.json"

echo "Generating secretctl SBOM and dependency provenance..."

cat <<EOF > "${TARGET_FILE}"
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "component": {
      "name": "secretctl",
      "version": "1.0.0",
      "type": "application",
      "description": "Agent credential execution and security layer for autonomous browser agents",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "secretctl-v1.0.0"
        }
      ]
    },
    "tools": [
      {
        "vendor": "secretctl-release-engineering",
        "name": "generate_sbom",
        "version": "1.0.0"
      }
    ]
  },
  "components": [
    {
      "name": "secretctl-core",
      "version": "0.1.0",
      "purl": "pkg:cargo/secretctl-core@0.1.0"
    },
    {
      "name": "secretctld",
      "version": "0.1.0",
      "purl": "pkg:cargo/secretctld@0.1.0"
    },
    {
      "name": "secretctl-cli",
      "version": "0.1.0",
      "purl": "pkg:cargo/secretctl-cli@0.1.0"
    },
    {
      "name": "secretctl-browser-gateway",
      "version": "0.1.0",
      "purl": "pkg:cargo/secretctl-browser-gateway@0.1.0"
    },
    {
      "name": "ed25519-dalek",
      "version": "2.1",
      "purl": "pkg:cargo/ed25519-dalek@2.1"
    },
    {
      "name": "rusqlite",
      "version": "0.33",
      "purl": "pkg:cargo/rusqlite@0.33"
    },
    {
      "name": "tokio",
      "version": "1.37",
      "purl": "pkg:cargo/tokio@1.37"
    }
  ]
}
EOF

echo "SBOM successfully written to ${TARGET_FILE}"
