#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-}"
SOURCE_APP="${2:-}"
TARGET_APP="${SECRETCTL_APP_TARGET:-$HOME/Applications/secretctl.app}"
BACKUP_ROOT="${SECRETCTL_RELEASE_BACKUPS:-$HOME/Library/Application Support/secretctl/releases}"

usage() {
    echo "usage: $0 install /path/to/secretctl.app" >&2
    echo "       $0 rollback /path/to/backup/secretctl.app" >&2
    exit 2
}

[ "$ACTION" = "install" ] || [ "$ACTION" = "rollback" ] || usage
[ -n "$SOURCE_APP" ] || usage
[ -d "$SOURCE_APP" ] || { echo "error: app bundle not found: $SOURCE_APP" >&2; exit 2; }
codesign --verify --deep --strict "$SOURCE_APP"
for REQUIRED in \
    Contents/MacOS/secretctl-menubar \
    Contents/Resources/bin/secretctl \
    Contents/Resources/bin/secretctld \
    Contents/Resources/bin/secretctl-native-host \
    Contents/Resources/extension/manifest.json; do
    [ -e "$SOURCE_APP/$REQUIRED" ] || { echo "error: release is missing $REQUIRED" >&2; exit 2; }
done

mkdir -p "$(dirname "$TARGET_APP")" "$BACKUP_ROOT"
STAGING="$(mktemp -d "${TMPDIR:-/tmp}/secretctl-install.XXXXXX")"
trap 'rm -rf "$STAGING"' EXIT
ditto "$SOURCE_APP" "$STAGING/secretctl.app"
codesign --verify --deep --strict "$STAGING/secretctl.app"

if [ -d "$TARGET_APP" ]; then
    INSTALLED_CLI="$TARGET_APP/Contents/Resources/bin/secretctl"
    if [ -x "$INSTALLED_CLI" ]; then
        "$INSTALLED_CLI" stop 2>/dev/null || true
        "$INSTALLED_CLI" backup --output "$BACKUP_ROOT/pre-upgrade.db" 2>/dev/null || true
    fi
    BACKUP="$BACKUP_ROOT/$(date -u +%Y%m%dT%H%M%SZ)-secretctl.app"
    mv "$TARGET_APP" "$BACKUP"
    echo "Previous app: $BACKUP"
fi
mv "$STAGING/secretctl.app" "$TARGET_APP"

CLI="$TARGET_APP/Contents/Resources/bin/secretctl"
if [ "$ACTION" = "install" ]; then
    "$CLI" init
    "$CLI" browser install-host
fi
echo "$ACTION complete: $TARGET_APP"
echo "Launch managed Chrome with:"
echo "  '$CLI' browser launch --extension '$TARGET_APP/Contents/Resources/extension'"
