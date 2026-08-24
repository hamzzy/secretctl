#!/usr/bin/env bash
# Assemble secretctl.app from the SwiftPM build product.
#
# A bare SwiftPM executable has no bundle identity, and macOS ties several
# things the app needs to that identity: UNUserNotificationCenter refuses to
# work without it, SMAppService cannot register a login item, and LSUIElement is
# what keeps the app out of the Dock. So the binary is wrapped in a real bundle
# and ad-hoc signed, which is enough for local use.
set -euo pipefail

CONFIGURATION="${1:-release}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP="$ROOT/build/secretctl.app"

echo "==> Building ($CONFIGURATION)"
swift build -c "$CONFIGURATION" --package-path "$ROOT"
BINARY="$(swift build -c "$CONFIGURATION" --package-path "$ROOT" --show-bin-path)/secretctl-menubar"

echo "==> Rendering the app icon"
ICONDIR="$ROOT/build/icon"
mkdir -p "$ICONDIR/secretctl.iconset"
swiftc -O "$ROOT/Tools/icon/DrawIcon.swift" -o "$ICONDIR/drawicon"
"$ICONDIR/drawicon" "$ICONDIR/secretctl.iconset"
iconutil -c icns "$ICONDIR/secretctl.iconset" -o "$ICONDIR/secretctl.icns"

echo "==> Assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BINARY" "$APP/Contents/MacOS/secretctl-menubar"
cp "$ROOT/Resources/Info.plist" "$APP/Contents/Info.plist"
cp "$ICONDIR/secretctl.icns" "$APP/Contents/Resources/secretctl.icns"
cp "$ICONDIR/mark.png" "$APP/Contents/Resources/mark.png"

# Ad-hoc signature. Notifications and the Keychain prompt both behave better
# with a stable signed identity than with an unsigned binary; replace "-" with a
# Developer ID for distribution.
echo "==> Signing (ad-hoc)"
codesign --force --deep --sign - \
    --options runtime \
    --identifier com.secretctl.menubar \
    "$APP" 2>&1 | sed 's/^/    /'

echo "==> Done: $APP"
echo "    Run with: open '$APP'"
