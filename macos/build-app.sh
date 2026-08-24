#!/usr/bin/env bash
# Assemble secretctl.app from the SwiftPM build product.
#
# A bare SwiftPM executable has no bundle identity, and macOS ties several
# things the app needs to that identity: UNUserNotificationCenter refuses to
# work without it, SMAppService cannot register a login item, and LSUIElement is
# what keeps the app out of the Dock. So the binary is wrapped in a real bundle
# and signed.
#
# Set SECRETCTL_SIGN_IDENTITY to a Developer ID Application identity for a
# distributable build. Without it the bundle is ad-hoc signed, which works
# locally but has one visible cost: an ad-hoc signature differs on every build,
# a code signature is part of a Keychain item's access control, and so macOS
# re-prompts for Keychain access after every rebuild. A stable identity ends
# that.
#
#     SECRETCTL_SIGN_IDENTITY="Developer ID Application: You (TEAMID)" ./build-app.sh
set -euo pipefail

CONFIGURATION="${1:-release}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$ROOT/.." && pwd)"
APP="$ROOT/build/secretctl.app"

echo "==> Building ($CONFIGURATION)"
swift build -c "$CONFIGURATION" --package-path "$ROOT"
BINARY="$(swift build -c "$CONFIGURATION" --package-path "$ROOT" --show-bin-path)/secretctl-menubar"
if [ "$CONFIGURATION" = "release" ]; then
    CARGO_PROFILE="release"
    cargo build --manifest-path "$REPO_ROOT/Cargo.toml" --locked --release \
        -p secretctl-cli -p secretctld -p secretctl-native-host
else
    CARGO_PROFILE="debug"
    cargo build --manifest-path "$REPO_ROOT/Cargo.toml" --locked \
        -p secretctl-cli -p secretctld -p secretctl-native-host
fi

echo "==> Rendering the app icon"
ICONDIR="$ROOT/build/icon"
mkdir -p "$ICONDIR/secretctl.iconset"
swiftc -O "$ROOT/Tools/icon/DrawIcon.swift" -o "$ICONDIR/drawicon"
"$ICONDIR/drawicon" "$ICONDIR/secretctl.iconset"
iconutil -c icns "$ICONDIR/secretctl.iconset" -o "$ICONDIR/secretctl.icns"

echo "==> Assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/bin" "$APP/Contents/Resources/extension"
cp "$BINARY" "$APP/Contents/MacOS/secretctl-menubar"
cp "$ROOT/Resources/Info.plist" "$APP/Contents/Info.plist"
cp "$ICONDIR/secretctl.icns" "$APP/Contents/Resources/secretctl.icns"
cp "$ICONDIR/mark.png" "$APP/Contents/Resources/mark.png"
cp "$REPO_ROOT/target/$CARGO_PROFILE/secretctl" "$APP/Contents/Resources/bin/secretctl"
cp "$REPO_ROOT/target/$CARGO_PROFILE/secretctld" "$APP/Contents/Resources/bin/secretctld"
cp "$REPO_ROOT/target/$CARGO_PROFILE/secretctl-native-host" "$APP/Contents/Resources/bin/secretctl-native-host"
cp -R "$REPO_ROOT/extension/." "$APP/Contents/Resources/extension/"

# Localizations. SwiftUI resolves `Text("…")` against Bundle.main, so the
# .lproj directories have to sit in the bundle itself rather than in a SwiftPM
# resource bundle beside it.
python3 "$ROOT/Tools/localize/extract.py" >/dev/null
for LPROJ in "$ROOT"/Resources/*.lproj; do
    [ -d "$LPROJ" ] || continue
    cp -R "$LPROJ" "$APP/Contents/Resources/"
done

# Pick the strongest identity available, unless one was named explicitly.
#
#   Developer ID Application — distributable and notarizable.
#   Apple Development       — local only, but *stable*, which is what stops the
#                             Keychain re-prompting after every rebuild.
#   ad-hoc                  — works, re-prompts every build.
IDENTITY="${SECRETCTL_SIGN_IDENTITY:-}"
if [ -z "$IDENTITY" ]; then
    IDENTITY="$(security find-identity -v -p codesigning 2>/dev/null \
        | grep "Developer ID Application" | head -1 \
        | sed -E 's/.*"(.*)"$/\1/' || true)"
fi
if [ -z "$IDENTITY" ]; then
    IDENTITY="$(security find-identity -v -p codesigning 2>/dev/null \
        | grep "Apple Development" | head -1 \
        | sed -E 's/.*"(.*)"$/\1/' || true)"
    if [ -n "$IDENTITY" ]; then
        echo "    note: signing with a development identity — stable enough to stop"
        echo "          the Keychain re-prompting, but not notarizable. A Developer ID"
        echo "          Application certificate is needed to distribute this."
    fi
fi
IDENTITY="${IDENTITY:--}"

if [ "$IDENTITY" = "-" ]; then
    echo "==> Signing (ad-hoc — expect a Keychain prompt after each rebuild)"
    TIMESTAMP="--timestamp=none"
else
    echo "==> Signing as $IDENTITY"
    # A development certificate has no timestamping service behind it.
    case "$IDENTITY" in
        "Developer ID"*) TIMESTAMP="--timestamp" ;;
        *) TIMESTAMP="--timestamp=none" ;;
    esac
fi

# --options runtime enables the hardened runtime, which notarization requires.
# The entitlements file takes no exceptions to it; see its comments.
codesign --force --deep --sign "$IDENTITY" \
    --options runtime \
    $TIMESTAMP \
    --entitlements "$ROOT/Resources/secretctl.entitlements" \
    --identifier com.secretctl.menubar \
    "$APP" 2>&1 | sed 's/^/    /'

echo "==> Verifying"
codesign --verify --strict --verbose=2 "$APP" 2>&1 | sed 's/^/    /'

case "$IDENTITY" in
"Developer ID"*)
    echo "==> To distribute:"
    echo "    ditto -c -k --keepParent '$APP' build/secretctl.zip"
    echo "    xcrun notarytool submit build/secretctl.zip --keychain-profile <profile> --wait"
    echo "    xcrun stapler staple '$APP'"
    ;;
esac

echo "==> Done: $APP"
echo "    Run with: open '$APP'"
