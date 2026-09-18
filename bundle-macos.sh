#!/bin/bash
# ============================================================================
#  Build a double-clickable Vusi.app for macOS (Apple Silicon / T2).
#  Run this on your Mac:   ./bundle-macos.sh          (all 3 attacks)
#                          ./bundle-macos.sh minimal  (no biased-nonce/GMP)
#  Result: Vusi.app in this folder — drag it to /Applications and double-click.
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"

MODE="${1:-full}"
APP="Vusi.app"
BIN_NAME="vusi-gui"

echo ">> [1/5] Building optimized release binary…"
if [ "$MODE" = "minimal" ]; then
  cargo build -p vusi-gui --release --no-default-features
else
  cargo build -p vusi-gui --release
fi

BIN="target/release/${BIN_NAME}"
[ -f "$BIN" ] || { echo "!! Build did not produce $BIN" >&2; exit 1; }

echo ">> [2/5] Assembling ${APP}…"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/Vusi"
chmod +x "$APP/Contents/MacOS/Vusi"

echo ">> [3/5] Building app icon…"
ICON_SRC="assets/icon-1024.png"
ICON_OK=0
if [ -f "$ICON_SRC" ] && command -v sips >/dev/null 2>&1 && command -v iconutil >/dev/null 2>&1; then
  ICONSET="$(mktemp -d)/Vusi.iconset"
  mkdir -p "$ICONSET"
  for sz in 16 32 64 128 256 512; do
    sips -z $sz $sz         "$ICON_SRC" --out "$ICONSET/icon_${sz}x${sz}.png"      >/dev/null
    sips -z $((sz*2)) $((sz*2)) "$ICON_SRC" --out "$ICONSET/icon_${sz}x${sz}@2x.png" >/dev/null
  done
  if iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/Vusi.icns" >/dev/null 2>&1; then
    ICON_OK=1
  fi
  rm -rf "$(dirname "$ICONSET")"
fi
[ "$ICON_OK" = 1 ] && echo "   icon: Vusi.icns embedded" || echo "   icon: skipped (sips/iconutil or PNG unavailable)"

echo ">> [4/5] Writing Info.plist…"
ICON_KEY=""
[ "$ICON_OK" = 1 ] && ICON_KEY='  <key>CFBundleIconFile</key>       <string>Vusi</string>'
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>            <string>Vusi</string>
  <key>CFBundleDisplayName</key>     <string>Vusi</string>
  <key>CFBundleIdentifier</key>      <string>dev.vusi.gui</string>
  <key>CFBundleVersion</key>         <string>0.2.0</string>
  <key>CFBundleShortVersionString</key> <string>0.2.0</string>
  <key>CFBundlePackageType</key>     <string>APPL</string>
  <key>CFBundleExecutable</key>      <string>Vusi</string>
${ICON_KEY}
  <key>LSMinimumSystemVersion</key>  <string>11.0</string>
  <key>NSHighResolutionCapable</key> <true/>
</dict>
</plist>
PLIST

echo ">> [5/5] Signing (ad-hoc) & clearing quarantine…"
# Ad-hoc signature + removing the quarantine attribute lets the app launch by
# double-click without the "unidentified developer / damaged" prompt.
codesign --force --deep --sign - "$APP" >/dev/null 2>&1 || echo "   (codesign unavailable — you may need to right-click → Open the first time)"
xattr -dr com.apple.quarantine "$APP" 2>/dev/null || true

echo ""
echo "✅ Done → $(pwd)/$APP"
echo "   Launch it:      open \"$APP\""
echo "   Install it:     drag Vusi.app into /Applications, then double-click"
