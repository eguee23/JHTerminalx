#!/usr/bin/env bash
# Crea JHTerminalx.app y un .dmg a partir de un binario ya compilado.
# Uso: packaging/macos/bundle.sh <binario> <versión> <directorio_salida>
set -euo pipefail

BIN="$1"
VERSION="$2"
OUT="$3"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

APP="$OUT/JHTerminalx.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/jhterminalx"
chmod +x "$APP/Contents/MacOS/jhterminalx"
cp "$ROOT/assets/icon.icns" "$APP/Contents/Resources/AppIcon.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>JHTerminalx</string>
  <key>CFBundleDisplayName</key><string>JHTerminalx</string>
  <key>CFBundleIdentifier</key><string>co.JH.JHTerminalx</string>
  <key>CFBundleExecutable</key><string>jhterminalx</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

# Firma ad hoc (sin certificado de Apple): evita el aviso de "dañado" en Apple Silicon.
codesign --force --deep --sign - "$APP"

DMG="$OUT/JHTerminalx-${VERSION}-macos-universal.dmg"
STAGE="$(mktemp -d)"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "JHTerminalx" -srcfolder "$STAGE" -ov -format UDZO "$DMG"
rm -rf "$STAGE"
echo "Creado $DMG"
