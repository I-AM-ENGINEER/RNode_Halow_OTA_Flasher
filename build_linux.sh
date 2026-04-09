#!/usr/bin/env bash
set -euo pipefail

# --------------------------------------------
# RNode-HaLow Flasher build for Linux
# Builds GUI and CLI single-file binaries via PyInstaller
# --------------------------------------------

cd "$(dirname "$0")"

APP_PY_GUI="rnode-halow-flasher-gui.py"
APP_PY_CLI="rnode-halow-flasher.py"
VENV_DIR=".venv"
DIST_DIR="dist"
BUILD_DIR="build"
SPEC_NAME_GUI="rnode-halow-flasher-gui"
SPEC_NAME_CLI="rnode-halow-flasher"

if [[ ! -f "$APP_PY_GUI" ]]; then
  echo "[!] '$APP_PY_GUI' not found in: $(pwd)"
  exit 1
fi

if [[ ! -f "$APP_PY_CLI" ]]; then
  echo "[!] '$APP_PY_CLI' not found in: $(pwd)"
  exit 1
fi

if [[ ! -d "modules" ]]; then
  echo "[!] 'modules/' folder not found in: $(pwd)"
  exit 1
fi

mkdir -p embedded_fw

PYTHON_BIN="python3"

# --- create venv (once) ---
if [[ ! -x "$VENV_DIR/bin/python" ]]; then
  echo "[*] Creating venv: $VENV_DIR"
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

VPY="$VENV_DIR/bin/python"
VPIP="$VENV_DIR/bin/pip"

echo "[*] Upgrading pip/setuptools/wheel..."
"$VPY" -m pip install --upgrade pip setuptools wheel

echo "[*] Installing build deps..."
"$VPIP" install --upgrade -r requirements.txt pyinstaller

# --- clean old outputs ---
rm -rf "$DIST_DIR" "$BUILD_DIR" "${SPEC_NAME_GUI}.spec" "${SPEC_NAME_CLI}.spec"

build_app() {
  local app_py="$1"
  local spec_name="$2"

  echo "[*] Building $spec_name..."
  "$VPY" -m PyInstaller \
    --noconfirm \
    --clean \
    --onefile \
    --name "$spec_name" \
    --add-data "modules:modules" \
    --add-data "embedded_fw:embedded_fw" \
    --collect-all scapy \
    --collect-all tftpy \
    --hidden-import tftpy \
    "$app_py"
}

# --- build ---
build_app "$APP_PY_GUI" "$SPEC_NAME_GUI"
build_app "$APP_PY_CLI" "$SPEC_NAME_CLI"

echo
echo "[OK] Done:"
echo "    $(pwd)/$DIST_DIR/$SPEC_NAME_GUI"
echo "    $(pwd)/$DIST_DIR/$SPEC_NAME_CLI"
echo
echo "Note:"
echo "  - Scapy raw send/sniff may require root/capabilities."
echo "  - If you want non-root run, you can do:"
echo "      sudo setcap cap_net_raw,cap_net_admin=eip ./$DIST_DIR/$SPEC_NAME_GUI"
echo "      sudo setcap cap_net_raw,cap_net_admin=eip ./$DIST_DIR/$SPEC_NAME_CLI"
echo
