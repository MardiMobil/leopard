#!/usr/bin/env bash
#
# install.sh - Installs mytool (VirusTotal CLI) globally on Kali/Ubuntu.
#
# Usage:
#   sudo bash install.sh
#
set -euo pipefail

TOOL_NAME="mytool"
SOURCE_FILE="mytool.py"
INSTALL_PATH="/usr/local/bin/${TOOL_NAME}"

# --- Must be run as root -----------------------------------------------
if [[ "${EUID}" -ne 0 ]]; then
    echo "[!] Please run this installer with sudo: sudo bash install.sh"
    exit 1
fi

# --- Confirm source file exists -----------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_PATH="${SCRIPT_DIR}/${SOURCE_FILE}"

if [[ ! -f "${SRC_PATH}" ]]; then
    echo "[!] Could not find ${SOURCE_FILE} in ${SCRIPT_DIR}"
    exit 1
fi

echo "[*] Installing dependencies..."

# --- Ensure python3 is available ----------------------------------------
if ! command -v python3 &>/dev/null; then
    echo "[*] python3 not found. Installing..."
    apt-get update -y
    apt-get install -y python3 python3-pip
fi

# --- Ensure pip3 is available --------------------------------------------
if ! command -v pip3 &>/dev/null; then
    echo "[*] pip3 not found. Installing..."
    apt-get update -y
    apt-get install -y python3-pip
fi

# --- Ensure the 'requests' library is installed --------------------------
if ! python3 -c "import requests" &>/dev/null; then
    echo "[*] Python 'requests' module not found. Installing..."
    # --break-system-packages handles PEP 668 externally-managed environments
    # (common on recent Kali/Ubuntu); fall back gracefully if unsupported.
    pip3 install --break-system-packages requests 2>/dev/null || \
        pip3 install requests || \
        apt-get install -y python3-requests
else
    echo "[*] 'requests' module already installed."
fi

# --- Install the tool ------------------------------------------------------
echo "[*] Copying ${SOURCE_FILE} to ${INSTALL_PATH}..."
cp "${SRC_PATH}" "${INSTALL_PATH}"
chmod +x "${INSTALL_PATH}"

echo ""
echo "[+] Installation complete!"
echo "[+] Run the tool from anywhere by typing: ${TOOL_NAME}"
echo ""
