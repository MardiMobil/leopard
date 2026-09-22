#!/usr/bin/env bash
#
# install.sh - Installs MardiMobil (multi-source OSINT CLI) globally
#              on Kali/Ubuntu.
#
# Usage:
#   sudo bash install.sh
#
set -euo pipefail

TOOL_NAME="mytool"
SOURCE_FILE="mytool.py"
INSTALL_PATH="/usr/local/bin/${TOOL_NAME}"
REQUIRED_PY_PACKAGES=("requests" "bs4")   # bs4 import name for beautifulsoup4

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

echo "[*] Checking system dependencies..."

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

# --- Ensure required Python libraries are installed -----------------------
echo "[*] Checking Python libraries: requests, beautifulsoup4..."

MISSING=()
for pkg in "${REQUIRED_PY_PACKAGES[@]}"; do
    if ! python3 -c "import ${pkg}" &>/dev/null; then
        MISSING+=("${pkg}")
    fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo "[*] Installing missing libraries: requests beautifulsoup4"
    # --break-system-packages handles PEP 668 externally-managed environments
    # (common on recent Kali/Ubuntu); fall back gracefully if unsupported.
    pip3 install --break-system-packages requests beautifulsoup4 2>/dev/null || \
        pip3 install requests beautifulsoup4 || \
        apt-get install -y python3-requests python3-bs4
else
    echo "[*] All required Python libraries already installed."
fi

# --- Install the tool ------------------------------------------------------
echo "[*] Copying ${SOURCE_FILE} to ${INSTALL_PATH}..."
cp "${SRC_PATH}" "${INSTALL_PATH}"
chmod +x "${INSTALL_PATH}"

echo ""
echo "[+] Installation complete!"
echo "[+] Run the tool from anywhere by typing: ${TOOL_NAME}"
echo ""
