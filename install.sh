#!/usr/bin/env bash
#
# install.sh - Installs MardiMobil (multi-source OSINT CLI) globally
#              on Kali/Ubuntu, and sets up a local .env for API keys.
#
# Usage:
#   sudo bash install.sh
#
set -euo pipefail

TOOL_NAME="mytool"
SOURCE_FILE="mytool.py"
INSTALL_PATH="/usr/local/bin/${TOOL_NAME}"
REQUIRED_PY_IMPORTS=("requests" "bs4" "dotenv")   # import names
PIP_PACKAGES=("requests" "beautifulsoup4" "python-dotenv")

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
echo "[*] Checking Python libraries: requests, beautifulsoup4, python-dotenv..."

MISSING=0
for imp in "${REQUIRED_PY_IMPORTS[@]}"; do
    if ! python3 -c "import ${imp}" &>/dev/null; then
        MISSING=1
        break
    fi
done

if [[ "${MISSING}" -eq 1 ]]; then
    echo "[*] Installing missing libraries: ${PIP_PACKAGES[*]}"
    # --break-system-packages handles PEP 668 externally-managed environments
    # (common on recent Kali/Ubuntu); fall back gracefully if unsupported.
    pip3 install --break-system-packages "${PIP_PACKAGES[@]}" 2>/dev/null || \
        pip3 install "${PIP_PACKAGES[@]}" || \
        apt-get install -y python3-requests python3-bs4 python3-dotenv
else
    echo "[*] All required Python libraries already installed."
fi

# --- Create the persistent, system-wide .env if it doesn't exist -----------
# mytool is installed globally to /usr/local/bin, so its config lives in a
# fixed system location (/etc/mytool/.env) rather than "next to the script" —
# that way your keys persist and are found no matter where mytool is run from.
ENV_DIR="/etc/mytool"
ENV_PATH="${ENV_DIR}/.env"

mkdir -p "${ENV_DIR}"

if [[ ! -f "${ENV_PATH}" ]]; then
    echo "[*] Creating .env template at ${ENV_PATH}..."
    cat > "${ENV_PATH}" << 'EOF'
# Add your API keys below
VIRUSTOTAL_API_KEY=your_vt_api_key_here
ABUSEIPDB_API_KEY=your_abuseip_api_key_here
EOF
    chmod 600 "${ENV_PATH}"
    echo "[+] .env created. Edit it with your real API keys before using Mode 1 (API search)."
else
    echo "[*] .env already exists at ${ENV_PATH} — leaving it untouched."
fi

# Also drop a .env template in the repo directory for convenience when
# running the script locally (e.g. `python3 mytool.py`) without installing.
LOCAL_ENV_PATH="${SCRIPT_DIR}/.env"
if [[ ! -f "${LOCAL_ENV_PATH}" ]]; then
    cp "${ENV_PATH}" "${LOCAL_ENV_PATH}" 2>/dev/null || cat > "${LOCAL_ENV_PATH}" << 'EOF'
# Add your API keys below
VIRUSTOTAL_API_KEY=your_vt_api_key_here
ABUSEIPDB_API_KEY=your_abuseip_api_key_here
EOF
fi

# --- Install the tool ------------------------------------------------------
echo "[*] Copying ${SOURCE_FILE} to ${INSTALL_PATH}..."
cp "${SRC_PATH}" "${INSTALL_PATH}"
chmod +x "${INSTALL_PATH}"

echo ""
echo "[+] Installation complete!"
echo "[+] Edit your API keys here: ${ENV_PATH}"
echo "[+] Run the tool from anywhere by typing: ${TOOL_NAME}"
echo ""
