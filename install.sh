#!/usr/bin/env bash
#
# install.sh - Installs leopard (multi-source OSINT CLI) globally
#              on Kali/Ubuntu, and sets up a local .env for API keys.
#              On Windows use install.ps1 instead.
#
# Usage:
#   sudo bash install.sh
#
set -euo pipefail

TOOL_NAME="leopard"
SOURCE_FILE="leopard.py"
# The code (CLI, GUI and its web/ assets) lives in LIB_DIR; INSTALL_PATH is a
# small launcher so `leopard` and `leopard --gui` work from anywhere.
LIB_DIR="/usr/local/lib/${TOOL_NAME}"
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
# leopard is installed globally to /usr/local/bin, so its config lives in a
# fixed system location (/etc/leopard/.env) rather than "next to the script" —
# that way your keys persist and are found no matter where leopard is run from.
ENV_DIR="/etc/leopard"
ENV_PATH="${ENV_DIR}/.env"

mkdir -p "${ENV_DIR}"

# The tool used to be called 'mytool': move its keys and remove the old install.
OLD_ENV_PATH="/etc/mytool/.env"
if [[ -f "${OLD_ENV_PATH}" && ! -f "${ENV_PATH}" ]]; then
    mv "${OLD_ENV_PATH}" "${ENV_PATH}"
    sed -i 's/^\([[:space:]]*\)MYTOOL_/\1LEOPARD_/' "${ENV_PATH}"
    chmod 600 "${ENV_PATH}"
    rmdir /etc/mytool 2>/dev/null || true
    echo "[*] Moved your API keys from ${OLD_ENV_PATH} to ${ENV_PATH}."
fi
rm -rf /usr/local/lib/mytool
rm -f /usr/local/bin/mytool

if [[ ! -f "${ENV_PATH}" ]]; then
    echo "[*] Creating .env template at ${ENV_PATH}..."
    cat > "${ENV_PATH}" << 'EOF'
# Add your API keys below
VIRUSTOTAL_API_KEY=your_vt_api_key_here
ABUSEIPDB_API_KEY=your_abuseip_api_key_here
# Optional: OTX works without a key, a key raises the rate limit
OTX_API_KEY=your_otx_api_key_here
URLHAUS_AUTH_KEY=your_urlhaus_auth_key_here
EOF
    chmod 600 "${ENV_PATH}"
    echo "[+] .env created. Edit it with your real API keys (or run: sudo leopard --keys)."
else
    echo "[*] .env already exists at ${ENV_PATH} — leaving it untouched."
fi

# Also drop a .env template in the repo directory for convenience when
# running the script locally (e.g. `python3 leopard.py`) without installing.
LOCAL_ENV_PATH="${SCRIPT_DIR}/.env"
if [[ ! -f "${LOCAL_ENV_PATH}" ]]; then
    cp "${ENV_PATH}" "${LOCAL_ENV_PATH}" 2>/dev/null || cat > "${LOCAL_ENV_PATH}" << 'EOF'
# Add your API keys below
VIRUSTOTAL_API_KEY=your_vt_api_key_here
ABUSEIPDB_API_KEY=your_abuseip_api_key_here
# Optional: OTX works without a key, a key raises the rate limit
OTX_API_KEY=your_otx_api_key_here
URLHAUS_AUTH_KEY=your_urlhaus_auth_key_here
EOF
    chmod 600 "${LOCAL_ENV_PATH}"
fi

# --- Install the tool ------------------------------------------------------
echo "[*] Copying leopard.py, gui.py and web/ to ${LIB_DIR}..."
mkdir -p "${LIB_DIR}/web"
cp "${SRC_PATH}" "${SCRIPT_DIR}/gui.py" "${LIB_DIR}/"
cp -r "${SCRIPT_DIR}/web/." "${LIB_DIR}/web/"
chmod -R a+rX "${LIB_DIR}"

# Small launcher so `leopard` works from anywhere.
cat > "${INSTALL_PATH}" << EOF
#!/bin/sh
exec python3 "${LIB_DIR}/leopard.py" "\$@"
EOF
chmod 755 "${INSTALL_PATH}"

echo ""
echo "[+] Installation complete!"
echo "[+] Edit your API keys here: ${ENV_PATH}"
echo "[+] Run the tool from anywhere by typing: ${TOOL_NAME}"
echo "[+] Browser interface: ${TOOL_NAME} --gui"
echo ""
