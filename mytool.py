#!/usr/bin/env python3
"""
MardiMobil - Multi-source OSINT CLI lookup tool.

Supports:
  - VirusTotal v3 REST API   (requires API key, loaded from .env)
  - AbuseIPDB v2 REST API    (requires API key, loaded from .env)
  - bgp.he.net public lookup (scraped, no key required)

Detects IPv4 / Domain / Hash input via regex and queries whichever
sources the user selected, in either API mode or no-API mode.
"""

import os
import re
import sys
import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# ANSI colors
# ---------------------------------------------------------------------------
class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


# Standard, honest browser-style headers. We identify as a normal client
# and handle blocks/CAPTCHAs gracefully rather than trying to evade them.
STANDARD_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# mytool.py runs from /usr/local/bin after a global install, so we can't
# rely on "the script's own directory" for a persistent .env (that would be
# /usr/local/bin, not your project folder, and any edits made in the repo
# would be silently ignored). Instead we use a single fixed system config
# location that install.sh also writes to, with a same-directory .env as
# a fallback for local/dev runs (e.g. `python3 mytool.py` from the repo).
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SYSTEM_ENV_PATH = "/etc/mytool/.env"
LOCAL_ENV_PATH = os.path.join(SCRIPT_DIR, ".env")

DEFAULT_VT_PLACEHOLDER = "your_vt_api_key_here"
DEFAULT_ABUSEIPDB_PLACEHOLDER = "your_abuseip_api_key_here"

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------
IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)
MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def detect_input_type(value: str) -> str:
    value = value.strip()
    if IPV4_RE.match(value):
        return "ip"
    if MD5_RE.match(value) or SHA1_RE.match(value) or SHA256_RE.match(value):
        return "hash"
    if DOMAIN_RE.match(value):
        return "domain"
    return "unknown"


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


LEOPARD_ART = r"""
                       _ __  _
                      ;'   '',)
                      /;6 , ;/
                     (Y)_:., |
                      `-', :; \
                        |;  ,.:\
                       /:.;   ;;)
                      |:;,.'|  :/
                     / |:  / ; /
                    /:;\ `| "//
                   /_,: | |./,|
                 _/: \.'|,|/| |
                /:.,:.|,|"| |:|
               /:;:|:,/;|:| |'|
          snd  |',:| \_ \ |_|;\_
              /;\_ /\_)) \_))\_))
             (;(________
"""


def print_banner():
    clear_screen()
    print(f"{C.MAGENTA}{C.BOLD}")
    print("  M A R D I   M O B I L")
    print("  OSINT Multi-Source CLI")
    print(f"{C.RESET}")
    print(f"{C.GREEN}{LEOPARD_ART}{C.RESET}")
    print(f"{C.CYAN}{'=' * 70}{C.RESET}\n")


# ---------------------------------------------------------------------------
# Menus
# ---------------------------------------------------------------------------
def prompt_auth_mode() -> str:
    print(f"{C.BOLD}Select search mode:{C.RESET}")
    print("  [1] Search using API keys")
    print("  [2] Search without API keys (Web Scraping / Public mode)")
    while True:
        choice = input(f"{C.YELLOW}> {C.RESET}").strip()
        if choice in ("1", "2"):
            return choice
        print(f"{C.RED}Invalid choice. Enter 1 or 2.{C.RESET}")


def prompt_sources() -> set:
    print(f"\n{C.BOLD}Which tools do you want to use? "
          f"(comma-separated, e.g. 1, 1,2, 1,3, 1,2,3):{C.RESET}")
    print("  [1] VirusTotal")
    print("  [2] AbuseIPDB")
    print("  [3] bgp.he.net")
    while True:
        raw = input(f"{C.YELLOW}> {C.RESET}").strip()
        parts = {p.strip() for p in raw.split(",") if p.strip()}
        if parts and parts.issubset({"1", "2", "3"}):
            return parts
        print(f"{C.RED}Invalid selection. Use numbers 1-3, comma-separated.{C.RESET}")


# ---------------------------------------------------------------------------
# .env key loading
# ---------------------------------------------------------------------------
def load_api_keys(mode: str, sources: set) -> dict:
    """
    Load API keys from the .env file in the script's directory.
    If a required key is missing or still the placeholder value,
    warn the user to edit .env and exit gracefully.
    """
    keys = {}
    if mode != "1":
        return keys

    # Prefer the system-wide .env (used by the globally installed tool);
    # fall back to a .env next to the script for local/dev runs.
    if os.path.isfile(SYSTEM_ENV_PATH):
        env_path = SYSTEM_ENV_PATH
    elif os.path.isfile(LOCAL_ENV_PATH):
        env_path = LOCAL_ENV_PATH
    else:
        print(f"{C.RED}[!] No .env file found at {SYSTEM_ENV_PATH} or {LOCAL_ENV_PATH}{C.RESET}")
        print(f"{C.YELLOW}    Run install.sh again, or create one manually with:{C.RESET}")
        print(f"{C.DIM}      VIRUSTOTAL_API_KEY=...\n      ABUSEIPDB_API_KEY=...{C.RESET}")
        sys.exit(1)

    # override=True ensures the .env file is always the source of truth,
    # even if a stale value happens to already be set in the shell environment.
    load_dotenv(dotenv_path=env_path, override=True)

    missing = []

    if "1" in sources:
        vt_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        if not vt_key or vt_key == DEFAULT_VT_PLACEHOLDER:
            missing.append("VIRUSTOTAL_API_KEY")
        else:
            keys["vt"] = vt_key

    if "2" in sources:
        abuse_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
        if not abuse_key or abuse_key == DEFAULT_ABUSEIPDB_PLACEHOLDER:
            missing.append("ABUSEIPDB_API_KEY")
        else:
            keys["abuseipdb"] = abuse_key

    if missing:
        print(f"{C.RED}[!] The following API key(s) are missing or still set to their "
              f"default placeholder in .env:{C.RESET}")
        for m in missing:
            print(f"    {C.YELLOW}- {m}{C.RESET}")
        print(f"\n{C.YELLOW}Please edit the .env file at:{C.RESET}")
        print(f"  {C.CYAN}{env_path}{C.RESET}")
        print(f"{C.YELLOW}and add your real API key(s), then rerun the tool.{C.RESET}")
        sys.exit(1)

    return keys


# ---------------------------------------------------------------------------
# VirusTotal (API mode only)
# ---------------------------------------------------------------------------
def vt_lookup_api(api_key: str, input_type: str, value: str):
    endpoints = {
        "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{value}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{value}",
        "hash": f"https://www.virustotal.com/api/v3/files/{value}",
    }
    url = endpoints[input_type]
    headers = {**STANDARD_HEADERS, "x-apikey": api_key}

    try:
        resp = requests.get(url, headers=headers, timeout=15)
    except requests.exceptions.ConnectionError:
        return False, "Network error: could not reach VirusTotal."
    except requests.exceptions.Timeout:
        return False, "VirusTotal request timed out."
    except requests.exceptions.RequestException as e:
        return False, f"VirusTotal error: {e}"

    if resp.status_code == 200:
        try:
            return True, resp.json()
        except ValueError:
            return False, "VirusTotal returned invalid JSON."
    if resp.status_code == 401:
        return False, "Invalid VirusTotal API key."
    if resp.status_code == 404:
        return False, f"VirusTotal: '{value}' not found."
    if resp.status_code == 429:
        return False, "VirusTotal rate limit exceeded."
    return False, f"VirusTotal unexpected error (HTTP {resp.status_code})."


def print_vt_summary(input_type: str, value: str, data: dict):
    try:
        attrs = data["data"]["attributes"]
    except (KeyError, TypeError):
        print(f"{C.RED}[VirusTotal] Unexpected response structure.{C.RESET}")
        return

    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    verdict = (
        f"{C.RED}{C.BOLD}MALICIOUS{C.RESET}" if malicious > 0 else
        f"{C.YELLOW}{C.BOLD}SUSPICIOUS{C.RESET}" if suspicious > 0 else
        f"{C.GREEN}{C.BOLD}CLEAN{C.RESET}"
    )

    print(f"{C.BLUE}{C.BOLD}[ VirusTotal ]{C.RESET}")
    print(f"  Verdict     : {verdict}")
    print(f"  {C.RED}Malicious   : {malicious}{C.RESET}")
    print(f"  {C.YELLOW}Suspicious  : {suspicious}{C.RESET}")
    print(f"  {C.GREEN}Harmless    : {harmless}{C.RESET}")
    print(f"  {C.CYAN}Undetected  : {undetected}{C.RESET}")

    if input_type == "ip":
        print(f"  Country     : {attrs.get('country', 'N/A')}")
        print(f"  AS Owner    : {attrs.get('as_owner', 'N/A')}")
    elif input_type == "domain":
        print(f"  Reputation  : {attrs.get('reputation', 'N/A')}")
    elif input_type == "hash":
        names = attrs.get("meaningful_name") or attrs.get("names", ["N/A"])
        if isinstance(names, list):
            names = names[0] if names else "N/A"
        print(f"  File Name   : {names}")
        print(f"  File Type   : {attrs.get('type_description', 'N/A')}")
    print()


# ---------------------------------------------------------------------------
# AbuseIPDB (API mode only — IP relevant; skip on hash/domain)
# ---------------------------------------------------------------------------
def abuseipdb_lookup_api(api_key: str, value: str):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {**STANDARD_HEADERS, "Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": value, "maxAgeInDays": 90}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=15)
    except requests.exceptions.ConnectionError:
        return False, "Network error: could not reach AbuseIPDB."
    except requests.exceptions.Timeout:
        return False, "AbuseIPDB request timed out."
    except requests.exceptions.RequestException as e:
        return False, f"AbuseIPDB error: {e}"

    if resp.status_code == 200:
        try:
            return True, resp.json()
        except ValueError:
            return False, "AbuseIPDB returned invalid JSON."
    if resp.status_code == 401:
        return False, "Invalid AbuseIPDB API key."
    if resp.status_code == 404:
        return False, f"AbuseIPDB: '{value}' not found."
    if resp.status_code == 429:
        return False, "AbuseIPDB rate limit exceeded."
    return False, f"AbuseIPDB unexpected error (HTTP {resp.status_code})."


def print_abuseipdb_summary(data: dict):
    try:
        d = data["data"]
    except (KeyError, TypeError):
        print(f"{C.RED}[AbuseIPDB] Unexpected response structure.{C.RESET}")
        return

    score = d.get("abuseConfidenceScore", 0)
    verdict = (
        f"{C.RED}{C.BOLD}HIGH RISK{C.RESET}" if score >= 75 else
        f"{C.YELLOW}{C.BOLD}MODERATE{C.RESET}" if score >= 25 else
        f"{C.GREEN}{C.BOLD}LOW RISK{C.RESET}"
    )

    print(f"{C.BLUE}{C.BOLD}[ AbuseIPDB ]{C.RESET}")
    print(f"  Verdict         : {verdict}")
    print(f"  Abuse Score     : {score}/100")
    print(f"  Total Reports   : {d.get('totalReports', 0)}")
    print(f"  Country         : {d.get('countryCode', 'N/A')}")
    print(f"  ISP             : {d.get('isp', 'N/A')}")
    print(f"  Domain          : {d.get('domain', 'N/A')}")
    print(f"  Is Whitelisted  : {d.get('isWhitelisted', False)}")
    print()


# ---------------------------------------------------------------------------
# bgp.he.net (scraped — public lookup page, no key required)
# ---------------------------------------------------------------------------
def bgp_he_net_lookup(value: str):
    url = f"https://bgp.he.net/ip/{value}" if IPV4_RE.match(value) else f"https://bgp.he.net/dns/{value}"

    try:
        resp = requests.get(url, headers=STANDARD_HEADERS, timeout=15)
    except requests.exceptions.ConnectionError:
        return False, "Network error: could not reach bgp.he.net."
    except requests.exceptions.Timeout:
        return False, "bgp.he.net request timed out."
    except requests.exceptions.RequestException as e:
        return False, f"bgp.he.net error: {e}"

    if resp.status_code == 403:
        return False, "bgp.he.net blocked this request (403 Forbidden). Try again later."
    if resp.status_code != 200:
        return False, f"bgp.he.net returned HTTP {resp.status_code}."

    return True, resp.text


def _extract_table_rows(soup, table_id, max_rows=5):
    """Grab up to max_rows of readable text from a table by id, if present."""
    table = soup.find("table", {"id": table_id})
    if not table:
        return []
    rows = table.find_all("tr")[1:max_rows + 1]
    out = []
    for row in rows:
        cols = [c.get_text(strip=True) for c in row.find_all(["td", "th"])]
        cols = [c for c in cols if c]
        if cols:
            out.append(" | ".join(cols))
    return out


def _extract_div_text(soup, div_id, max_lines=6):
    """Grab readable text lines from a div by id, if present."""
    div = soup.find("div", {"id": div_id})
    if not div:
        return []
    text = div.get_text(separator="\n")
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    return lines[:max_lines]


def _extract_asn_hits(soup, max_lines=6):
    """Fallback: scan all table cells for anything that looks like ASN data."""
    asn_re = re.compile(r"\bAS\d+\b")
    hits = []
    for cell in soup.find_all(["td", "th"]):
        text = cell.get_text(strip=True)
        if text and asn_re.search(text):
            hits.append(text)
        if len(hits) >= max_lines:
            break
    return hits


def _extract_main_content_snippet(soup, max_lines=10):
    """
    Last-resort fallback: pull raw visible text from the page's main content
    container (or body) and return a short, readable snippet so the user
    still gets *something* even if the known selectors have changed.
    """
    container = (
        soup.find("div", {"id": "content"})
        or soup.find("main")
        or soup.find("body")
    )
    if not container:
        return []

    # Strip script/style noise before extracting text
    for tag in container.find_all(["script", "style"]):
        tag.decompose()

    text = container.get_text(separator="\n")
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    # Filter out very short/nav-like fragments to keep the snippet useful
    lines = [l for l in lines if len(l) > 3]
    return lines[:max_lines]


def print_bgp_summary(html: str, value: str):
    print(f"{C.BLUE}{C.BOLD}[ bgp.he.net ]{C.RESET}")
    try:
        soup = BeautifulSoup(html, "html.parser")

        found_anything = False

        prefixes = _extract_table_rows(soup, "table_prefixes", max_rows=3)
        if prefixes:
            found_anything = True
            print(f"  {C.CYAN}Announced Prefixes:{C.RESET}")
            for line in prefixes:
                print(f"    {line}")

        whois_lines = _extract_div_text(soup, "whois", max_lines=6)
        if whois_lines:
            found_anything = True
            print(f"  {C.CYAN}WHOIS Snippet:{C.RESET}")
            for line in whois_lines:
                print(f"    {C.DIM}{line}{C.RESET}")

        dns_lines = _extract_div_text(soup, "dns", max_lines=6)
        if dns_lines:
            found_anything = True
            print(f"  {C.CYAN}DNS Records:{C.RESET}")
            for line in dns_lines:
                print(f"    {C.DIM}{line}{C.RESET}")

        if not found_anything:
            asn_hits = _extract_asn_hits(soup, max_lines=6)
            if asn_hits:
                found_anything = True
                print(f"  {C.CYAN}Routing / ASN Data:{C.RESET}")
                for line in asn_hits:
                    print(f"    {line}")

        if not found_anything:
            snippet = _extract_main_content_snippet(soup, max_lines=10)
            if snippet:
                print(f"  {C.YELLOW}Known selectors didn't match (page layout may have "
                      f"changed). Showing a raw content snippet instead:{C.RESET}")
                for line in snippet:
                    print(f"    {C.DIM}{line}{C.RESET}")
            else:
                print(f"  {C.YELLOW}No readable content could be extracted for "
                      f"'{value}'.{C.RESET}")
    except Exception as e:
        print(f"  {C.YELLOW}Could not parse bgp.he.net page content ({e}).{C.RESET}")
    print()


# ---------------------------------------------------------------------------
# Main search loop
# ---------------------------------------------------------------------------
def run_search(input_type: str, value: str, mode: str, sources: set, api_keys: dict):
    # --- VirusTotal ---
    if "1" in sources:
        if mode == "1":
            ok, result = vt_lookup_api(api_keys.get("vt", ""), input_type, value)
            if ok:
                print_vt_summary(input_type, value, result)
            else:
                print(f"{C.RED}[VirusTotal] {result}{C.RESET}\n")
        else:
            print(f"{C.YELLOW}[VirusTotal] Skipped — this source requires an API key "
                  f"(not available in no-API mode). Get a free key at "
                  f"virustotal.com and rerun in API mode.{C.RESET}\n")

    # --- AbuseIPDB ---
    if "2" in sources:
        if input_type == "hash":
            print(f"{C.YELLOW}[AbuseIPDB] Skipped — AbuseIPDB only supports "
                  f"IP address lookups, not file hashes.{C.RESET}\n")
        elif input_type == "domain":
            print(f"{C.YELLOW}[AbuseIPDB] Skipped — AbuseIPDB only supports "
                  f"IP address lookups, not domains.{C.RESET}\n")
        elif mode == "1":
            ok, result = abuseipdb_lookup_api(api_keys.get("abuseipdb", ""), value)
            if ok:
                print_abuseipdb_summary(result)
            else:
                print(f"{C.RED}[AbuseIPDB] {result}{C.RESET}\n")
        else:
            print(f"{C.YELLOW}[AbuseIPDB] Skipped — this source requires an API key "
                  f"(not available in no-API mode). Get a free key at "
                  f"abuseipdb.com and rerun in API mode.{C.RESET}\n")

    # --- bgp.he.net ---
    if "3" in sources:
        if input_type == "hash":
            print(f"{C.YELLOW}[bgp.he.net] Skipped — bgp.he.net only supports "
                  f"IP addresses and domains, not file hashes.{C.RESET}\n")
        else:
            ok, result = bgp_he_net_lookup(value)
            if ok:
                print_bgp_summary(result, value)
            else:
                print(f"{C.RED}[bgp.he.net] {result}{C.RESET}\n")


def main():
    print_banner()

    mode = prompt_auth_mode()
    sources = prompt_sources()
    api_keys = load_api_keys(mode, sources)

    print(f"\n{C.GREEN}Setup complete. Enter an IP, domain, or file hash to look up.{C.RESET}")
    print(f"{C.GREEN}Type 'exit' or 'quit' to close the tool.{C.RESET}\n")

    while True:
        try:
            user_input = input(f"{C.MAGENTA}{C.BOLD}MardiMobil > {C.RESET}").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{C.CYAN}Exiting MardiMobil. Goodbye!{C.RESET}")
            break

        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit"):
            print(f"{C.CYAN}Exiting MardiMobil. Goodbye!{C.RESET}")
            break

        input_type = detect_input_type(user_input)
        if input_type == "unknown":
            print(f"{C.RED}[!] Could not identify input as a valid IPv4 address, "
                  f"domain, or hash (MD5/SHA-1/SHA-256).{C.RESET}\n")
            continue

        print(f"{C.CYAN}[*] Detected type: {input_type.upper()} — querying selected sources...{C.RESET}\n")
        run_search(input_type, user_input, mode, sources, api_keys)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.CYAN}Interrupted. Exiting.{C.RESET}")
        sys.exit(0)
