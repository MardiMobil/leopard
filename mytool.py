#!/usr/bin/env python3
"""
MardiMobil - Multi-source OSINT CLI lookup tool.

Supports:
  - VirusTotal v3 REST API   (requires API key)
  - AbuseIPDB v2 REST API    (requires API key)
  - bgp.he.net public lookup (scraped, no key required)

Detects IPv4 / Domain / Hash input via regex and queries whichever
sources the user selected, in either API mode or no-API mode.
"""

import os
import re
import sys
import requests
from bs4 import BeautifulSoup

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


UA_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    )
}

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


def print_banner():
    clear_screen()
    leopard = r"""
          .------.
        _/  .  .  \_
       /  (  @  @  )  \
      |   \   __   /   |
      |   /'-.__.-'\   |
       \  \        /  /
        `-.________.-'
         / /|_/\_|\ \
        / /  ""''""  \ \
       (_/          \_)
"""
    print(f"{C.GREEN}{C.BOLD}{leopard}{C.RESET}")
    print(f"{C.CYAN}{'=' * 70}{C.RESET}")
    print(f"{C.MAGENTA}{C.BOLD}      M A R D I   M O B I L   -   OSINT MULTI-SOURCE CLI{C.RESET}")
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


def prompt_api_keys(mode: str, sources: set) -> dict:
    keys = {}
    if mode != "1":
        return keys
    if "1" in sources:
        keys["vt"] = input("Please enter your VirusTotal API key: ").strip()
    if "2" in sources:
        keys["abuseipdb"] = input("Please enter your AbuseIPDB API key: ").strip()
    # bgp.he.net never requires a key
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
    headers = {**UA_HEADERS, "x-apikey": api_key}

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
    headers = {**UA_HEADERS, "Key": api_key, "Accept": "application/json"}
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
        resp = requests.get(url, headers=UA_HEADERS, timeout=15)
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


def print_bgp_summary(html: str, value: str):
    print(f"{C.BLUE}{C.BOLD}[ bgp.he.net ]{C.RESET}")
    try:
        soup = BeautifulSoup(html, "html.parser")

        prefix_table = soup.find("table", {"id": "table_prefixes"})
        if prefix_table:
            rows = prefix_table.find_all("tr")[1:4]  # show up to 3 rows
            if rows:
                print(f"  {C.CYAN}Announced Prefixes:{C.RESET}")
                for row in rows:
                    cols = [c.get_text(strip=True) for c in row.find_all("td")]
                    if cols:
                        print(f"    {' | '.join(cols)}")

        whois_pre = soup.find("pre", {"id": "whois"})
        if whois_pre:
            text = whois_pre.get_text()
            snippet_lines = [l for l in text.splitlines() if l.strip()][:6]
            if snippet_lines:
                print(f"  {C.CYAN}WHOIS Snippet:{C.RESET}")
                for line in snippet_lines:
                    print(f"    {C.DIM}{line.strip()}{C.RESET}")

        if not prefix_table and not whois_pre:
            print(f"  {C.YELLOW}No structured data found for '{value}'. "
                  f"The page layout may have changed.{C.RESET}")
    except Exception:
        print(f"  {C.YELLOW}Could not parse bgp.he.net page content.{C.RESET}")
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
    api_keys = prompt_api_keys(mode, sources)

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
