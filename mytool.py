#!/usr/bin/env python3
"""
mytool - Interactive VirusTotal v3 API CLI lookup tool.

Detects whether input is an IPv4 address, a domain name, or a file hash
(MD5/SHA-1/SHA-256) using regex, queries the appropriate VirusTotal v3
endpoint, and prints a clean, colorized summary of the detection stats.
"""

import re
import sys
import requests

# ---------------------------------------------------------------------------
# ANSI colors (basic, no external deps required)
# ---------------------------------------------------------------------------
class Color:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


VT_BASE_URL = "https://www.virustotal.com/api/v3"

# ---------------------------------------------------------------------------
# Regex patterns for input detection
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


def detect_input_type(user_input: str) -> str:
    """Return 'ip', 'hash', 'domain', or 'unknown' based on regex matching."""
    value = user_input.strip()

    if IPV4_RE.match(value):
        return "ip"
    if MD5_RE.match(value) or SHA1_RE.match(value) or SHA256_RE.match(value):
        return "hash"
    if DOMAIN_RE.match(value):
        return "domain"
    return "unknown"


def build_url(input_type: str, value: str) -> str:
    endpoints = {
        "ip": f"{VT_BASE_URL}/ip_addresses/{value}",
        "domain": f"{VT_BASE_URL}/domains/{value}",
        "hash": f"{VT_BASE_URL}/files/{value}",
    }
    return endpoints[input_type]


def query_virustotal(api_key: str, input_type: str, value: str):
    """
    Query the VirusTotal v3 API. Returns (success: bool, data_or_message).
    Handles network errors, auth errors, and not-found responses gracefully.
    """
    url = build_url(input_type, value)
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=15)
    except requests.exceptions.ConnectionError:
        return False, "Network error: could not reach VirusTotal. Check your internet connection."
    except requests.exceptions.Timeout:
        return False, "Network error: the request to VirusTotal timed out."
    except requests.exceptions.RequestException as e:
        return False, f"Network error: {e}"

    if response.status_code == 200:
        try:
            return True, response.json()
        except ValueError:
            return False, "Received an invalid (non-JSON) response from VirusTotal."

    if response.status_code == 401:
        return False, "Invalid API key. Please restart the tool and enter a valid VirusTotal API key."
    if response.status_code == 404:
        return False, f"Not Found: '{value}' has no record in VirusTotal's database."
    if response.status_code == 429:
        return False, "Rate limit exceeded. Please wait a moment before trying again."

    return False, f"Unexpected error (HTTP {response.status_code}): {response.text[:200]}"


def print_banner():
    print(f"{Color.CYAN}{Color.BOLD}")
    print("=" * 55)
    print("   VT-Search | VirusTotal v3 API CLI Lookup Tool")
    print("=" * 55)
    print(f"{Color.RESET}")


def print_summary(input_type: str, value: str, data: dict):
    """Parse the VT JSON response and print a clean colorized summary."""
    try:
        attributes = data["data"]["attributes"]
    except (KeyError, TypeError):
        print(f"{Color.RED}[!] Unexpected response structure from VirusTotal.{Color.RESET}")
        return

    stats = attributes.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    timeout = stats.get("timeout", 0)
    total = malicious + suspicious + harmless + undetected + timeout

    # Overall verdict color
    if malicious > 0:
        verdict = f"{Color.RED}{Color.BOLD}MALICIOUS{Color.RESET}"
    elif suspicious > 0:
        verdict = f"{Color.YELLOW}{Color.BOLD}SUSPICIOUS{Color.RESET}"
    else:
        verdict = f"{Color.GREEN}{Color.BOLD}CLEAN{Color.RESET}"

    print(f"\n{Color.BLUE}{'-' * 55}{Color.RESET}")
    print(f"{Color.BOLD}Target:{Color.RESET}   {value}")
    print(f"{Color.BOLD}Type:{Color.RESET}     {input_type.upper()}")
    print(f"{Color.BOLD}Verdict:{Color.RESET}  {verdict}")
    print(f"{Color.BLUE}{'-' * 55}{Color.RESET}")

    print(f"{Color.BOLD}Detection Stats (out of {total} engines):{Color.RESET}")
    print(f"  {Color.RED}Malicious   : {malicious}{Color.RESET}")
    print(f"  {Color.YELLOW}Suspicious  : {suspicious}{Color.RESET}")
    print(f"  {Color.GREEN}Harmless    : {harmless}{Color.RESET}")
    print(f"  {Color.CYAN}Undetected  : {undetected}{Color.RESET}")
    if timeout:
        print(f"  {Color.MAGENTA}Timeout     : {timeout}{Color.RESET}")

    # Type-specific extra info
    if input_type == "ip":
        country = attributes.get("country", "N/A")
        owner = attributes.get("as_owner", "N/A")
        print(f"\n{Color.BOLD}Country:{Color.RESET}   {country}")
        print(f"{Color.BOLD}AS Owner:{Color.RESET}  {owner}")

    elif input_type == "domain":
        reputation = attributes.get("reputation", "N/A")
        categories = attributes.get("categories", {})
        print(f"\n{Color.BOLD}Reputation:{Color.RESET} {reputation}")
        if categories:
            cats = ", ".join(f"{k}: {v}" for k, v in list(categories.items())[:3])
            print(f"{Color.BOLD}Categories:{Color.RESET} {cats}")

    elif input_type == "hash":
        names = attributes.get("meaningful_name") or attributes.get("names", ["N/A"])
        if isinstance(names, list):
            names = names[0] if names else "N/A"
        file_type = attributes.get("type_description", "N/A")
        size = attributes.get("size", "N/A")
        sha256 = attributes.get("sha256", "N/A")
        print(f"\n{Color.BOLD}File Name:{Color.RESET}  {names}")
        print(f"{Color.BOLD}File Type:{Color.RESET}  {file_type}")
        print(f"{Color.BOLD}Size:{Color.RESET}       {size} bytes")
        print(f"{Color.BOLD}SHA256:{Color.RESET}     {sha256}")

    print(f"{Color.BLUE}{'-' * 55}{Color.RESET}\n")


def get_api_key() -> str:
    while True:
        api_key = input("Please enter your VirusTotal API key: ").strip()
        if api_key:
            return api_key
        print(f"{Color.YELLOW}API key cannot be empty. Please try again.{Color.RESET}")


def main():
    print_banner()
    api_key = get_api_key()

    print(f"\n{Color.GREEN}Ready. Enter an IP, domain, or file hash to look up.{Color.RESET}")
    print(f"{Color.GREEN}Type 'exit' or 'quit' to close the tool.{Color.RESET}\n")

    while True:
        try:
            user_input = input(f"{Color.MAGENTA}{Color.BOLD}VT-Search > {Color.RESET}").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{Color.CYAN}Exiting VT-Search. Goodbye!{Color.RESET}")
            break

        if not user_input:
            continue

        if user_input.lower() in ("exit", "quit"):
            print(f"{Color.CYAN}Exiting VT-Search. Goodbye!{Color.RESET}")
            break

        input_type = detect_input_type(user_input)

        if input_type == "unknown":
            print(f"{Color.RED}[!] Could not identify input as a valid IPv4 address, "
                  f"domain, or hash (MD5/SHA-1/SHA-256). Please try again.{Color.RESET}\n")
            continue

        print(f"{Color.CYAN}[*] Detected type: {input_type.upper()} — querying VirusTotal...{Color.RESET}")

        success, result = query_virustotal(api_key, input_type, user_input)

        if success:
            print_summary(input_type, user_input, result)
        else:
            print(f"{Color.RED}[!] {result}{Color.RESET}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Color.CYAN}Interrupted. Exiting.{Color.RESET}")
        sys.exit(0)
