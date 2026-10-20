#!/usr/bin/env python3
"""
vt-search - Multi-source OSINT CLI lookup tool.

The banner, prompt and GUI greet each user by their own display name:
the login name by default, or whatever `mytool --name "..."` saved.

Supports:
  - VirusTotal v3 REST API      (API key)   IPv4 / IPv6 / domain / hash
  - AbuseIPDB v2 REST API       (API key)   IPv4 / IPv6
  - AlienVault OTX              (API key)   IPv4 / IPv6 / domain / hash
  - URLhaus (abuse.ch)          (Auth-Key)  IPv4 / domain / hash
  - Shodan InternetDB           (no key)    IPv4
  - bgp.he.net public lookup    (scraped)   IPv4 / IPv6 / domain

Usage:
  mytool                              interactive menu
  mytool 8.8.8.8 example.com          look targets up directly
  mytool -f targets.txt -o out.csv    bulk lookup, save results
  mytool --list-sources               show sources and which keys are set

Detects the input type (defanged input such as 1.2.3[.]4 or hxxp://... is OK)
and queries the selected sources in parallel. Keyed sources without a key are
skipped with a hint instead of failing the whole run.
"""

from __future__ import annotations

import argparse
import csv
import getpass
import io
import ipaddress
import json
import math
import os
import re
import shutil
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone

import requests
from bs4 import BeautifulSoup
from dotenv import dotenv_values

TIMEOUT = 15          # seconds per HTTP request
MAX_RETRY_WAIT = 60   # cap for Retry-After when a source rate-limits us


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

    @classmethod
    def disable(cls):
        for name in ("RED", "GREEN", "YELLOW", "BLUE", "MAGENTA", "CYAN", "BOLD", "DIM", "RESET"):
            setattr(cls, name, "")


def setup_console(no_color: bool):
    # Never crash on characters the console code page can't show (old cmd.exe).
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    if no_color or os.getenv("NO_COLOR") or not sys.stdout.isatty():
        C.disable()
    elif os.name == "nt":
        os.system("")  # turns on ANSI escape processing in the Windows console


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

# After a global install mytool runs from /usr/local/lib/mytool (Linux) or
# %LOCALAPPDATA%\Programs\mytool (Windows), so "the script's own directory"
# is not a good home for API keys. We use one fixed per-system config file
# that the installers also write to, with a same-directory .env as a fallback
# for local/dev runs (e.g. `python mytool.py` from the repo). MYTOOL_ENV
# overrides both.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if os.name == "nt":
    SYSTEM_ENV_PATH = os.path.join(
        os.getenv("APPDATA") or os.path.expanduser("~"), "mytool", ".env")
else:
    SYSTEM_ENV_PATH = "/etc/mytool/.env"
LOCAL_ENV_PATH = os.path.join(SCRIPT_DIR, ".env")


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
IP = frozenset({"ipv4", "ipv6"})
ALL_KINDS = frozenset({"ipv4", "ipv6", "domain", "hash"})


@dataclass(frozen=True)
class Source:
    id: str
    name: str
    kinds: frozenset
    key_env: str | None = None
    key_optional: bool = False   # works without a key, just with lower limits
    weight: float = 0.0          # how much this source's score counts (0 = not scored)


# Order = menu numbers in interactive mode.
SOURCES = [
    Source("vt", "VirusTotal", ALL_KINDS, "VIRUSTOTAL_API_KEY", weight=1.0),
    Source("abuseipdb", "AbuseIPDB", IP, "ABUSEIPDB_API_KEY", weight=0.9),
    Source("otx", "AlienVault OTX", ALL_KINDS, "OTX_API_KEY", key_optional=True, weight=0.4),
    Source("urlhaus", "URLhaus", frozenset({"ipv4", "domain", "hash"}), "URLHAUS_AUTH_KEY",
           weight=0.9),
    Source("shodan", "Shodan InternetDB", frozenset({"ipv4"}), weight=0.5),
    Source("bgp", "bgp.he.net", IP | {"domain"}),
]
KEYED_SOURCES = [s for s in SOURCES if s.key_env]
SOURCE_BY_ID = {s.id: s for s in SOURCES}
SOURCE_ALIASES = {"virustotal": "vt", "abuse": "abuseipdb", "alienvault": "otx", "bgp.he.net": "bgp"}

KIND_LABEL = {"ipv4": "IPv4", "ipv6": "IPv6", "domain": "Domain", "hash": "Hash"}
KIND_PLURAL = {"ipv4": "IPv4 addresses", "ipv6": "IPv6 addresses",
               "domain": "domains", "hash": "file hashes"}


def describe_kinds(kinds) -> str:
    order = ["ip"] if IP <= kinds else [k for k in ("ipv4", "ipv6") if k in kinds]
    order += [k for k in ("domain", "hash") if k in kinds]
    names = ["IP addresses" if k == "ip" else KIND_PLURAL[k] for k in order]
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def parse_sources(spec: str) -> list[Source]:
    """'all' or a comma list of ids / menu numbers, e.g. 'vt,bgp' or '1,6'."""
    spec = (spec or "all").strip().lower()
    if spec in ("", "all"):
        return list(SOURCES)
    picked = []
    for part in (p.strip() for p in spec.split(",")):
        if not part:
            continue
        if part.isdigit() and 1 <= int(part) <= len(SOURCES):
            src = SOURCES[int(part) - 1]
        else:
            src = SOURCE_BY_ID.get(SOURCE_ALIASES.get(part, part))
        if not src:
            raise ValueError(f"Unknown source '{part}'. "
                             f"Use: {', '.join(s.id for s in SOURCES)} or all.")
        if src not in picked:
            picked.append(src)
    if not picked:
        raise ValueError("Select at least one source.")
    return picked


# ---------------------------------------------------------------------------
# .env key loading
# ---------------------------------------------------------------------------
def _is_placeholder(value: str) -> bool:
    return value.startswith("your_") and value.endswith("_here")


def find_env_file() -> str | None:
    """First existing .env of: $MYTOOL_ENV, the system config file, one next to the script."""
    return next((p for p in (os.getenv("MYTOOL_ENV"), SYSTEM_ENV_PATH, LOCAL_ENV_PATH)
                 if p and os.path.isfile(p)), None)


def load_api_keys() -> tuple[dict, str | None]:
    """
    Returns ({source_id: key}, env_path_used). Real environment variables
    fill in anything the file leaves empty. Placeholders count as missing.
    """
    env_path = find_env_file()
    file_values = dotenv_values(env_path) if env_path else {}

    keys = {}
    for src in SOURCES:
        if not src.key_env:
            continue
        value = (file_values.get(src.key_env) or os.getenv(src.key_env) or "").strip()
        if value and not _is_placeholder(value):
            keys[src.id] = value
    return keys, env_path


# Display name shown in the banner, prompt and GUI. Letters (any language),
# digits, spaces, '.', '_' and '-' only: it is printed straight to terminals.
NAME_ENV = "MYTOOL_NAME"
NAME_RE = re.compile(r"^[\w .-]{1,32}$")


def _login_name() -> str:
    try:
        name = getpass.getuser().strip()
    except Exception:  # no login name in some containers/services
        name = ""
    return name if NAME_RE.match(name) else "OSINT"


def load_display_name() -> str:
    env_path = find_env_file()
    value = ((dotenv_values(env_path).get(NAME_ENV) if env_path else None)
             or os.getenv(NAME_ENV) or "").strip()
    return value if NAME_RE.match(value) else _login_name()


def save_display_name(name: str) -> str:
    """Validate and store the display name in the .env; returns the file path."""
    name = name.strip()
    if not NAME_RE.match(name):
        raise ValueError("Use 1-32 letters, digits, spaces, '.', '_' or '-'.")
    path = find_env_file() or SYSTEM_ENV_PATH
    set_env_value(path, NAME_ENV, name)
    return path


def set_env_value(path: str, name: str, value: str):
    """Replace NAME=... in the .env file, or append it; other lines are kept."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    is_new = not os.path.isfile(path)
    lines = []
    if not is_new:
        with open(path, encoding="utf-8-sig") as f:
            lines = f.read().splitlines()
    pattern = re.compile(rf"^\s*(?:export\s+)?{re.escape(name)}\s*=")
    for i, line in enumerate(lines):
        if pattern.match(line):
            lines[i] = f"{name}={value}"
            break
    else:
        lines.append(f"{name}={value}")
    # Rewrite in place so the file keeps its owner-only permissions.
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    if is_new and os.name != "nt":
        os.chmod(path, 0o600)


def _mask(value: str) -> str:
    return f"{value[:4]}...{value[-4:]}" if len(value) >= 12 else "set"


def ask_yes_no(question: str, default: bool = True) -> bool:
    hint = "[Y/n]" if default else "[y/N]"
    while True:
        answer = read_line(f"{C.BOLD}{question}{C.RESET} {hint}: ").lower()
        if not answer:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print(f"{C.RED}Please answer y or n.{C.RESET}")


def edit_keys(keys: dict, env_path: str | None) -> tuple[dict, str | None]:
    """Menu to add/replace API keys in the .env file. Enter on its own = done."""
    path = env_path or SYSTEM_ENV_PATH
    changed = False
    while True:
        print(f"\n{C.BOLD}API keys{C.RESET} {C.DIM}({path}){C.RESET}")
        for i, src in enumerate(KEYED_SOURCES, 1):
            if src.id in keys:
                state = f"{C.GREEN}{_mask(keys[src.id])}{C.RESET}"
            else:
                state = f"{C.YELLOW}not set{' (optional)' if src.key_optional else ''}{C.RESET}"
            print(f"  [{i}] {src.name:<16} {C.DIM}{src.key_env:<20}{C.RESET} {state}")
        choice = read_line(f"{C.YELLOW}Which key to add/change? (number, Enter = done) > {C.RESET}")
        if not choice:
            break
        if not choice.isdigit() or not 1 <= int(choice) <= len(KEYED_SOURCES):
            print(f"{C.RED}Enter a number from 1 to {len(KEYED_SOURCES)}.{C.RESET}")
            continue

        src = KEYED_SOURCES[int(choice) - 1]
        value = getpass.getpass(f"New {src.name} key (typing is hidden, Enter = cancel): ")
        value = value.replace("﻿", "").strip().strip("'\"")
        if not value:
            print(f"{C.DIM}Cancelled.{C.RESET}")
            continue
        if any(ch.isspace() for ch in value) or "#" in value:
            print(f"{C.RED}That doesn't look like an API key (spaces or '#'). Not saved.{C.RESET}")
            continue
        try:
            set_env_value(path, src.key_env, value)
        except OSError as e:
            print(f"{C.RED}[!] Could not write {path}: {e.strerror}{C.RESET}")
            if os.name != "nt":
                print(f"{C.YELLOW}    Run with sudo, or point MYTOOL_ENV to a file you own.{C.RESET}")
            continue
        keys[src.id] = value
        changed = True
        print(f"{C.GREEN}[+] {src.key_env} saved.{C.RESET}")

    if changed:
        keys, env_path = load_api_keys()  # re-read so file precedence rules still apply
        print(f"{C.GREEN}[+] API keys updated.{C.RESET}")
    print()
    return keys, env_path


def maybe_edit_keys(keys: dict, env_path: str | None) -> tuple[dict, str | None]:
    if ask_yes_no("Do you want to add or change any API keys?"):
        return edit_keys(keys, env_path)
    print()
    return keys, env_path


# ---------------------------------------------------------------------------
# Input detection
# ---------------------------------------------------------------------------
HASH_RE = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", re.I)
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def normalize(raw: str) -> tuple[str, str]:
    """
    Refang and clean the input, then detect its type.
    Returns (value, kind) where kind is ipv4 | ipv6 | domain | hash |
    private | unknown.
    """
    s = raw.strip()
    for a, b in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("[:]", ":")):
        s = s.replace(a, b)
    s = re.sub(r"^hxxp", "http", s, flags=re.I)
    if "://" in s:                       # full URL -> host part
        s = s.split("://", 1)[1]
    s = re.split(r"[/?#]", s)[0]
    if s.startswith("[") and "]" in s:   # [ipv6]:port
        s = s[1:s.index("]")]
    elif s.count(":") == 1:              # host:port
        s = s.split(":")[0]
    s = s.rstrip(".")

    if HASH_RE.match(s):
        return s.lower(), "hash"
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        # A TLD is never all digits, so "999.1.1.1" is a bad IP, not a domain.
        if DOMAIN_RE.match(s) and not s.rsplit(".", 1)[-1].isdigit():
            return s.lower(), "domain"
        return s, "unknown"
    if not ip.is_global:
        return str(ip), "private"
    return str(ip), "ipv4" if ip.version == 4 else "ipv6"


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
class SourceError(Exception):
    """Expected failure (network, auth, rate limit...). Message is shown as-is."""


class NotFound(Exception):
    pass


def http(method: str, url: str, name: str, *, retry_429: bool = True, **kwargs) -> requests.Response:
    kwargs["headers"] = {**STANDARD_HEADERS, **kwargs.get("headers", {})}
    kwargs.setdefault("timeout", TIMEOUT)
    for attempt in range(2):
        try:
            resp = requests.request(method, url, **kwargs)
        except requests.exceptions.ConnectionError:
            raise SourceError(f"Network error: could not reach {name}.")
        except requests.exceptions.Timeout:
            raise SourceError(f"{name} request timed out.")
        except requests.exceptions.RequestException as e:
            raise SourceError(f"{name} error: {e}")
        if resp.status_code == 429 and retry_429 and attempt == 0:
            try:
                wait = int(resp.headers.get("Retry-After", 20))
            except ValueError:
                wait = 20
            time.sleep(min(max(wait, 1), MAX_RETRY_WAIT))
            continue
        return resp
    return resp


def check(resp: requests.Response, name: str, value: str) -> dict:
    """Map common HTTP failures to friendly errors and return the JSON body."""
    if resp.status_code in (401, 403):
        raise SourceError(f"{name} rejected the API key (HTTP {resp.status_code}).")
    if resp.status_code == 404:
        raise NotFound(f"'{value}' not found.")
    if resp.status_code == 429:
        raise SourceError(f"{name} rate limit exceeded. Try again later or use --delay.")
    if resp.status_code != 200:
        raise SourceError(f"{name} unexpected error (HTTP {resp.status_code}).")
    try:
        return resp.json()
    except ValueError:
        raise SourceError(f"{name} returned invalid JSON.")


def clean_fields(fields: dict) -> dict:
    return {k: v for k, v in fields.items() if v not in (None, "", [], {})}


# ---------------------------------------------------------------------------
# Lookups. Each returns (verdict, fields, score). verdict is one of
# malicious | suspicious | clean | info; score is this source's 0-100
# maliciousness estimate, or None when the source says nothing about threat.
# ---------------------------------------------------------------------------
def vt_lookup(key: str, value: str, kind: str):
    path = {"ipv4": "ip_addresses", "ipv6": "ip_addresses", "domain": "domains", "hash": "files"}[kind]
    resp = http("GET", f"https://www.virustotal.com/api/v3/{path}/{value}", "VirusTotal",
                headers={"x-apikey": key, "Accept": "application/json"})
    data = check(resp, "VirusTotal", value)
    try:
        attrs = data["data"]["attributes"]
    except (KeyError, TypeError):
        raise SourceError("VirusTotal returned an unexpected response structure.")

    stats = attrs.get("last_analysis_stats", {})
    malicious, suspicious = stats.get("malicious", 0), stats.get("suspicious", 0)
    verdict = "malicious" if malicious else "suspicious" if suspicious else "clean"
    fields = {
        "Malicious": malicious,
        "Suspicious": suspicious,
        "Harmless": stats.get("harmless", 0),
        "Undetected": stats.get("undetected", 0),
    }
    if kind in IP:
        fields.update({"Country": attrs.get("country"), "AS Owner": attrs.get("as_owner"),
                       "Network": attrs.get("network")})
    elif kind == "domain":
        cats = attrs.get("categories") or {}
        fields.update({"Reputation": attrs.get("reputation"), "Registrar": attrs.get("registrar"),
                       "Categories": ", ".join(sorted(set(cats.values())))})
    else:
        names = attrs.get("meaningful_name") or attrs.get("names") or []
        fields.update({"File Name": names[0] if isinstance(names, list) and names else names,
                       "File Type": attrs.get("type_description"), "Size": attrs.get("size"),
                       "Threat Label": (attrs.get("popular_threat_classification") or {})
                       .get("suggested_threat_label")})
    # Saturating curve: 1 engine ~22, 3 ~53, 5 ~71, 10 ~92.
    score = round(100 * (1 - math.exp(-(malicious + 0.5 * suspicious) / 4)))
    return verdict, clean_fields(fields), score


def abuseipdb_lookup(key: str, value: str, kind: str):
    resp = http("GET", "https://api.abuseipdb.com/api/v2/check", "AbuseIPDB",
                headers={"Key": key, "Accept": "application/json"},
                params={"ipAddress": value, "maxAgeInDays": 90})
    data = check(resp, "AbuseIPDB", value)
    d = data.get("data")
    if not isinstance(d, dict):
        raise SourceError("AbuseIPDB returned an unexpected response structure.")

    score = d.get("abuseConfidenceScore", 0)
    verdict = "malicious" if score >= 75 else "suspicious" if score >= 25 else "clean"
    return verdict, clean_fields({
        "Abuse Score": f"{score}/100",
        "Total Reports": d.get("totalReports", 0),
        "Last Reported": d.get("lastReportedAt"),
        "Country": d.get("countryCode"),
        "ISP": d.get("isp"),
        "Domain": d.get("domain"),
        "Usage Type": d.get("usageType"),
        "Tor Exit Node": d.get("isTor"),
        "Is Whitelisted": d.get("isWhitelisted"),
    }), score


def otx_lookup(key: str, value: str, kind: str):
    section = {"ipv4": "IPv4", "ipv6": "IPv6", "domain": "domain", "hash": "file"}[kind]
    headers = {"Accept": "application/json", **({"X-OTX-API-KEY": key} if key else {})}
    # OTX can take 15-25 s for popular indicators with thousands of pulses.
    resp = http("GET", f"https://otx.alienvault.com/api/v1/indicators/{section}/{value}/general",
                "AlienVault OTX", headers=headers, timeout=35)
    data = check(resp, "AlienVault OTX", value)

    info = data.get("pulse_info") or {}
    pulses = info.get("pulses") or []
    count = info.get("count", len(pulses))
    families = sorted({(m.get("display_name") if isinstance(m, dict) else str(m))
                       for p in pulses for m in (p.get("malware_families") or [])} - {None, ""})
    tags = sorted({t for p in pulses for t in (p.get("tags") or []) if t})
    # Pulses are community context, not a verdict: popular benign hosts such
    # as 8.8.8.8 appear in many of them. So OTX never says "malicious" alone
    # and only adds to the score when pulses name a malware family.
    return "info", clean_fields({
        "Pulses": count,
        "Malware Families": ", ".join(families[:8]),
        "Tags": ", ".join(tags[:10]),
        "Country": data.get("country_name"),
        "ASN": data.get("asn"),
        "Top Pulses": [p.get("name", "") for p in pulses[:3]],
    }), 50 if families else 0


def urlhaus_lookup(key: str, value: str, kind: str):
    if kind == "hash":
        field = {32: "md5_hash", 64: "sha256_hash"}.get(len(value))
        if not field:
            raise SourceError("URLhaus only supports MD5 and SHA-256 hashes, not SHA-1.")
        url, payload = "https://urlhaus-api.abuse.ch/v1/payload/", {field: value}
    else:
        url, payload = "https://urlhaus-api.abuse.ch/v1/host/", {"host": value}
    resp = http("POST", url, "URLhaus", headers={"Auth-Key": key, "Accept": "application/json"},
                data=payload)
    data = check(resp, "URLhaus", value)

    status = data.get("query_status")
    if status == "no_results":
        return "clean", {"Result": "No malware URLs or payloads recorded"}, 0
    if status != "ok":
        raise SourceError(f"URLhaus query failed ({status}).")

    if kind == "hash":
        return "malicious", clean_fields({
            "Signature": data.get("signature"),
            "File Type": data.get("file_type"),
            "Size": data.get("file_size"),
            "First Seen": data.get("firstseen"),
            "Seen on URLs": data.get("url_count"),
        }), 100

    urls = data.get("urls") or []
    online = [u for u in urls if u.get("url_status") == "online"]
    threats = sorted({u.get("threat") for u in urls if u.get("threat")})
    tags = sorted({t for u in urls for t in (u.get("tags") or [])})
    blacklists = {k: v for k, v in (data.get("blacklists") or {}).items() if v and v != "not listed"}
    verdict = "malicious" if online else "suspicious" if urls else "clean"
    return verdict, clean_fields({
        "Malware URLs": data.get("url_count", len(urls)),
        "Online Now": len(online),
        "Threats": ", ".join(threats),
        "Tags": ", ".join(tags[:10]),
        "Blacklists": ", ".join(f"{k}: {v}" for k, v in blacklists.items()),
        "First Seen": data.get("firstseen"),
        "Recent URLs": [u.get("url", "") for u in urls[:3]],
    }), {"malicious": 100, "suspicious": 60}.get(verdict, 0)


def shodan_lookup(key: str, value: str, kind: str):
    resp = http("GET", f"https://internetdb.shodan.io/{value}", "Shodan InternetDB",
                headers={"Accept": "application/json"})
    if resp.status_code == 404:
        raise NotFound("No open ports or vulnerabilities recorded for this IP.")
    data = check(resp, "Shodan InternetDB", value)
    vulns = data.get("vulns") or []
    tags = {t.lower() for t in data.get("tags") or []}
    # Open ports and CVEs are exposure, not maliciousness; only threat tags count.
    score = 60 if tags & {"compromised", "malware", "c2", "botnet"} else 30 if "tor" in tags else 0
    return "info", clean_fields({
        "Open Ports": ", ".join(str(p) for p in data.get("ports") or []),
        "Hostnames": ", ".join((data.get("hostnames") or [])[:5]),
        "Tags": ", ".join(data.get("tags") or []),
        "Known Vulns": (f"{len(vulns)} ({', '.join(vulns[:5])}{', ...' if len(vulns) > 5 else ''})"
                        if vulns else None),
        "CPEs": [c for c in (data.get("cpes") or [])[:5]],
    }), score


def _resolve_public_ips(domain: str) -> list[str]:
    """bgp.he.net's /dns/ page is filled in by JavaScript, so resolve locally."""
    try:
        infos = socket.getaddrinfo(domain, None)
    except (socket.gaierror, UnicodeError):
        raise NotFound("Domain did not resolve to an IP address.")
    ips = []
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0].split("%")[0])
        except ValueError:
            continue
        if ip.is_global and str(ip) not in ips:
            ips.append(str(ip))
    if not ips:
        raise NotFound("Domain did not resolve to a public IP address.")
    return sorted(ips, key=lambda a: ":" in a)  # IPv4 first


def _parse_ipinfo(soup):
    """Read the server-rendered 'IP Info' tab: hostname, announcements, notes."""
    box = soup.find("div", {"id": "ipinfo"})
    if not box:
        return None, [], []
    title = box.select_one(".preview-focus-title a")
    rows = []
    for tr in box.select("table tbody tr"):
        cells = [td.get_text(" ", strip=True) for td in tr.find_all("td")]
        if len(cells) >= 3 and cells[:3] not in rows:
            rows.append(cells[:3])
    notes = [t for t in (d.get_text(" ", strip=True) for d in box.select(".ip-preview-content")[1:])
             if t and not t.lower().startswith("loading")]
    return (title.get_text(strip=True) if title else None), rows, notes


def _prefix_len(prefix: str) -> int:
    try:
        return int(prefix.rsplit("/", 1)[1])
    except (IndexError, ValueError):
        return -1


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
    container (or body) so the user still gets *something* even if the known
    selectors have changed.
    """
    container = soup.find("div", {"id": "content"}) or soup.find("main") or soup.find("body")
    if not container:
        return []
    for tag in container.find_all(["script", "style"]):
        tag.decompose()
    lines = [l.strip() for l in container.get_text(separator="\n").splitlines() if l.strip()]
    return [l for l in lines if len(l) > 3 and not l.lower().startswith("loading")][:max_lines]


def bgp_lookup(key: str, value: str, kind: str):
    fields = {}
    ip = value
    if kind == "domain":
        ips = _resolve_public_ips(value)
        ip = ips[0]
        fields["Resolved IPs"] = ", ".join(ips[:4]) + (" ..." if len(ips) > 4 else "")

    resp = http("GET", f"https://bgp.he.net/ip/{ip}", "bgp.he.net", retry_429=False)
    if resp.status_code == 403:
        raise SourceError("bgp.he.net blocked this request (403 Forbidden). Try again later.")
    if resp.status_code != 200:
        raise SourceError(f"bgp.he.net returned HTTP {resp.status_code}.")

    soup = BeautifulSoup(resp.text, "html.parser")
    hostname, rows, notes = _parse_ipinfo(soup)
    if rows:
        asn, prefix, desc = max(rows, key=lambda r: _prefix_len(r[1]))  # most specific route
        fields.update({
            "Hostname": hostname,
            "Origin ASN": f"{asn} ({desc})" if desc else asn,
            "Prefix": prefix,
            "Announcements": [" | ".join(r) for r in rows] if len(rows) > 1 else [],
            "Notes": " ".join(notes),
        })
        return "info", clean_fields(fields), None

    hits =_extract_asn_hits(soup, max_lines=6)
    if hits:
        fields["Routing / ASN Data"] = hits
    elif notes:
        fields["Notes"] = " ".join(notes)
    else:
        snippet = _extract_main_content_snippet(soup, max_lines=10)
        if not snippet:
            raise NotFound(f"No routing data found for {ip}.")
        fields.update({"Note": "Known selectors didn't match (page layout may have changed).",
                       "Raw Snippet": snippet})
    return "info", clean_fields(fields), None


LOOKUPS = {
    "vt": vt_lookup,
    "abuseipdb": abuseipdb_lookup,
    "otx": otx_lookup,
    "urlhaus": urlhaus_lookup,
    "shodan": shodan_lookup,
    "bgp": bgp_lookup,
}


# ---------------------------------------------------------------------------
# Running lookups
# ---------------------------------------------------------------------------
def run_source(src: Source, value: str, kind: str, keys: dict) -> dict:
    """Run one source; every failure becomes a result instead of an exception."""
    result = {"source": src.id, "name": src.name, "status": "ok",
              "verdict": "", "score": None, "fields": {}, "message": ""}
    if kind not in src.kinds:
        result.update(status="skipped", message=f"{src.name} only supports {describe_kinds(src.kinds)}.")
        return result
    key = keys.get(src.id, "")
    if src.key_env and not key and not src.key_optional:
        result.update(status="skipped", message=f"No API key. Add {src.key_env} to your .env.")
        return result
    try:
        verdict, fields, score = LOOKUPS[src.id](key, value, kind)
        result.update(verdict=verdict, fields=fields, score=score)
    except NotFound as e:
        result.update(status="not_found", message=str(e))
    except SourceError as e:
        result.update(status="error", message=str(e))
    except Exception as e:  # one broken source must never kill the whole report
        result.update(status="error", message=f"Unexpected error ({e.__class__.__name__}: {e}).")
    return result


def lookup(raw: str, sources: list[Source], keys: dict) -> dict:
    value, kind = normalize(raw)
    report = {
        "target": raw.strip(),
        "value": value,
        "type": kind,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "results": [],
    }
    if kind == "unknown":
        report["error"] = ("Could not identify input as a valid IPv4/IPv6 address, "
                           "domain, or hash (MD5/SHA-1/SHA-256).")
    elif kind == "private":
        report["error"] = f"{value} is a private/reserved address; OSINT sources have no data for it."
    else:
        with ThreadPoolExecutor(max_workers=len(sources)) as pool:
            report["results"] = list(pool.map(lambda s: run_source(s, value, kind, keys), sources))
        report["score"] = overall_score(report["results"])
    return report


def overall_score(results: list[dict]) -> dict | None:
    """
    Combine per-source scores into one 0-100 maliciousness score.

    Each source's score is scaled by how much we trust it (Source.weight) and
    the results are merged like independent evidence ("noisy-OR"):
        score = 1 - (1 - w1*s1) * (1 - w2*s2) * ...
    So one strong source is enough for a high score, several medium ones
    reinforce each other, and all-clean stays at 0.
    Returns None when no scoring source answered.
    """
    scored = [(SOURCE_BY_ID[r["source"]].weight, r["score"]) for r in results
              if r["status"] == "ok" and r["score"] is not None and SOURCE_BY_ID[r["source"]].weight]
    if not scored:
        return None
    benign = 1.0
    for weight, score in scored:
        benign *= 1 - weight * min(max(score, 0), 100) / 100
    value = round((1 - benign) * 100)
    level = "HIGH" if value >= 60 else "MEDIUM" if value >= 25 else "LOW"
    return {"value": value, "level": level, "sources": len(scored)}


VERDICT_RANK = {"": 0, "info": 0, "clean": 1, "suspicious": 2, "malicious": 3}


def worst_verdict(report: dict) -> str:
    verdicts = [r["verdict"] for r in report["results"] if r["status"] == "ok"]
    return max(verdicts, key=VERDICT_RANK.__getitem__, default="")


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def verdict_text(verdict: str) -> str:
    style = {
        "malicious": (C.RED, "MALICIOUS"),
        "suspicious": (C.YELLOW, "SUSPICIOUS"),
        "clean": (C.GREEN, "CLEAN"),
        "info": (C.CYAN, "INFO"),
    }.get(verdict)
    return f"{style[0]}{C.BOLD}{style[1]}{C.RESET}" if style else "-"


def print_result(r: dict):
    name = r["name"]
    if r["status"] == "skipped":
        print(f"{C.YELLOW}[{name}] Skipped - {r['message']}{C.RESET}\n")
        return
    if r["status"] == "error":
        print(f"{C.RED}[{name}] {r['message']}{C.RESET}\n")
        return
    if r["status"] == "not_found":
        print(f"{C.YELLOW}[{name}] {r['message']}{C.RESET}\n")
        return

    label_color = {"Malicious": C.RED, "Suspicious": C.YELLOW,
                   "Harmless": C.GREEN, "Undetected": C.CYAN}
    print(f"{C.BLUE}{C.BOLD}[ {name} ]{C.RESET}")
    print(f"  {'Verdict':<16}: {verdict_text(r['verdict'])}")
    for label, value in r["fields"].items():
        if isinstance(value, list):
            print(f"  {C.CYAN}{label}:{C.RESET}")
            for line in value:
                print(f"    {C.DIM}{line}{C.RESET}")
        else:
            color = label_color.get(label, "")
            print(f"  {color}{label:<16}: {value}{C.RESET if color else ''}")
    print()


# 3x5 block font for the score box; each cell is drawn two characters wide.
BIG_GLYPHS = {
    "0": ["###", "# #", "# #", "# #", "###"],
    "1": [" # ", "## ", " # ", " # ", "###"],
    "2": ["###", "  #", "###", "#  ", "###"],
    "3": ["###", "  #", "###", "  #", "###"],
    "4": ["# #", "# #", "###", "  #", "  #"],
    "5": ["###", "#  ", "###", "  #", "###"],
    "6": ["###", "#  ", "###", "# #", "###"],
    "7": ["###", "  #", "  #", "  #", "  #"],
    "8": ["###", "# #", "###", "# #", "###"],
    "9": ["###", "# #", "###", "  #", "###"],
    "%": ["#   #", "   # ", "  #  ", " #   ", "#   #"],
    "-": ["   ", "   ", "###", "   ", "   "],
}
LEVEL_COLOR = {"HIGH": "RED", "MEDIUM": "YELLOW", "LOW": "GREEN"}


def _can_print(text: str) -> bool:
    try:
        text.encode(getattr(sys.stdout, "encoding", None) or "ascii")
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def score_box(score: dict | None) -> list[str]:
    """Big framed '87%' block, as plain lines (no colors)."""
    fancy = _can_print("█┌─┐│└┘·")
    block = "█" if fancy else "#"
    tl, tr, bl, br, h, v = ("┌", "┐", "└", "┘", "─", "│") if fancy else ("+", "+", "+", "+", "-", "|")
    dot = "·" if fancy else "-"

    text = f"{score['value']}%" if score else "--"
    rows = ["  ".join(BIG_GLYPHS[ch][i] for ch in text) for i in range(5)]
    rows = ["".join(block * 2 if c == "#" else "  " for c in row) for row in rows]
    title = "MALICIOUS SCORE"
    footer = (f"{score['level']} RISK {dot} {score['sources']} source(s)" if score
              else "no threat data")

    # Fixed minimum width so the box doesn't jump around between results.
    inner = max(34, len(title), len(footer), *(len(r) for r in rows)) + 4
    center = lambda s: f"{v}{s.center(inner)}{v}"
    return ([f"{tl}{h * inner}{tr}", center(title), center("")]
            + [center(r) for r in rows]
            + [center(""), center(footer), f"{bl}{h * inner}{br}"])


def print_score(score: dict | None):
    """Print the score box aligned to the right edge of the terminal."""
    lines = score_box(score)
    width = shutil.get_terminal_size((100, 24)).columns
    pad = " " * max(0, width - len(lines[0]) - 1)
    color = getattr(C, LEVEL_COLOR[score["level"]]) if score else C.DIM
    for line in lines:
        print(f"{pad}{color}{C.BOLD}{line}{C.RESET}")
    print()


def print_report(report: dict):
    if report.get("error"):
        print(f"{C.RED}[!] {report['error']}{C.RESET}\n")
        return
    print(f"{C.CYAN}[*] {report['value']} - detected type: {KIND_LABEL[report['type']]}"
          f" - queried {len(report['results'])} source(s){C.RESET}")
    print_score(report.get("score"))
    for r in report["results"]:
        print_result(r)


def score_text(score: dict | None) -> str:
    if not score:
        return f"{C.DIM}  --{C.RESET}"
    color = getattr(C, LEVEL_COLOR[score["level"]])
    return f"{color}{C.BOLD}{score['value']:>3}% {score['level']:<6}{C.RESET}"


def print_summary(reports: list[dict]):
    print(f"{C.CYAN}{'=' * 70}{C.RESET}")
    print(f"{C.BOLD}Summary ({len(reports)} targets){C.RESET}")
    width = min(max(len(r["value"]) for r in reports), 64)
    for rep in reports:
        if rep.get("error"):
            print(f"  {rep['value']:<{width}}  {C.RED}invalid{C.RESET}")
        else:
            print(f"  {rep['value']:<{width}}  {score_text(rep.get('score'))}  "
                  f"{verdict_text(worst_verdict(rep))}")
    print()


def _cell(value) -> str:
    """CSV cell; neutralise spreadsheet formulas since OSINT data is untrusted."""
    text = " | ".join(map(str, value)) if isinstance(value, list) else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def export_text(reports: list[dict], fmt: str) -> str:
    """Render reports as 'csv' or 'json' text (shared by the CLI and the GUI)."""
    if fmt == "json":
        return json.dumps(reports, indent=2, ensure_ascii=False)

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["timestamp", "target", "type", "risk_score", "risk_level",
                "source", "status", "verdict", "source_score", "details"])
    for rep in reports:
        if rep.get("error"):
            w.writerow([_cell(x) for x in (rep["timestamp"], rep["value"], rep["type"],
                                           "", "", "", "invalid", "", "", rep["error"])])
            continue
        score = rep.get("score") or {}
        for r in rep["results"]:
            details = r["message"] or "; ".join(
                f"{k}: {' | '.join(map(str, v)) if isinstance(v, list) else v}"
                for k, v in r["fields"].items())
            w.writerow([_cell(x) for x in (
                rep["timestamp"], rep["value"], rep["type"],
                score.get("value", ""), score.get("level", ""),
                r["name"], r["status"], r["verdict"],
                "" if r.get("score") is None else r["score"], details)])
    return buf.getvalue()


def write_output(path: str, reports: list[dict]):
    fmt = "csv" if path.lower().endswith(".csv") else "json"
    # utf-8-sig lets Excel open the CSV with the right encoding.
    with open(path, "w", newline="", encoding="utf-8-sig" if fmt == "csv" else "utf-8") as f:
        f.write(export_text(reports, fmt))
    print(f"{C.GREEN}[+] Saved {len(reports)} result(s) to {os.path.abspath(path)}{C.RESET}")


def check_output_path(path: str) -> str | None:
    if not path.lower().endswith((".json", ".csv")):
        return "Output file must end in .json or .csv"
    return None


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


def print_banner(name: str):
    clear_screen()
    print(f"{C.MAGENTA}{C.BOLD}")
    print("  " + "   ".join(" ".join(word.upper()) for word in name.split()))
    print("  OSINT Multi-Source CLI")
    print(f"{C.RESET}")
    print(f"{C.GREEN}{LEOPARD_ART}{C.RESET}")
    print(f"{C.CYAN}{'=' * 70}{C.RESET}\n")


def print_sources(keys: dict, env_path: str | None):
    print(f"{C.BOLD}Sources:{C.RESET}")
    for i, src in enumerate(SOURCES, 1):
        if not src.key_env:
            state = f"{C.GREEN}no key needed{C.RESET}"
        elif src.id in keys:
            state = f"{C.GREEN}key OK{C.RESET}"
        elif src.key_optional:
            state = f"{C.GREEN}works without key{C.RESET} {C.DIM}({src.key_env} raises limits){C.RESET}"
        else:
            state = f"{C.YELLOW}no key ({src.key_env}) - will be skipped{C.RESET}"
        print(f"  [{i}] {src.name:<18} {C.DIM}{src.id:<10}{C.RESET} {state}")
        print(f"      {C.DIM}{describe_kinds(src.kinds)}{C.RESET}")
    where = env_path or f"{SYSTEM_ENV_PATH} (not created yet)"
    print(f"\n{C.DIM}API keys file: {where}{C.RESET}\n")


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------
def prompt_sources(keys: dict, env_path: str | None) -> list[Source]:
    print_sources(keys, env_path)
    print(f"{C.BOLD}Which sources do you want to use? "
          f"(comma-separated numbers, e.g. 1,3,6 - Enter = all):{C.RESET}")
    while True:
        try:
            return parse_sources(read_line(f"{C.YELLOW}> {C.RESET}"))
        except ValueError as e:
            print(f"{C.RED}{e}{C.RESET}")


def read_line(prompt: str) -> str:
    # Piped input from PowerShell can start with a BOM; strip it.
    return input(prompt).replace("﻿", "").strip()


def run_batch(targets: list[str], sources: list[Source], keys: dict, delay: float) -> list[dict]:
    reports = []
    for i, target in enumerate(targets):
        if i and delay:
            time.sleep(delay)
        if len(targets) > 1:
            print(f"{C.MAGENTA}{C.BOLD}[{i + 1}/{len(targets)}] {target}{C.RESET}")
        report = lookup(target, sources, keys)
        print_report(report)
        reports.append(report)
    if len(targets) > 1:
        print_summary(reports)
    return reports


def interactive(keys: dict, env_path: str | None, ask_keys: bool, name: str) -> list[dict]:
    goodbye = f"{C.CYAN}Goodbye, {name}!{C.RESET}"
    print_banner(name)
    try:
        if ask_keys:
            keys, env_path = maybe_edit_keys(keys, env_path)
        sources = prompt_sources(keys, env_path)
    except (EOFError, KeyboardInterrupt):
        print(f"\n{goodbye}")
        return []

    print(f"\n{C.GREEN}Setup complete. Enter an IP, domain, or file hash to look up.{C.RESET}")
    print(f"{C.GREEN}Commands: 'save <file.json|file.csv>' to export, 'exit' or 'quit' to close.{C.RESET}\n")

    reports = []
    while True:
        try:
            user_input = read_line(f"{C.MAGENTA}{C.BOLD}{name} > {C.RESET}")
        except (EOFError, KeyboardInterrupt):
            print(f"\n{goodbye}")
            break

        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit"):
            print(goodbye)
            break
        if user_input.lower().startswith("save"):
            path = user_input[4:].strip()
            problem = "Usage: save results.json  (or .csv)" if not path else check_output_path(path)
            if problem:
                print(f"{C.RED}[!] {problem}{C.RESET}\n")
            elif not reports:
                print(f"{C.YELLOW}[!] Nothing to save yet.{C.RESET}\n")
            else:
                try:
                    write_output(path, reports)
                except OSError as e:
                    print(f"{C.RED}[!] Could not save: {e}{C.RESET}")
                print()
            continue

        report = lookup(user_input, sources, keys)
        print_report(report)
        if not report.get("error"):
            reports.append(report)
    return reports


def read_targets(path: str) -> list[str]:
    with open(path, encoding="utf-8-sig") as f:
        return [l.strip() for l in f if l.strip() and not l.lstrip().startswith("#")]


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="mytool",
        description="vt-search - multi-source OSINT lookup for IPs, domains and file hashes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  mytool                               interactive menu\n"
            "  mytool 8.8.8.8 example.com           look up targets\n"
            "  mytool 1.2.3[.]4 -s vt,abuseipdb     only some sources\n"
            "  mytool -f iocs.txt -o report.csv     bulk lookup, save as CSV\n"
            "  mytool -f iocs.txt --delay 15        respect free VirusTotal limits (4/min)\n"
            "  mytool --keys                        add or change API keys\n"
            "  mytool --gui                         open the browser interface\n"
            "  mytool --name \"Your Name\"            set the name shown in the banner and GUI\n"
            "\nOn start you are asked whether to change API keys (Enter = yes);\n"
            "--skip-keys skips that question. It is never asked when input is piped.\n"
            "\nsources: " + ", ".join(s.id for s in SOURCES)
        ),
    )
    p.add_argument("targets", nargs="*", help="IPs, domains or hashes (defanged input is OK)")
    p.add_argument("-f", "--file", help="read targets from a file, one per line ('#' starts a comment)")
    p.add_argument("-s", "--sources", default="all",
                   help="comma-separated source ids or 'all' (default: all)")
    p.add_argument("-o", "--output", help="save results to a .json or .csv file")
    p.add_argument("--delay", type=float, default=0, metavar="SEC",
                   help="seconds to wait between targets in bulk mode")
    p.add_argument("--list-sources", action="store_true", help="show sources and API key status")
    p.add_argument("--keys", action="store_true", help="add or change API keys, then exit")
    p.add_argument("--skip-keys", action="store_true",
                   help="don't ask about changing API keys on start")
    p.add_argument("--name", metavar="NAME",
                   help="save your display name (banner, prompt, GUI); default: your login name")
    p.add_argument("--gui", action="store_true", help="open the browser interface instead")
    p.add_argument("--port", type=int, default=8765, help="port for --gui (default: 8765)")
    p.add_argument("--no-browser", action="store_true",
                   help="with --gui: start the server but don't open a browser")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    args = p.parse_args(argv)

    if args.output and check_output_path(args.output):
        p.error(check_output_path(args.output))
    if args.delay < 0:
        p.error("--delay must be 0 or more")
    try:
        args.sources = parse_sources(args.sources)
    except ValueError as e:
        p.error(str(e))
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    setup_console(args.no_color)

    if args.name is not None:
        try:
            path = save_display_name(args.name)
        except ValueError as e:
            print(f"{C.RED}[!] Invalid name: {e}{C.RESET}")
            return 2
        except OSError as e:
            print(f"{C.RED}[!] Could not save the name: {e.strerror}{C.RESET}")
            return 1
        print(f"{C.GREEN}[+] Display name set to '{args.name.strip()}' ({path}).{C.RESET}")
        if not (args.targets or args.file or args.gui or args.keys or args.list_sources):
            return 0

    keys, env_path = load_api_keys()
    name = load_display_name()

    if args.list_sources:
        print_sources(keys, env_path)
        return 0
    if args.gui:
        import gui  # lives next to this file
        return gui.serve(args.port, open_browser=not args.no_browser)
    if args.keys:
        try:
            edit_keys(keys, env_path)
        except (EOFError, KeyboardInterrupt):
            print()
        return 0
    # Only ask a human: piped/redirected runs (scripts, schedulers) must not block.
    ask_keys = not args.skip_keys and sys.stdin.isatty() and sys.stdout.isatty()

    targets = list(args.targets)
    if args.file:
        try:
            targets += read_targets(args.file)
        except OSError as e:
            print(f"{C.RED}[!] Could not read {args.file}: {e.strerror}{C.RESET}")
            return 1
        if not targets:
            print(f"{C.YELLOW}[!] {args.file} has no targets.{C.RESET}")
            return 1
    targets = list(dict.fromkeys(targets))  # drop duplicates, keep order

    if targets:
        if ask_keys:
            try:
                keys, env_path = maybe_edit_keys(keys, env_path)
            except EOFError:
                pass
        reports = run_batch(targets, args.sources, keys, args.delay)
    else:
        reports = interactive(keys, env_path, ask_keys, name)

    if args.output and reports:
        try:
            write_output(args.output, reports)
        except OSError as e:
            print(f"{C.RED}[!] Could not save {args.output}: {e.strerror}{C.RESET}")
            return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{C.CYAN}Interrupted. Exiting.{C.RESET}")
        sys.exit(0)
