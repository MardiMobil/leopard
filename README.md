# vt-search

Virustotal search on cli. Just add your Api key and use your Virustotal account on cli.

**MardiMobil** is a multi-source OSINT lookup tool for IPs, domains and file hashes.
It detects the input type, queries the selected sources in parallel and gives a
verdict per source plus one 0-100% malicious score. Works on Linux and Windows,
as a **CLI** (`mytool`) or a **browser GUI** (`mytool --gui`). Both share the same
code, so they always give the same results.

| # | Source | id | Key | Supports |
|---|--------|----|-----|----------|
| 1 | VirusTotal | `vt` | `VIRUSTOTAL_API_KEY` | IP, domain, hash |
| 2 | AbuseIPDB | `abuseipdb` | `ABUSEIPDB_API_KEY` | IP |
| 3 | AlienVault OTX | `otx` | `OTX_API_KEY` (optional) | IP, domain, hash |
| 4 | URLhaus (abuse.ch) | `urlhaus` | `URLHAUS_AUTH_KEY` | IPv4, domain, MD5/SHA-256 |
| 5 | Shodan InternetDB | `shodan` | none | IPv4 |
| 6 | bgp.he.net | `bgp` | none | IP, domain |

Sources whose key is missing are skipped with a hint; the rest still run.
IPv4 and IPv6 are supported, and defanged input (`1.2.3[.]4`, `hxxp://evil[.]com/x`) is cleaned automatically.

## Install

**Linux (Kali/Ubuntu)**
```bash
sudo bash install.sh
sudo nano /etc/mytool/.env        # add your keys
```

**Windows** (no admin needed)
```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
notepad $env:APPDATA\mytool\.env  # add your keys
```
Then open a new terminal and run `mytool`.

**Run without installing**
```bash
pip install -r requirements.txt
python mytool.py                  # reads .env next to the script
```

Free keys: [VirusTotal](https://www.virustotal.com/gui/join-us) ·
[AbuseIPDB](https://www.abuseipdb.com/register) ·
[OTX](https://otx.alienvault.com/) ·
[URLhaus / abuse.ch](https://auth.abuse.ch/)

## Usage

```bash
mytool                                  # interactive menu ('save out.csv' exports results)
mytool 8.8.8.8 example.com              # look targets up directly
mytool 1.2.3[.]4 -s vt,abuseipdb        # only some sources (ids or menu numbers)
mytool -f iocs.txt -o report.csv        # bulk lookup from a file, save as CSV
mytool -f iocs.txt -o report.json       # ... or as JSON
mytool -f iocs.txt --delay 15           # stay under free VirusTotal limits (4/min)
mytool --list-sources                   # which keys are set, where the .env is
```

Target files take one IP / domain / hash per line; blank lines and lines starting with `#` are ignored.
In bulk mode a summary with the score and worst verdict per target is printed at the end.

### Browser GUI

```bash
mytool --gui                    # opens http://127.0.0.1:8765 in your browser
mytool --gui --port 9000 --no-browser
python gui.py                   # same thing without installing
```

Paste targets (or load a .txt), tick sources and press **Analyze** (Ctrl+Enter).
Each target gets a score ring and a card per source; the results table links to
them and exports CSV/JSON. **API keys** opens a form that writes the same `.env`
as the CLI. Press Ctrl+C in the terminal to stop the server.

It only listens on 127.0.0.1 (not reachable from the network), checks the Host
header, and requires a per-run random token on every API call, so other websites
can't use it through your browser. Keys are never sent back to the page in full.

### API keys on start

Every start asks `Do you want to add or change any API keys? [Y/n]`.
Enter (yes) opens a small menu: pick a source number, paste the key (input is hidden)
and it is written to your `.env` (replaced if it exists, added if not). Enter on an
empty line finishes. `n` skips straight to the lookup.

- `mytool --keys` opens the same menu and exits.
- `--skip-keys` skips the question; it is also skipped automatically when input or
  output is piped, so scripts never hang.

### Malicious score (0-100%)

Every result starts with a big score box on the right side of the terminal.
Each source gives its own 0-100 estimate:

| Source | Score |
|--------|-------|
| VirusTotal | by malicious engines: 1 -> 22, 3 -> 53, 5 -> 71, 10 -> 92 (suspicious counts half) |
| AbuseIPDB | its abuse confidence score |
| URLhaus | 100 if a malware URL is online / hash is known, 60 if only past URLs |
| OTX | 50 if pulses name a malware family, else 0 |
| Shodan | 60 for compromised/malware/c2/botnet tags, 30 for tor, else 0 |
| bgp.he.net | not scored (routing data only) |

They are combined by trust weight (VT 1.0, AbuseIPDB 0.9, URLhaus 0.9, Shodan 0.5,
OTX 0.4) as independent evidence: `score = 1 - Π(1 - weight × source_score)`.
One strong source is enough for a high score and agreeing sources push it higher.
Levels: **0-24 LOW**, **25-59 MEDIUM**, **60-100 HIGH**. The score is also in the
summary table and in `.json` / `.csv` exports (`risk_score`, `risk_level`).

## Where API keys are read from

1. `MYTOOL_ENV` environment variable (path to a .env file), if set
2. `/etc/mytool/.env` (Linux) or `%APPDATA%\mytool\.env` (Windows)
3. `.env` next to `mytool.py`

Plain environment variables fill in any key the file leaves empty.

## Security notes

- `.env` is git-ignored; never commit real keys. Installers create it as owner-only.
- Results from third parties are treated as untrusted: CSV cells that start with
  `=`, `+`, `-` or `@` are prefixed with `'` so spreadsheets don't run them as formulas.
- OTX pulse counts and Shodan data are shown as **INFO**, not as a malicious verdict:
  popular benign hosts appear in many OTX pulses.
