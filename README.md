# vt-search

Check an IP address, domain or file hash against several threat-intelligence sources at once.
You get each source's verdict plus one **0–100% malicious score**.

- **Two interfaces:** terminal (`mytool`) and browser GUI (`mytool --gui`). Both run the same code, so results are identical.
- Runs on **Windows and Linux**.
- Bulk lookups, CSV/JSON export, defanged input (`1.2.3[.]4`, `hxxp://evil[.]com`) and IPv6.
- Personal: the banner, prompt and GUI header show **your own name** (see [Your display name](#your-display-name)).

---

## Contents

1. [Sources](#1-sources)
2. [Installation](#2-installation)
3. [API keys](#3-api-keys)
4. [Browser GUI](#4-browser-gui)
5. [Terminal (CLI)](#5-terminal-cli)
6. [Reading the results](#6-reading-the-results)
7. [Troubleshooting](#7-troubleshooting)
8. [Updating and uninstalling](#8-updating-and-uninstalling)
9. [Security](#9-security)
10. [All options](#10-all-options)

---

## 1. Sources

| # | Source | id | Key | Checks |
|---|--------|----|-----|--------|
| 1 | VirusTotal | `vt` | required | IP, domain, hash |
| 2 | AbuseIPDB | `abuseipdb` | required | IP |
| 3 | AlienVault OTX | `otx` | optional (works without one) | IP, domain, hash |
| 4 | URLhaus (abuse.ch) | `urlhaus` | required | IPv4, domain, MD5/SHA-256 |
| 5 | Shodan InternetDB | `shodan` | not needed | IPv4 |
| 6 | bgp.he.net | `bgp` | not needed | IP, domain |

A source without a key is **skipped**; the others still run.
So you can use OTX, Shodan and bgp.he.net without any keys at all.

---

## 2. Installation

### Requirements
- **Python 3.10 or newer**
- Internet access

### Windows

1. Install Python if you don't have it (in PowerShell):
   ```powershell
   winget install Python.Python.3.13
   ```
2. Get the repo: on GitHub click the green **Code** → **Download ZIP** and extract it.
   Or, with git:
   ```powershell
   git clone https://github.com/MardiMobil/vt-search.git
   ```
3. Go into the folder and run the installer (no admin rights needed):
   ```powershell
   cd vt-search
   powershell -ExecutionPolicy Bypass -File .\install.ps1
   ```
4. **Open a new terminal window** (the old one won't know the new command) and check:
   ```powershell
   mytool --list-sources
   ```

What the installer does:
- copies the tool to `%LOCALAPPDATA%\Programs\mytool` (with its own Python environment);
- adds the `mytool` command to your PATH;
- creates `%APPDATA%\mytool\.env` for API keys (readable only by your account).

### Linux (Kali, Ubuntu, Debian)

```bash
git clone https://github.com/MardiMobil/vt-search.git
cd vt-search
sudo bash install.sh
mytool --list-sources
```
Keys are stored in `/etc/mytool/.env` (readable only by root).

### Run without installing (any OS)

```bash
pip install -r requirements.txt
python mytool.py            # terminal
python mytool.py --gui      # browser
```
In this mode keys are read from a `.env` file next to `mytool.py`.

---

## 3. API keys

### Where to get them (all free)

| Source | Where |
|--------|-------|
| VirusTotal | [virustotal.com](https://www.virustotal.com/gui/join-us) → sign up → profile → **API Key** |
| AbuseIPDB | [abuseipdb.com/register](https://www.abuseipdb.com/register) → **Account** → **API** |
| AlienVault OTX | [otx.alienvault.com](https://otx.alienvault.com/) → **Settings** → **OTX Key** |
| URLhaus | [auth.abuse.ch](https://auth.abuse.ch/) → sign in → **Auth-Key** |

### 4 ways to add a key

**a) On every start (easiest).** When `mytool` starts it asks:
```
Do you want to add or change any API keys? [Y/n]:
```
- **Enter** → pick a number from the list → paste the key → **Enter**.
  What you type is **hidden** (like a password); that's expected.
- An empty **Enter** finishes.
- **`n`** → continue without touching the keys.

**b) Key menu only:**
```bash
mytool --keys
```

**c) In the browser:** `mytool --gui` → **Settings** (top right) → enter the key → **Save**.

**d) Edit the file by hand:**
- Windows: `notepad $env:APPDATA\mytool\.env`
- Linux: `sudo nano /etc/mytool/.env`

```
VIRUSTOTAL_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
OTX_API_KEY=your_key
URLHAUS_AUTH_KEY=your_key
```
No quotes needed, and no spaces around `=`.

Check with `mytool --list-sources`: sources with a key show **key OK**.

### Your display name

The CLI banner (`A L I   M A M M A D O V`), the prompt (`Ali Mammadov >`), the goodbye
message and the GUI header all show your name. By default it is your computer login name.
Change it any time:

- CLI: `mytool --name "Ali Mammadov"`
- GUI: **Settings** → **Display name** → **Save**
- or add `MYTOOL_NAME=Ali Mammadov` to your `.env`

Allowed: 1–32 letters, digits, spaces, `.`, `_` and `-`.

---

## 4. Browser GUI

```bash
mytool --gui
```
Your browser opens automatically (`http://127.0.0.1:8765`). Keep the terminal window open, the server runs there.
Press **Ctrl+C** in the terminal to stop it.

**Step by step:**
1. In **Targets**, enter one target per line, or use **Load from .txt**.
2. Tick the sources you want under **Sources** (your choice is remembered).
3. Click **Analyze** (or press **Ctrl+Enter**).
4. Each target gets a card:
   - on the left, a **score ring** with the malicious score (%);
   - on the right, one card per source with its result.
5. The **Results** table lists every target with its score. Click a target to jump to its card.
6. **Export CSV / Export JSON** downloads the results. **Clear** empties the page.

A free VirusTotal key allows 4 requests per minute. For many targets, set
**Delay between targets** to `15`.

---

## 5. Terminal (CLI)

### Interactive mode
```bash
mytool
```
1. Answer the API key question (see above).
2. Choose sources, e.g. `1,2,6`, or press **Enter** for all.
3. Type a target and press **Enter**. Repeat as often as you like.
4. Type `save results.csv` (or `.json`) to write everything so far to a file.
5. Type `exit` to quit.

### Direct commands

| Goal | Command |
|---|---|
| One target | `mytool 8.8.8.8` |
| Several targets | `mytool 8.8.8.8 google.com 44d88612fea8a8f36de82e1278abb02f` |
| Defanged input | `mytool "hxxp://evil[.]com/login"` |
| Only some sources | `mytool 1.1.1.1 -s vt,abuseipdb` (or by number: `-s 1,2`) |
| Bulk lookup from a file | `mytool -f iocs.txt` |
| Save results for Excel | `mytool -f iocs.txt -o report.csv` |
| Save results as JSON | `mytool -f iocs.txt -o report.json` |
| Respect VirusTotal limits | `mytool -f iocs.txt --delay 15` |
| Skip the key question | `mytool 8.8.8.8 --skip-keys` |

**Bulk file** (`iocs.txt`): one target per line; lines starting with `#` are ignored.
```
# incident 2026-10-20
8.8.8.8
1.1.1[.]1
evil-domain.com
44d88612fea8a8f36de82e1278abb02f
```
At the end you get a summary table with every target's score.

**For testing:** `44d88612fea8a8f36de82e1278abb02f` is the hash of the harmless **EICAR** test file.
Antivirus engines flag it as malicious, so it's a safe way to see a high score.

---

## 6. Reading the results

### Per-source verdicts

| Verdict | Meaning |
|---------|---------|
| 🔴 **MALICIOUS** | flagged as malicious |
| 🟡 **SUSPICIOUS** | suspicious |
| 🟢 **CLEAN** | nothing found |
| 🔵 **INFO** | information only, not a verdict (OTX, Shodan, bgp.he.net) |
| ⚪ **SKIPPED** | no key, or the source doesn't support this input type |
| ❗ **ERROR** | wrong key, rate limit or network error (the message says which) |

### Malicious score (0–100%)

| Score | Level |
|-------|-------|
| 0–24 | 🟢 **LOW** |
| 25–59 | 🟡 **MEDIUM** |
| 60–100 | 🔴 **HIGH** |

**How it's calculated:** each source gives its own score:

| Source | Score |
|--------|-------|
| VirusTotal | by number of malicious engines: 1 → 22, 3 → 53, 5 → 71, 10 → 92 (suspicious counts half) |
| AbuseIPDB | its abuse confidence score |
| URLhaus | active malware URL or known hash → 100, only past URLs → 60 |
| OTX | 50 if pulses name a malware family, otherwise 0 |
| Shodan | compromised/malware/c2/botnet tag → 60, tor → 30, otherwise 0 |
| bgp.he.net | not scored (routing data only) |

The scores are then combined by trust weight (VT 1.0, AbuseIPDB 0.9, URLhaus 0.9, Shodan 0.5, OTX 0.4)
as independent evidence: `score = 1 − Π(1 − weight × source_score)`.
One strong source is enough for a high score, and agreeing sources push it higher.

> The score helps you decide; it is not a final verdict. Always check the details in the source cards too.

---

## 7. Troubleshooting

| Problem | Fix |
|---------|-----|
| `mytool : The term 'mytool' is not recognized` | Open a **new** terminal after installing. |
| Typing `python` opens the Microsoft Store | Use `py` instead, or install with `winget install Python.Python.3.13`. |
| `install.ps1 cannot be loaded because running scripts is disabled` | Run exactly: `powershell -ExecutionPolicy Bypass -File .\install.ps1` |
| `rejected the API key (HTTP 401/403)` | The key is wrong or expired. Re-enter it with `mytool --keys`. |
| `rate limit exceeded` | The free quota is used up. Wait a bit, and use `--delay 15` for bulk lookups. |
| `Network error: could not reach Shodan InternetDB` | Your network (firewall/ISP) blocks Shodan. The other sources still work. |
| `request timed out` (OTX) | OTX is slow for popular indicators. Try again. |
| GUI: `Port 8765 is busy` | Not a problem; the tool picks a free port and prints the address in the terminal. |
| GUI: `Forbidden. Reload the page.` | The server was restarted. Reload the page (F5). |
| Linux: `Could not write /etc/mytool/.env` | Run `sudo mytool --keys`. |
| The key question every start is annoying | Answer `n`, or add `--skip-keys`. |

---

## 8. Updating and uninstalling

### Update
```bash
git pull                     # or download a new ZIP
```
Then run the installer again: `install.ps1` on Windows, `sudo bash install.sh` on Linux.
Your keys (`.env`) are left untouched.

### Uninstall
**Windows** (PowerShell):
```powershell
Remove-Item -Recurse "$env:LOCALAPPDATA\Programs\mytool", "$env:APPDATA\mytool"
```
Then remove the `...\Programs\mytool` entry from your user `Path` under
**Settings → System → About → Advanced system settings → Environment Variables**.

**Linux:**
```bash
sudo rm -rf /usr/local/lib/mytool /usr/local/bin/mytool /etc/mytool
```

---

## 9. Security

- **Keys:** stored only in the `.env` file. It is in `.gitignore`, so it never goes to GitHub.
  The installers create it readable by its owner only. Never share your keys.
- **GUI** listens on `127.0.0.1` only, so it isn't reachable from the network.
  - Every start creates a new random token, so other websites can't use the tool or change your keys through your browser.
  - The Host header is checked (protects against DNS rebinding).
  - Keys are never sent to the page in full, only a hint like `abcd...wxyz`.
- **Third-party data** is treated as untrusted:
  - the GUI never runs it as code;
  - CSV cells starting with `=`, `+`, `-` or `@` get a leading `'` so Excel doesn't run them as formulas.
- **Only public sources** are queried; the tool never contacts the target itself.

---

## 10. All options

```
mytool [targets ...] [options]

  -f, --file FILE       read targets from a file
  -s, --sources LIST    sources: vt,abuseipdb,otx,urlhaus,shodan,bgp or all (default)
  -o, --output FILE     write results to a .json or .csv file
  --delay SEC           seconds to wait between targets
  --list-sources        show sources and API key status
  --keys                open the key menu and exit
  --skip-keys           don't ask about API keys on start
  --name NAME           save your display name (banner, prompt, GUI)
  --gui                 open the browser interface
  --port PORT           GUI port (default 8765)
  --no-browser          start the GUI server without opening a browser
  --no-color            plain output without colors
  -h, --help            help
```

Key file lookup order: `MYTOOL_ENV` environment variable → system file
(`/etc/mytool/.env` or `%APPDATA%\mytool\.env`) → `.env` next to `mytool.py`.
