<#
install.ps1 - Installs MardiMobil (multi-source OSINT CLI) for the current
              Windows user and sets up a private .env for API keys.

Usage (from the repo folder, no admin rights needed):
    powershell -ExecutionPolicy Bypass -File .\install.ps1

Installs to  %LOCALAPPDATA%\Programs\mytool  (own Python venv + mytool.cmd)
Keys live in %APPDATA%\mytool\.env           (readable only by you)
#>
$ErrorActionPreference = 'Stop'

$ToolName   = 'mytool'
$RepoDir    = $PSScriptRoot
$SrcPath    = Join-Path $RepoDir 'mytool.py'
$ReqPath    = Join-Path $RepoDir 'requirements.txt'
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\$ToolName"
$VenvPython = Join-Path $InstallDir 'venv\Scripts\python.exe'
$EnvDir     = Join-Path $env:APPDATA $ToolName
$EnvPath    = Join-Path $EnvDir '.env'

function Fail($msg) { Write-Host "[!] $msg" -ForegroundColor Red; exit 1 }

if (-not (Test-Path $SrcPath)) { Fail "Could not find mytool.py in $RepoDir" }

# --- Find Python 3.10+ ------------------------------------------------------
# 'py' (the official launcher) first: 'python' may be the Microsoft Store stub.
Write-Host "[*] Looking for Python 3.10+..."
$Python = $null
foreach ($c in @(@{ Exe = 'py'; Args = @('-3') }, @{ Exe = 'python'; Args = @() })) {
    if (-not (Get-Command $c.Exe -ErrorAction SilentlyContinue)) { continue }
    try {
        $ok = & $c.Exe @($c.Args + @('-c', 'import sys; print(sys.version_info >= (3, 10))')) 2>$null
    } catch { $ok = $null }
    if ($ok -eq 'True') { $Python = $c; break }
}
if (-not $Python) { Fail "Python 3.10+ not found. Install it with:  winget install Python.Python.3.13" }

# --- Private virtual environment + libraries ---------------------------------
New-Item -ItemType Directory -Force $InstallDir | Out-Null
if (-not (Test-Path $VenvPython)) {
    Write-Host "[*] Creating virtual environment in $InstallDir\venv..."
    & $Python.Exe @($Python.Args + @('-m', 'venv', (Join-Path $InstallDir 'venv')))
    if ($LASTEXITCODE -ne 0) { Fail "Could not create the virtual environment." }
}
Write-Host "[*] Installing Python libraries: requests, beautifulsoup4, python-dotenv..."
& $VenvPython -m pip install --disable-pip-version-check -q --upgrade -r $ReqPath
if ($LASTEXITCODE -ne 0) { Fail "pip install failed." }

# --- Persistent per-user .env --------------------------------------------------
New-Item -ItemType Directory -Force $EnvDir | Out-Null
if (-not (Test-Path $EnvPath)) {
    Write-Host "[*] Creating .env template at $EnvPath..."
    @(
        '# Add your API keys below'
        'VIRUSTOTAL_API_KEY=your_vt_api_key_here'
        'ABUSEIPDB_API_KEY=your_abuseip_api_key_here'
        '# Optional: OTX works without a key, a key raises the rate limit'
        'OTX_API_KEY=your_otx_api_key_here'
        'URLHAUS_AUTH_KEY=your_urlhaus_auth_key_here'
    ) | Set-Content -Path $EnvPath -Encoding ascii
    # Owner-only access, the Windows equivalent of chmod 600.
    icacls $EnvPath /inheritance:r /grant:r "$($env:USERDOMAIN)\$($env:USERNAME):(R,W)" | Out-Null
    Write-Host "[+] .env created. Edit it with your real API keys." -ForegroundColor Green
} else {
    Write-Host "[*] .env already exists at $EnvPath - leaving it untouched."
}

# --- Install the tool + a 'mytool' command on PATH ----------------------------
Write-Host "[*] Copying mytool.py, gui.py and web\ to $InstallDir..."
Copy-Item $SrcPath (Join-Path $InstallDir 'mytool.py') -Force
Copy-Item (Join-Path $RepoDir 'gui.py') (Join-Path $InstallDir 'gui.py') -Force
New-Item -ItemType Directory -Force (Join-Path $InstallDir 'web') | Out-Null
Copy-Item (Join-Path $RepoDir 'web\*') (Join-Path $InstallDir 'web') -Recurse -Force
@(
    '@echo off'
    "`"$VenvPython`" `"$(Join-Path $InstallDir 'mytool.py')`" %*"
) | Set-Content -Path (Join-Path $InstallDir 'mytool.cmd') -Encoding ascii

$UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not (($UserPath -split ';') -contains $InstallDir)) {
    [Environment]::SetEnvironmentVariable('Path', (@($UserPath, $InstallDir) -ne '' -join ';'), 'User')
    Write-Host "[*] Added $InstallDir to your PATH (open a new terminal to use it)."
}

Write-Host ""
Write-Host "[+] Installation complete!" -ForegroundColor Green
Write-Host "[+] Edit your API keys here: $EnvPath"
Write-Host "[+] Open a new terminal and run: $ToolName   (or: $ToolName --help)"
Write-Host "[+] Browser interface:          $ToolName --gui"
Write-Host ""
