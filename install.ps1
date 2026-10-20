<#
install.ps1 - Installs leopard (multi-source OSINT CLI + browser GUI) for the
              current Windows user and sets up a private .env for API keys.

Usage (from the repo folder, no admin rights needed):
    powershell -ExecutionPolicy Bypass -File .\install.ps1

Installs to  %LOCALAPPDATA%\Programs\leopard  (own Python venv + leopard.exe)
Keys live in %APPDATA%\leopard\.env           (readable only by you)
Running it again updates the tool and keeps your keys.
#>
$ErrorActionPreference = 'Stop'

$ToolName   = 'leopard'
$RepoDir    = $PSScriptRoot
$SrcPath    = Join-Path $RepoDir 'leopard.py'
$ReqPath    = Join-Path $RepoDir 'requirements.txt'
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\$ToolName"
$VenvPython = Join-Path $InstallDir 'venv\Scripts\python.exe'
$EnvDir     = Join-Path $env:APPDATA $ToolName
$EnvPath    = Join-Path $EnvDir '.env'

# The tool used to be called 'mytool'; its files are migrated below.
$OldInstallDir = Join-Path $env:LOCALAPPDATA 'Programs\mytool'
$OldEnvPath    = Join-Path $env:APPDATA 'mytool\.env'

function Fail($msg) { Write-Host "[!] $msg" -ForegroundColor Red; exit 1 }

if (-not (Test-Path $SrcPath)) { Fail "Could not find leopard.py in $RepoDir" }

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
if ((Test-Path $OldEnvPath) -and -not (Test-Path $EnvPath)) {
    # Move (not copy) so the keys don't stay behind in the old folder.
    Move-Item $OldEnvPath $EnvPath
    (Get-Content $EnvPath) -replace '^(\s*)MYTOOL_', '$1LEOPARD_' | Set-Content $EnvPath -Encoding utf8
    # Only succeeds if the old folder is now empty; anything else stays put.
    Remove-Item (Split-Path $OldEnvPath) -ErrorAction SilentlyContinue
    Write-Host "[*] Moved your API keys from $OldEnvPath to $EnvPath."
}
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
    Write-Host "[+] .env created. Edit it with your real API keys." -ForegroundColor Green
} else {
    Write-Host "[*] .env already exists at $EnvPath - keeping your keys."
}
# Owner-only access, the Windows equivalent of chmod 600.
icacls $EnvPath /inheritance:r /grant:r "$($env:USERDOMAIN)\$($env:USERNAME):(R,W)" | Out-Null

# --- Install the tool -----------------------------------------------------------
Write-Host "[*] Copying leopard.py, gui.py and web\ to $InstallDir..."
Copy-Item $SrcPath (Join-Path $InstallDir 'leopard.py') -Force
Copy-Item (Join-Path $RepoDir 'gui.py') (Join-Path $InstallDir 'gui.py') -Force
New-Item -ItemType Directory -Force (Join-Path $InstallDir 'web') | Out-Null
Copy-Item (Join-Path $RepoDir 'web\*') (Join-Path $InstallDir 'web') -Recurse -Force

# --- 'leopard' command ----------------------------------------------------------
# A real leopard.exe (pip's console-script launcher) instead of a .cmd file:
# with a batch file, Windows asks "Terminate batch job (Y/N)?" after Ctrl+C.
Write-Host "[*] Building the leopard.exe launcher..."
$LauncherDir = Join-Path $InstallDir 'launcher'
New-Item -ItemType Directory -Force $LauncherDir | Out-Null
@"
import runpy
import sys

def main():
    sys.path.insert(0, r"$InstallDir")
    sys.argv[0] = r"$(Join-Path $InstallDir 'leopard.py')"
    runpy.run_path(sys.argv[0], run_name="__main__")
"@ | Set-Content (Join-Path $LauncherDir 'leopard_launcher.py') -Encoding ascii
@'
[build-system]
requires = ["setuptools>=61"]
build-backend = "setuptools.build_meta"

[project]
name = "leopard-launcher"
version = "1.0"

[project.scripts]
leopard = "leopard_launcher:main"

[tool.setuptools]
py-modules = ["leopard_launcher"]
'@ | Set-Content (Join-Path $LauncherDir 'pyproject.toml') -Encoding ascii
& $VenvPython -m pip install --disable-pip-version-check -q --force-reinstall --no-deps $LauncherDir
if ($LASTEXITCODE -ne 0) { Fail "Could not build the leopard.exe launcher." }
# Copy only the exe: putting venv\Scripts on PATH would also expose its python.exe.
Copy-Item (Join-Path $InstallDir 'venv\Scripts\leopard.exe') (Join-Path $InstallDir 'leopard.exe') -Force
Remove-Item (Join-Path $InstallDir 'leopard.cmd') -ErrorAction SilentlyContinue

# --- PATH: add the new folder, drop the old 'mytool' one -------------------------
$UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$Parts = @(($UserPath -split ';') | Where-Object { $_ -and $_ -ne $OldInstallDir })
if (-not ($Parts -contains $InstallDir)) {
    $Parts += $InstallDir
    Write-Host "[*] Added $InstallDir to your PATH (open a new terminal to use it)."
}
$NewPath = $Parts -join ';'
if ($NewPath -ne $UserPath) { [Environment]::SetEnvironmentVariable('Path', $NewPath, 'User') }

if (Test-Path $OldInstallDir) {
    Remove-Item -Recurse -Force $OldInstallDir
    Write-Host "[*] Removed the old 'mytool' installation."
}

Write-Host ""
Write-Host "[+] Installation complete!" -ForegroundColor Green
Write-Host "[+] Edit your API keys here: $EnvPath"
Write-Host "[+] Open a new terminal and run: $ToolName   (or: $ToolName --help)"
Write-Host "[+] Browser interface:          $ToolName --gui"
Write-Host ""
