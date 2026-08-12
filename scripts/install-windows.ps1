#Requires -Version 5.1
<#
.SYNOPSIS
    Install chiralite on Windows (client mode only).

.DESCRIPTION
    What this script does:
      1. Locates a compatible Python interpreter (>= 3.10) via py launcher or PATH
      2. Builds xdelta3 from the required fork
      3. Installs chiralite via pip

    Windows limitations:
      - Server mode is NOT supported: tmpfs sandboxing and the clamd AV socket
        are Linux-only features.  Run the server on a Linux host.
      - The chiralite client runs without ClamAV; received files are written
        directly after rapidhash verification.
      - Filesystem events use ReadDirectoryChangesW via watchdog, which does
        not support recursive renames as reliably as inotify/FSEvents.

.PARAMETER Dev
    Install in editable mode (pip install -e .).

.PARAMETER SkipXdelta
    Skip building xdelta3 (use only if already installed from the fork).

.EXAMPLE
    .\scripts\install-windows.ps1
    .\scripts\install-windows.ps1 -Dev
#>

[CmdletBinding()]
param(
    [switch]$Dev,
    [switch]$SkipXdelta
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Split-Path -Parent $ScriptDir
$MinMinor  = 10  # requires Python >= 3.10

function Write-Log  { param([string]$Msg) Write-Host "[chiralite] $Msg" }
function Write-Fail { param([string]$Msg) Write-Error "[chiralite] ERROR: $Msg" }

# ── locate a compatible Python ─────────────────────────────────────────────────
# Tries the Python Launcher (py.exe) first — it enumerates all registered
# Python installs — then falls back to scanning PATH for executables whose
# name matches python3?.* (same regex discipline as the POSIX scripts).
# Sets script-scoped $Python and $Pip variables.

function Find-Python {
    $candidates = [System.Collections.Generic.List[string]]::new()

    # 1. Python Launcher: py --list emits lines like "  -3.12-64  ..."
    if (Get-Command py -ErrorAction SilentlyContinue) {
        $pyList = py --list 2>$null
        $versions = $pyList |
            Select-String -Pattern '^\s*-?(3\.\d+)' |
            ForEach-Object { $_.Matches[0].Groups[1].Value } |
            Sort-Object { [int]($_ -split '\.')[1] } -Descending
        foreach ($v in $versions) {
            $candidates.Add("py -$v")
        }
    }

    # 2. Executables on PATH matching python3.X or python3 or python
    $pathDirs = $env:PATH -split ';' | Where-Object { Test-Path $_ }
    $pathCandidates = $pathDirs |
        ForEach-Object { Get-ChildItem -Path $_ -Filter 'python*.exe' -ErrorAction SilentlyContinue } |
        Where-Object   { $_.Name -match '^python3?(\.\d+)?\.exe$' } |
        Sort-Object    { [int](([regex]'\.(\d+)\.exe').Match($_.Name).Groups[1].Value) } -Descending |
        Select-Object  -ExpandProperty FullName
    foreach ($p in $pathCandidates) { $candidates.Add($p) }

    foreach ($cmd in $candidates) {
        $parts = $cmd -split ' '
        try {
            $minor = & $parts[0] $parts[1..($parts.Length-1)] `
                -c "import sys; print(sys.version_info.minor)" 2>$null
            $major = & $parts[0] $parts[1..($parts.Length-1)] `
                -c "import sys; print(sys.version_info.major)" 2>$null
            if ([int]$major -eq 3 -and [int]$minor -ge $MinMinor) {
                $script:Python = $cmd
                $script:Pip    = "$cmd -m pip"
                Write-Log "Using Python: $(& $parts[0] $parts[1..($parts.Length-1)] --version 2>&1)"
                return $true
            }
        } catch { }
    }
    return $false
}

function Invoke-Python {
    param([string[]]$Args)
    $parts = $script:Python -split ' '
    & $parts[0] ($parts[1..($parts.Length-1)] + $Args)
}

function Invoke-Pip {
    param([string[]]$Args)
    Invoke-Python (@('-m', 'pip') + $Args)
}

# ── check prerequisites ────────────────────────────────────────────────────────

Write-Log "Checking prerequisites"

if (-not (Find-Python)) {
    Write-Fail @"
No compatible Python (>= 3.10) found.

Install Python 3.10 or later from https://www.python.org/downloads/ or via
winget:  winget install Python.Python.3.12

Then re-run this script.
"@
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Fail @"
git not found.

Install Git from https://git-scm.com/ or via winget:
    winget install Git.Git
Then re-run this script.
"@
}

# Visual C++ build tools are required to compile the C extensions.
$clPresent = Get-Command cl -ErrorAction SilentlyContinue
if (-not $clPresent) {
    Write-Log "WARNING: cl.exe not found on PATH."
    Write-Log "         C extensions (rapidhash, xdelta3) require Visual C++ Build Tools."
    Write-Log "         Install from: https://visualstudio.microsoft.com/visual-cpp-build-tools/"
    Write-Log "         Then open a 'Developer PowerShell for VS' and re-run this script."
    Write-Log "         Continuing — install may fail at the C compilation step."
}

# ── xdelta3 ────────────────────────────────────────────────────────────────────

if (-not $SkipXdelta) {
    $BuildDir = Join-Path $env:TEMP 'xdelta3-python-build'
    $RepoUrl  = 'https://github.com/samuelcolvin/xdelta3-python.git'

    Write-Log "Cloning xdelta3 fork into $BuildDir"
    if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
    git clone --depth=1 --branch master $RepoUrl $BuildDir

    # Patch: assert.h include and gnu11 flag (same patches as the POSIX script)
    $XdeltaC = Join-Path $BuildDir 'xdelta3\xdelta3.c'
    if (Test-Path $XdeltaC) {
        $src = Get-Content $XdeltaC -Raw
        if ($src -notmatch '#include <assert\.h>') {
            $src = "#include <assert.h>`n" + $src
            Set-Content $XdeltaC $src -NoNewline
            Write-Log "  added #include <assert.h>"
        }
    }
    $SetupCfg = Join-Path $BuildDir 'setup.cfg'
    if (Test-Path $SetupCfg) {
        $cfg = Get-Content $SetupCfg -Raw
        if ($cfg -notmatch 'std=gnu11') {
            Add-Content $SetupCfg "`n[build_ext]`nextra_compile_args = /std:c11"
            Write-Log "  added /std:c11 compile flag (MSVC equivalent of -std=gnu11)"
        }
    }

    Write-Log "Building and installing xdelta3"
    Invoke-Pip @('install', '--no-build-isolation', $BuildDir)

    Write-Log "Verifying xdelta3"
    Invoke-Python @('-c', "import xdelta3, importlib.metadata; print('xdelta3', importlib.metadata.version('xdelta3'), '— OK')")
}

# ── chiralite ─────────────────────────────────────────────────────────────────

Write-Log "Installing chiralite"
if ($Dev) {
    Invoke-Pip @('install', '-e', $RepoRoot)
} else {
    Invoke-Pip @('install', $RepoRoot)
}

# Build the rapidhash CFFI extension if not already compiled
try {
    Invoke-Python @('-c', 'import chiralite.hash') | Out-Null
} catch {
    Write-Log "  compiling rapidhash CFFI extension"
    Invoke-Python @('-m', 'chiralite._rapidhash_build')
}

# ── verify ─────────────────────────────────────────────────────────────────────

Write-Log "Verifying installation"
chiralite --version
Write-Log "chiralite is ready (client mode)."
Write-Log ""
Write-Log "Next steps:"
Write-Log "  1. Generate keys:  chiralite keygen --out-dir `$env:APPDATA\chiralite"
Write-Log "  2. Edit config:    `$env:APPDATA\chiralite\config.yaml  (see docs/install.md)"
Write-Log "  3. Start client:   chiralite start"
Write-Log ""
Write-Log "NOTE: The server must run on Linux. See docs/install.md for details."
