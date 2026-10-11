#Requires -Version 5.1
<#
.SYNOPSIS
    Dev harness for install.ps1's in-distro setup -- NOT needed to install
    Chimera. It exists so we can iterate on the setup script without paying
    the ~200-package download on every test.

.DESCRIPTION
    Three tiers, cheapest first:

      Tier 3 (seconds, no distro needed)  -Show
          Extracts the assembled $setupScript / $smokeScript straight from
          install.ps1 (via AST, so it is the real shipped code, never a
          hand-copy) and prints them. Catches wsl.conf section mistakes,
          placeholder leaks, PowerShell interpolation bugs.

      Tier 1 (fast, reuses a live distro)  default
          Ensures a throwaway $DistroName exists (reuses it if present),
          deletes the test user so setup is re-runnable, then runs the
          real setup + smoke scripts inside it. Packages already installed
          resolve in seconds.

      Tier 2 (slow, cold)                  -Fresh
          Unregisters and re-imports the distro from the cached rootfs
          tarball first. Only needed to test a cold-start install.

    The setup script is NOT idempotent by design (the real installer always
    imports a fresh distro), so this harness does the userdel cleanup that
    the installer would not need.

.EXAMPLE
    .\test-setup.ps1 -Show                 # tier 3: inspect only
    .\test-setup.ps1 -Flatpak              # tier 1: run in reused distro
    .\test-setup.ps1 -Flatpak -Fresh       # tier 2: cold import first
#>
[CmdletBinding()]
param(
    [string]$DistroName  = 'ChimeraTest',
    [string]$InstallPath = 'C:\WSL\chimera-test',
    [string]$DownloadDir = 'C:\WSL\downloads',
    [switch]$Flatpak,
    [switch]$Fresh,
    [switch]$Show
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$WSL       = "$env:WINDIR\System32\wsl.exe"
$Installer = Join-Path $PSScriptRoot 'install.ps1'

function Say ([string]$m) { Write-Host "[test] $m" -ForegroundColor Cyan }
function OK  ([string]$m) { Write-Host "[OK] $m"    -ForegroundColor Green }
function Bad ([string]$m) { Write-Host "[BAD] $m"   -ForegroundColor Red }

# ---------------------------------------------------------------------------
# Parse install.ps1 once; pull the real setup/smoke assembly out of it.
# ---------------------------------------------------------------------------
$errs = $null
$ast  = [System.Management.Automation.Language.Parser]::ParseFile($Installer, [ref]$null, [ref]$errs)
if ($errs.Count -gt 0) { $errs | ForEach-Object { Bad $_.Message }; exit 1 }

function Get-Assembly {
    <#
        Returns the statements that BUILD $setupScript / $smokeScript, i.e.
        everything from the `$u =` assignments up to (not including) the
        statement that pipes the script into wsl. Those are pure string
        operations with no side effects, so we can run them in this harness
        and get byte-identical output to what the installer would send.
    #>
    param([string]$Var, [string]$AnchorPattern, [string]$StartPattern)
    $stmts = @($ast.EndBlock.Statements)
    $start = -1; $end = -1
    for ($i = 0; $i -lt $stmts.Count; $i++) {
        $t = $stmts[$i].Extent.Text
        if ($start -lt 0 -and $t -match $StartPattern) { $start = $i }
        if ($start -ge 0 -and $t -match $AnchorPattern) { $end = $i; break }
    }
    if ($start -lt 0 -or $end -le $start) { throw "could not locate assembly for $$Var" }
    # keep assignments / if-else blocks; drop standalone comments
    $slice = $stmts[$start..($end-1)]
    ($slice | Where-Object {
        $_.Extent.Text.Trim() -ne '' -and $_.Extent.Text.Trim() -notmatch '^#'
    }).Extent.Text -join "`n"
}

$setupCode = Get-Assembly -Var 'setupScript' -AnchorPattern '^\$setupScript\s*\|' -StartPattern '^\$u\s*='
$smokeCode = Get-Assembly -Var 'smokeScript' -AnchorPattern '^try\s*\{' -StartPattern '^\$smokeScript\s*='

function Build-Scripts([bool]$withFlatpak) {
    $Flatpak = $withFlatpak
    $Username = 'tuser'; $Hostname = 'testhost'; $Timezone = 'Etc/UTC'
    $DistroName = $DistroName
    # dot-sourcing runs in THIS function's scope, so $setupScript/$smokeScript
    # become local variables here -- no escaping gymnastics needed.
    . ([ScriptBlock]::Create($setupCode + "`n" + $smokeCode))
    return @{ setup = $setupScript; smoke = $smokeScript }
}

# ---------------------------------------------------------------------------
# Tier 3: show only
# ---------------------------------------------------------------------------
$built = Build-Scripts $Flatpak.IsPresent
$setup = $built.setup
$smoke = $built.smoke

if ($Show) {
    Say '--- $setupScript ---'
    $setup
    Say '--- $smokeScript ---'
    $smoke
    exit 0
}

# quick static sanity before we spend time in the distro
$problems = @()
if ($setup -match '__BOOTCMD__|__FLATPAK|__\w+__') { $problems += 'placeholder leaked into setup script' }
if ($smoke  -match '__FLATPAK|__\w+__')              { $problems += 'placeholder leaked into smoke script' }
if (-not $setup.TrimEnd().EndsWith('# end'))        { $problems += 'setup script does not end on the # end guard' }
if (-not $smoke.TrimEnd().EndsWith('# end'))         { $problems += 'smoke script does not end on the # end guard' }
if ($setup -match '(?m)^command=' -and -not $Flatpak){ $problems += 'boot command present but -Flatpak is off' }
if ($problems.Count) { $problems | ForEach-Object { Bad $_ }; exit 1 }
OK 'static checks passed (no placeholders, guards intact)'

# ---------------------------------------------------------------------------
# Ensure the throwaway distro exists (tier 1 reuses; -Fresh rebuilds)
# ---------------------------------------------------------------------------
$installed = @(& $WSL --list --quiet 2>$null) -replace "`0", '' | ForEach-Object { $_.Trim() } | Where-Object { $_ }

if ($Fresh -and $installed -contains $DistroName) {
    Say "unregistering $DistroName (-Fresh)"
    & $WSL --unregister $DistroName 2>&1 | Out-Null
    $installed = @(& $WSL --list --quiet 2>$null) -replace "`0", '' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}

if (-not ($installed -contains $DistroName)) {
    $tar = Get-ChildItem $DownloadDir -Filter 'chimera-linux-x86_64-ROOTFS-*-full.tar.gz' -ErrorAction SilentlyContinue |
           Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $tar) { Bad "no rootfs tarball in $DownloadDir"; exit 1 }
    Say "importing $DistroName from $($tar.Name) (cold, ~5s + full apk downloads on first run)"
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    & $WSL --import $DistroName $InstallPath $tar.FullName --version 2 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Bad "import failed (rc=$LASTEXITCODE)"; exit 1 }
    OK "imported $DistroName"
} else {
    Say "reusing existing $DistroName (tier 1: no re-import, packages cached in-distro)"
}

# ---------------------------------------------------------------------------
# Clean the test user so setup (which is not idempotent) can re-run
# ---------------------------------------------------------------------------
Say "removing test user tuser if present"
& $WSL -d $DistroName -u root -- sh -c 'userdel -r tuser 2>/dev/null; rm -f /etc/doas.conf.bak; exit 0' 2>&1 | Out-Null

# ---------------------------------------------------------------------------
# Run the real setup script, then the real smoke script
# ---------------------------------------------------------------------------
Say 'running $setupScript'
$setup | & $WSL -d $DistroName -u root sh -s 2>&1 | Out-Host
$rc = $LASTEXITCODE
if ($rc -ne 0) { Bad "setup exited rc=$rc"; exit 1 }
OK 'setup exited 0'

# install.ps1 terminates the distro before the smoke test so that the
# `default=user` we just wrote in wsl.conf takes effect. Mirror that, or the
# smoke runs as root with no user remotes and looks like a false failure.
Say 'bouncing distro so default user takes effect'
& $WSL --terminate $DistroName 2>&1 | Out-Null
Start-Sleep -Seconds 2

Say 'running $smokeScript'
$smoke | & $WSL -d $DistroName sh -s 2>&1 | Out-Host
if ($LASTEXITCODE -ne 0) { Bad "smoke exited rc=$LASTEXITCODE"; exit 1 }
OK 'smoke exited 0'