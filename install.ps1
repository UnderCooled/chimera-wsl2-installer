#Requires -Version 5.1
<#
.SYNOPSIS
    Install Chimera Linux as a WSL2 distro (security-hardened).

.DESCRIPTION
    Hardened rewrite of the original installer. Key differences vs. the original:
      * Passwords are NEVER interpolated into a shell script and NEVER written to disk.
        They are piped straight to `chpasswd` over stdin, which closes the
        root-level command-injection hole (e.g. a password containing $(...) or backticks).
      * No temp file containing secrets: the in-distro setup script is fed to `sh -s`
        over stdin, so a crash can never leave a password-bearing file in %TEMP%.
      * TLS 1.2+ enforced; non-HTTPS RootfsBase rejected.
      * DistroName / Username / Hostname / Timezone are all validated before use.
      * Distro lookup uses exact match instead of `-match` (no accidental name collisions).
      * `-Force` no longer silently skips `--unregister`; data loss is announced.
      * ext4.vhdx directory is re-ACL'd to "you + SYSTEM only" via icacls.
      * Supports `-ExpectedSha256` to pin the artifact hash (defends against a
        compromised upstream: a same-origin sha256sums.txt proves nothing).

.NOTES
    The user created here is added to `wheel` and granted `permit persist :wheel`
    in /etc/doas.conf, i.e. they can obtain full root. That is by design, but it
    means the user password is effectively a root password.
#>

[CmdletBinding()]
param(
    [string]$DistroName  = 'Chimera',
    [string]$InstallPath = 'C:\WSL\chimera',
    [string]$DownloadDir = 'C:\WSL\downloads',
    [string]$Username    = $(if ($env:USERNAME) { $env:USERNAME.ToLower() } else { 'chimera' }),
    [string]$Hostname    = $(if ($env:COMPUTERNAME) { "$($env:COMPUTERNAME)-chimera".ToLower() } else { 'chimera' }),
    [string]$Timezone    = 'America/New_York',
    [string]$RootfsBase  = 'https://repo.chimera-linux.org/live/latest',
    [string]$ExpectedSha256 = '',
    [switch]$SkipAclHardening,
    [switch]$Force
)

# ---------------------------------------------------------------------------
# Runtime policy
# ---------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

# PowerShell 7.4 turns a non-zero native exit code into a terminating error when
# ErrorActionPreference is 'Stop'. We check $LASTEXITCODE manually, so opt out.
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}

# Text piped to native commands (wsl.exe) must be UTF-8, not ASCII, otherwise
# non-ASCII passwords/usernames get mangled on the way in.
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)

# TLS 1.2 minimum; older Windows defaults to TLS 1.0/SSLv3.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

# Terminating errors land here, so `Fail` can just throw and still exit 1
# (and dot-sourcing this script no longer kills the host session).
trap {
    Write-Host "[FAIL] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
function Say ([string]$msg) { Write-Host "[chimera-wsl2] $msg" -ForegroundColor Cyan }
function OK  ([string]$msg) { Write-Host "[OK] $msg"            -ForegroundColor Green }
function Warn([string]$msg) { Write-Host "[WARN] $msg"          -ForegroundColor Yellow }
function Fail([string]$msg) { throw $msg }

$WSL   = "$env:WINDIR\System32\wsl.exe"
$PS5Exe = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"

# ---------------------------------------------------------------------------
# Input validation -- everything that reaches a shell must be whitelisted
# ---------------------------------------------------------------------------
function Assert-Pattern {
    param([string]$Value, [string]$Pattern, [string]$Label, [string]$Hint)
    if ($Value -notmatch $Pattern) {
        Fail "$Label '$Value' is invalid. $Hint"
    }
}

# WSL distro names: printable, no path/hostile separators.
Assert-Pattern $DistroName '^[A-Za-z0-9][A-Za-z0-9._ -]{0,49}$' 'DistroName' `
    'Allowed: start with a letter/digit, then [A-Za-z0-9._ -], <= 50 chars.'

# POSIX username: also tight enough to be safe inside single quotes.
Assert-Pattern $Username '^[a-z][a-z0-9_-]{0,31}$' 'Username' `
    'Must start with a lowercase letter, then [a-z0-9_-], <= 32 chars.'

# RFC 1123 single label.
Assert-Pattern $Hostname '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$' 'Hostname' `
    'Must be a single RFC-1123 label (lowercase alnum + hyphen, <= 63 chars).'

# Timezone: "Area/Locality"-ish, no traversal, no shell metacharacters.
Assert-Pattern $Timezone '^[A-Za-z0-9_+\-]{1,40}(/[A-Za-z0-9_+\-]{1,40}){0,2}$' 'Timezone' `
    'Expected form: Area/Locality, e.g. America/New_York or Etc/UTC.'

$RootfsBase = $RootfsBase.TrimEnd('/')
if ($RootfsBase -notmatch '^https://[A-Za-z0-9._\-]+(/.*)?$') {
    Fail "RootfsBase '$RootfsBase' must be an https:// URL. Refusing plaintext HTTP."
}
if ($ExpectedSha256 -and $ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$') {
    Fail "-ExpectedSha256 must be 64 hex characters."
}

Say 'preflight'

# ---------------------------------------------------------------------------
# WSL availability
# ---------------------------------------------------------------------------
function Install-WSL-IfMissing {
    $wslOk = $false
    if (Test-Path -LiteralPath $WSL) {
        try {
            $null = & $WSL --version 2>&1
            if ($LASTEXITCODE -eq 0) { $wslOk = $true }
        } catch { }
    }
    if ($wslOk) { return }

    Warn "WSL2 doesn't look usable on this machine (wsl.exe missing or feature not enabled)."
    Write-Host ''
    Write-Host '  To install WSL2 we need to run, as ADMINISTRATOR:' -ForegroundColor Yellow
    Write-Host '      wsl --install --no-distribution'
    Write-Host ''
    Write-Host '  This enables the WSL Windows feature, downloads the WSL2 kernel,'
    Write-Host '  and may require a REBOOT before this installer can proceed.'
    Write-Host ''
    $resp = Read-Host 'Run it now with elevation? (y/N)'
    if ($resp -ne 'y') {
        Fail 'Aborting. Install WSL manually (wsl --install) then re-run this script.'
    }
    if (-not (Test-Path -LiteralPath $PS5Exe)) {
        Fail "Could not find $PS5Exe -- cannot elevate. Run 'wsl --install' manually."
    }
    # Full path, never a bare 'powershell.exe' resolved through %PATH%.
    Start-Process -FilePath $PS5Exe `
        -ArgumentList '-NoProfile','-Command',"& '$WSL' --install --no-distribution; Write-Host ''; Read-Host 'Press Enter to close'" `
        -Verb RunAs -Wait
    OK 'WSL2 install requested. If Windows needs a reboot, do that and re-run this script.'
    exit 0
}

Install-WSL-IfMissing
OK 'wsl available'

# ---------------------------------------------------------------------------
# Existing distro: exact match, explicit data-loss warning
# ---------------------------------------------------------------------------
$installed = @(& $WSL --list --quiet 2>$null) -replace "`0", '' |
    ForEach-Object { $_.Trim() } | Where-Object { $_ }

if ($installed -contains $DistroName) {
    if (-not $Force) {
        Warn "distro '$DistroName' is already registered."
        Warn "Unregistering PERMANENTLY DELETES the distro's ext4.vhdx and ALL data in it."
        $resp = Read-Host "Unregister and reinstall? (y/N)"
        if ($resp -ne 'y') {
            Say 'aborting'
            exit 0
        }
    } else {
        Warn "-Force: unregistering '$DistroName' -- ALL existing data will be permanently deleted."
    }
    & $WSL --unregister $DistroName 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "wsl --unregister failed (rc=$LASTEXITCODE)" }
    OK "old '$DistroName' unregistered"
}

Write-Host ''
Say 'user setup'

# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------
$usernameInput = Read-Host "Linux username [$Username]"
if (-not [string]::IsNullOrWhiteSpace($usernameInput)) { $Username = $usernameInput.Trim() }
Assert-Pattern $Username '^[a-z][a-z0-9_-]{0,31}$' 'Username' `
    'Must start with a lowercase letter, then [a-z0-9_-], <= 32 chars.'

function Read-PlaintextPassword {
    param([string]$Prompt)
    while ($true) {
        $sec1 = Read-Host -Prompt $Prompt -AsSecureString
        $sec2 = Read-Host -Prompt '  re-enter to confirm' -AsSecureString
        $b1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec1)
        $b2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec2)
        try {
            $p1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b1)
            $p2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b2)
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b1)
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b2)
        }
        if ($p1 -ne $p2)  { Warn 'passwords do not match; try again'; continue }
        if ($p1.Length -lt 8) { Warn 'password must be at least 8 chars; try again'; continue }
        # Passwords go to `chpasswd` over stdin, one "user:password" line each.
        # Only characters that could break that framing (or be invisible/typo-prone)
        # are rejected. Quotes and $ are fine now -- nothing is re-parsed by a shell.
        if ($p1 -match '[\r\n\x00-\x1f]') {
            Warn 'password cannot contain newlines or control characters; try again'
            continue
        }
        return $p1
    }
}

$UserPassword = Read-PlaintextPassword "Password for '$Username'"
$useSamePw = Read-Host 'Use the same password for root? (Y/n)'
if ($useSamePw -eq 'n' -or $useSamePw -eq 'N') {
    $RootPassword = Read-PlaintextPassword 'Password for root'
} else {
    $RootPassword = $UserPassword
}
OK 'credentials captured'

# ---------------------------------------------------------------------------
# Resolve + verify the rootfs tarball
# ---------------------------------------------------------------------------
$shaPinned = [bool]$ExpectedSha256

if ($shaPinned) {
    # Offline pin: we still need the filename, so trust the caller's pin for content
    # and only ask upstream which build is current.
    $stageFilename = $null
}

if (-not $shaPinned) {
    Say "discovering latest chimera-linux-x86_64-ROOTFS from $RootfsBase"
    $sumsUrl = "$RootfsBase/sha256sums.txt"
    try {
        $sums = (Invoke-WebRequest -Uri $sumsUrl -UseBasicParsing -TimeoutSec 30 -MaximumRedirection 3).Content
    } catch {
        Fail "couldn't fetch sha256sums.txt at $sumsUrl : $($_.Exception.Message)"
    }

    # Chimera's sha256sums.txt lines look like:
    #   <64-hex>  chimera-linux-x86_64-ROOTFS-20251220-full.tar.gz
    # If upstream ever changes that format, this regex is what to edit.
    $needle = '^([0-9a-f]{64})\s+chimera-linux-x86_64-ROOTFS-(\d+)-full\.tar\.gz$'
    $foundSha = $null
    $foundDate = $null
    foreach ($line in ($sums -split "`r?`n")) {
        if ($line -match $needle) {
            # Copy the strings out: $matches is reused by the next -match.
            $foundSha  = $matches[1]
            $foundDate = $matches[2]
            break
        }
    }
    if (-not $foundSha) {
        Fail "couldn't find chimera-linux-x86_64-ROOTFS-*-full.tar.gz line in sha256sums.txt"
    }
    $ExpectedSha256 = $foundSha.ToLower()
    $stageFilename  = "chimera-linux-x86_64-ROOTFS-$foundDate-full.tar.gz"
    Write-Host '  (verify this hash out-of-band if you care about upstream compromise)' -ForegroundColor DarkGray
} else {
    Say 'using -ExpectedSha256 pin; querying upstream only for the current filename'
    $sumsUrl = "$RootfsBase/sha256sums.txt"
    try {
        $sums = (Invoke-WebRequest -Uri $sumsUrl -UseBasicParsing -TimeoutSec 30 -MaximumRedirection 3).Content
        foreach ($line in ($sums -split "`r?`n")) {
            if ($line -match '^([0-9a-f]{64})\s+(chimera-linux-x86_64-ROOTFS-\d+-full\.tar\.gz)$') {
                $stageFilename = $matches[2]
                $upstreamSha = $matches[1].ToLower()
                break
            }
        }
    } catch {
        Warn "couldn't fetch sha256sums.txt to resolve the filename: $($_.Exception.Message)"
    }
    if (-not $stageFilename) {
        Fail "could not determine the current filename. Drop -ExpectedSha256, or pass a filename you trust."
    }
    if ($upstreamSha -and $upstreamSha -ne $ExpectedSha256.ToLower()) {
        Write-Host '' -ForegroundColor Yellow
        Warn "PIN MISMATCH: upstream sha256sums.txt says $upstreamSha"
        Warn "               you pinned                                $($ExpectedSha256.ToLower())"
        $resp = Read-Host 'Continue with YOUR pinned hash anyway? (y/N)'
        if ($resp -ne 'y') { Fail 'Aborting on pin mismatch.' }
    }
}

$stageUrl = "$RootfsBase/$stageFilename"
OK "target: $stageFilename"
OK "sha256: $($ExpectedSha256.ToLower())$(if ($shaPinned) { ' (pinned)' })"

# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------
Say 'preparing dirs'
New-Item -ItemType Directory -Path $DownloadDir -Force | Out-Null
New-Item -ItemType Directory -Path $InstallPath  -Force | Out-Null
if (((Get-ChildItem -LiteralPath $InstallPath -Force -ErrorAction SilentlyContinue) | Measure-Object).Count -gt 0 -and -not $Force) {
    Fail "$InstallPath is not empty. Use -Force or pick a different -InstallPath."
}

$stageFile = Join-Path $DownloadDir $stageFilename
$partFile  = "$stageFile.part"

function Get-Sha256Hex {
    param([string]$Path)
    if (Get-Command Get-FileHash -ErrorAction SilentlyContinue) {
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower()
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        try { $bytes = $sha.ComputeHash($fs) } finally { $fs.Dispose() }
    } finally { $sha.Dispose() }
    return ([System.BitConverter]::ToString($bytes) -replace '-', '').ToLower()
}

$needDownload = $true
if (Test-Path -LiteralPath $stageFile) {
    Say "checking cached tarball at $stageFile"
    if ((Get-Sha256Hex $stageFile) -eq $ExpectedSha256.ToLower()) {
        $mb = [math]::Round((Get-Item -LiteralPath $stageFile).Length / 1048576, 1)
        OK "cached tarball matches pinned hash ($mb MB) -- skipping download"
        $needDownload = $false
    } else {
        Warn 'cached tarball hash mismatch -- deleting and re-downloading'
        Remove-Item -LiteralPath $stageFile -Force -ErrorAction SilentlyContinue
    }
}

if ($needDownload) {
    Say "downloading $stageFilename (~115 MB)"
    Remove-Item -LiteralPath $partFile -Force -ErrorAction SilentlyContinue
    $swDl = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        Invoke-WebRequest -Uri $stageUrl -OutFile $partFile -UseBasicParsing -MaximumRedirection 3
    } catch {
        # Never leave a truncated/attacker-controlled .part lying around.
        Remove-Item -LiteralPath $partFile -Force -ErrorAction SilentlyContinue
        Fail "download failed: $($_.Exception.Message)"
    }
    $swDl.Stop()
    if (-not (Test-Path -LiteralPath $partFile)) { Fail 'download produced no file' }
    Move-Item -LiteralPath $partFile -Destination $stageFile -Force
    $mb = [math]::Round((Get-Item -LiteralPath $stageFile).Length / 1048576, 1)
    OK "downloaded $mb MB in $([math]::Round($swDl.Elapsed.TotalSeconds, 1))s"
}

Say 'verifying sha256'
$actual = Get-Sha256Hex $stageFile
if ($ExpectedSha256.ToLower() -ne $actual) {
    Fail "SHA256 MISMATCH. Expected $($ExpectedSha256.ToLower()), got $actual. Delete $stageFile and retry."
}
OK "sha256 verified ($actual)"

# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------
Say "wsl --import $DistroName"
$swImport = [System.Diagnostics.Stopwatch]::StartNew()
& $WSL --import $DistroName $InstallPath $stageFile --version 2 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "wsl --import failed (rc=$LASTEXITCODE)" }
$swImport.Stop()
OK "imported in $([math]::Round($swImport.Elapsed.TotalSeconds, 1))s"

# ---------------------------------------------------------------------------
# In-distro setup -- NO SECRETS in this script, delivered over stdin to `sh -s`
# ---------------------------------------------------------------------------
Say "writing /etc/wsl.conf and creating user '$Username'"

$u  = $Username   # validated above
$h  = $Hostname   # validated above
$tz = $Timezone   # validated above

$setupScript = @"
set -e
echo '--- wsl.conf ---'
cat > /etc/wsl.conf << 'EOF'
[boot]
systemd=false
[user]
default=$u
[network]
generateHosts=true
generateResolvConf=true
[interop]
enabled=true
appendWindowsPath=false
[automount]
enabled=true
options="metadata,umask=22,fmask=11,noexec"
EOF

echo '--- hostname / timezone ---'
echo "$h" > /etc/hostname
if [ -f "/usr/share/zoneinfo/$tz" ]; then
    ln -sf "/usr/share/zoneinfo/$tz" /etc/localtime
    echo "$tz" > /etc/timezone
else
    echo "WARN: /usr/share/zoneinfo/$tz missing; leaving time as-is"
fi

mkdir -p /var/spool/mail
chmod 0775 /var/spool/mail

echo '--- apk ---'
apk update            || echo 'WARN: apk update failed (no network?)'
apk add --no-cache bash   || echo 'WARN: could not install bash'
apk add --no-cache shadow || echo 'WARN: could not install shadow (useradd/chpasswd may be missing)'
apk add --no-cache doas   || echo 'WARN: could not install doas'

echo '--- user ---'
if command -v bash >/dev/null 2>&1; then
    useradd -m -G wheel,users -s /bin/bash '$u'
else
    useradd -m -G wheel,users -s /bin/sh '$u'
fi
echo 'permit persist :wheel' > /etc/doas.conf
chmod 0400 /etc/doas.conf

echo '--- setup done ---'
"@
$setupScript = $setupScript -replace "`r`n", "`n"

# `sh -s` reads the program from stdin: nothing is ever written to disk,
# so there is no password-bearing temp file to leak or to forget to clean up.
$setupScript | & $WSL -d $DistroName -u root sh -s 2>&1 | Tee-Object -Variable setupOut | Out-Host
if ($LASTEXITCODE -ne 0) { Fail "in-distro setup failed (rc=$LASTEXITCODE)" }
OK 'in-distro setup complete'

# ---------------------------------------------------------------------------
# Passwords: piped directly to chpasswd, never through a shell
# ---------------------------------------------------------------------------
function Set-DistroPassword {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '',
        Justification = 'Password is piped as plaintext to chpasswd over stdin; never interpolated into shell or written to disk.')]
    param([string]$User, [string]$Password, [string[]]$ExtraArgs)
    $line = "$User`:$Password"
    $line | & $WSL -d $DistroName -u root chpasswd @ExtraArgs 2>&1 | Out-Null
    return $LASTEXITCODE
}

Say "setting password for '$Username'"
$rc = Set-DistroPassword -User $Username -Password $UserPassword -ExtraArgs @('-c','SHA512')
if ($rc -ne 0) {
    Warn "chpasswd -c SHA512 failed (rc=$rc); retrying with the default hashing method"
    $rc = Set-DistroPassword -User $Username -Password $UserPassword -ExtraArgs @()
}
if ($rc -ne 0) {
    Fail "could not set the password for '$Username'. Is the 'shadow' package installed? Set it manually: wsl -d $DistroName -u root -- passwd $Username"
}

Say 'setting password for root'
$rc = Set-DistroPassword -User 'root' -Password $RootPassword -ExtraArgs @('-c','SHA512')
if ($rc -ne 0) {
    Warn "chpasswd -c SHA512 failed (rc=$rc); retrying with the default hashing method"
    $rc = Set-DistroPassword -User 'root' -Password $RootPassword -ExtraArgs @()
}
if ($rc -ne 0) {
    Fail "could not set the root password. Set it manually: wsl -d $DistroName -u root -- passwd"
}

# Passwords are no longer needed; drop the plaintext references.
$UserPassword = $null
$RootPassword = $null
[GC]::Collect()
OK 'passwords set'

# ---------------------------------------------------------------------------
# Lock down the directory holding ext4.vhdx (it contains /etc/shadow)
# ---------------------------------------------------------------------------
if (-not $SkipAclHardening) {
    Say "restricting NTFS ACLs on $InstallPath"
    try {
        # SIDs, not localized names: 'SYSTEM'/'BUILTIN' differ per UI language.
        $userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        & "$env:WINDIR\System32\icacls.exe" $InstallPath `
            /inheritance:r `
            /grant:r "*${userSid}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            OK 'ACLs restricted to your account + SYSTEM (Administrators removed)'
            Write-Host '    note: other local admins can no longer read your ext4.vhdx' -ForegroundColor DarkGray
        } else {
            Warn "icacls returned rc=$LASTEXITCODE; check the ACLs on $InstallPath manually."
        }
    } catch {
        Warn "could not tighten ACLs: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# Restart + smoke test
# ---------------------------------------------------------------------------
Say 'bouncing distro so default user takes effect'
& $WSL --terminate $DistroName 2>&1 | Out-Null
Start-Sleep -Seconds 2

Say 'smoke test'
# Literal here-string (@' '@): PowerShell does NOT interpolate it, so $(...) stays
# intact for the shell, and there is no nested-quote puzzle to get wrong.
$smokeScript = @'
echo "user=$(whoami) uid=$(id -u)"
echo "apk:"; apk --version 2>&1 | head -1
echo "kernel:"; uname -r
'@
try {
    $smokeScript | & $WSL -d $DistroName sh -s 2>&1 | Out-Host
} catch {
    Warn "smoke test threw: $($_.Exception.Message)  (distro is probably fine - verify manually with: wsl -d $DistroName)"
}

Write-Host ''
Write-Host '=========================================' -ForegroundColor Green
Write-Host '  Chimera installed and ready'            -ForegroundColor Green
Write-Host '=========================================' -ForegroundColor Green
Write-Host "  Distro:    $DistroName"
Write-Host "  Path:      $InstallPath"
Write-Host "  Stage:     $stageFilename"
Write-Host "  User:      $Username (password you set during install)"
Write-Host '  Root:      password you set during install'
Write-Host "  Hostname:  $h"
Write-Host ''
Write-Host "  NOTE: '$Username' is in 'wheel' with 'permit persist :wheel' in /etc/doas.conf," -ForegroundColor Yellow
Write-Host '        i.e. this user can become root. Treat the user password as a root password.' -ForegroundColor Yellow
Write-Host ''
Write-Host '  To change passwords later:' -ForegroundColor Yellow
Write-Host "    wsl -d $DistroName -- passwd"
Write-Host "    wsl -d $DistroName -u root -- passwd"
Write-Host ''
Write-Host "  Run with:  wsl -d $DistroName"
Write-Host ''
Write-Host '  Useful apk commands:'
Write-Host '    apk search <term>         search packages'
Write-Host '    apk info <pkg>            show package info'
Write-Host '    doas apk add <pkg>        install'
Write-Host '    doas apk upgrade          update everything'
Write-Host '    doas apk del <pkg>        remove'
Write-Host ''
