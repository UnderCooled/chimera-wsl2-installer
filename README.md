# chimera-wsl2-installer

The easiest Chimera Linux installer for Windows WSL2.

One-shot installer for [Chimera Linux](https://chimera-linux.org/) on WSL2.

Chimera is a new BSD-userland + Linux-kernel distribution: musl libc, LLVM
toolchain, FreeBSD userland (chimerautils), `apk` (apk-tools port from
Alpine) as the package manager, and [dinit](https://github.com/davmac314/dinit)
as the init system. It's not in the Microsoft Store. This script automates
the whole "download rootfs, `wsl --import`, configure the in-distro side"
flow so you can be in a working Chimera shell in about 90 seconds.

## Quick start (easiest path)

**On a Windows 11 machine**:

1. Download this repo as a ZIP from GitHub
   ([direct link](https://github.com/t3m3d/chimera-wsl2-installer/archive/refs/heads/main.zip))
   and extract it anywhere.
2. **Double-click `run.cmd`** in the extracted folder.
3. Watch the PowerShell window. When it says "Chimera installed and ready",
   you're done.
4. Open a regular PowerShell and run: `wsl -d Chimera`

`run.cmd` handles the two friction points that bite first-time users:
PowerShell blocks unsigned `.ps1` files by default, and double-clicking
a `.ps1` opens Notepad instead of running it. `run.cmd` runs `install.ps1`
through PowerShell with the right flags, in a window that stays open so
you can read the output.

If WSL2 isn't installed yet on the machine, the script will detect that,
ask permission, and run `wsl --install` for you (with a UAC prompt). After
that you may need to **reboot once** and re-run.

If you prefer the terminal path, scroll to [Usage](#usage) below.

## What it does

1. Verifies WSL2 is installed
2. Reads `sha256sums.txt` from
   [`repo.chimera-linux.org/live/latest`](https://repo.chimera-linux.org/live/latest/)
   to discover the current ROOTFS filename + hash (so the installer
   tracks upstream automatically; no hard-coded date)
3. Downloads `chimera-linux-x86_64-ROOTFS-<date>-full.tar.gz` (~115 MB)
4. Verifies the SHA256 against the upstream entry
5. `wsl --import` to register the distro
6. Inside the new distro:
   - writes `/etc/wsl.conf` with sensible defaults (`appendWindowsPath=false`
     and `noexec` on `/mnt/c` — see [Hardening](#hardening) below)
   - creates `/etc/hostname`, sets timezone
   - runs `apk update` then installs `bash`, `shadow`, and `opendoas` (non-interactively)
   - creates a non-root user in the `wheel` group with `doas`
     (OpenBSD's lighter sudo) wired via `/etc/doas.conf`
   - with `-Flatpak`: installs `dbus` + `flatpak` + `xdg-desktop-portal-gtk`,
     starts the D-Bus system bus on every boot via `[boot] command=` (WSL
     never runs dinit, so dinit boot links are dead here), registers the
     flathub remote for the new user, and drops a self-heal hook in
     `/etc/profile.d/wsl-dbus.sh`
7. Bounces WSL so the default-user setting takes effect

Re-running the script later reuses the cached tarball if its SHA still
matches upstream — re-installs after the first run finish in seconds
instead of re-downloading.

## Hardening

The installer bakes `/mnt/c noexec` + `appendWindowsPath=false` into
`/etc/wsl.conf`. Net effect inside the new Chimera install:

- Linux PATH does **not** absorb your Windows `PATH`. Typing a binary
  finds the Linux install, never some stray `C:\...\foo.exe`.
- `/mnt/c/...whatever.exe` can be **read and listed** but **cannot be
  executed** from inside WSL. Prevents accidentally running a Windows
  binary when you meant the Linux native version, and shrinks the
  blast-radius if a script does something stupid in `/mnt/c`.
- `explorer.exe .` / `code .` / `cmd.exe` still work when you explicitly
  cross the boundary (since `[interop] enabled=true`).

If you don't want this for your use case, edit `/etc/wsl.conf` after
install and run `wsl --shutdown` to apply.

## Usage

The double-click path is `run.cmd`. From a terminal you'd run:

```powershell
.\install.ps1
```

Useful parameters:

| Parameter | Default | Notes |
| --- | --- | --- |
| `-DistroName` | `Chimera` | Name `wsl --list` will show. |
| `-InstallPath` | `C:\WSL\chimera` | Where the distro's `ext4.vhdx` lives. Pick a non-system drive (e.g. `D:\WSL\chimera`) if you don't want it ballooning your `C:`. |
| `-DownloadDir` | `C:\WSL\downloads` | Stage tarball cache. Re-runs reuse the cached file if its SHA matches upstream. |
| `-Username` | your Windows username, lower-cased | The Linux user the installer creates. Overridable here or at the interactive prompt. |
| `-Hostname` | `<computer>-chimera` | Written to `/etc/hostname`. |
| `-Timezone` | `America/New_York` | Symlinks `/etc/localtime`. |
| `-RootfsBase` | upstream | Mirror URL. Default is `https://repo.chimera-linux.org/live/latest`. |
| `-Flatpak` | off | Install `dbus` + `flatpak` + GTK portal, start the system bus on boot, add flathub for the new user (`--user` scope; system-wide flatpak needs polkit, unavailable here). |

Example: install to a non-system drive, named differently:

```powershell
.\install.ps1 -DistroName ChimeraDev -InstallPath D:\WSL\chimera-dev
```

Example: full install with Flatpak support:

```powershell
.\install.ps1 -Flatpak
```

## Development: testing the setup script

`test-setup.ps1` is a dev harness (not needed to install Chimera). It runs
the *real* in-distro setup/smoke scripts from `install.ps1` — extracted via
the PowerShell AST, so it is always the shipped code, never a hand-copy —
against a throwaway `ChimeraTest` distro, so you don't re-download ~200
packages on every edit. Three tiers, cheapest first:

```powershell
.\test-setup.ps1 -Show              # seconds, no distro: print the assembled
                                   # setup/smoke scripts, catch wsl.conf
                                   # section or placeholder bugs
.\test-setup.ps1 -Flatpak           # fast: reuse a live ChimeraTest distro
.\test-setup.ps1 -Flatpak -Fresh    # slow: cold re-import first
```

## After install

The installer creates one user (the one you set during the run), in the
`wheel` group with `doas` enabled. `bash`, `shadow`, and `opendoas` are
installed. `doas` (from the `opendoas` package) is OpenBSD's lighter sudo
replacement, which Chimera ships instead of `sudo`. Use it the same way: `doas apk add ...`.

With `-Flatpak`, the D-Bus system bus starts automatically on every boot
(via `[boot] command=` in `/etc/wsl.conf`, plus a self-heal hook in
`/etc/profile.d/wsl-dbus.sh` — needed because WSL boots `/init`, never
dinit, so dinit service links never run). The flathub remote is registered
for your user only; install apps with:

```sh
flatpak --user install flathub <app>   # e.g. flatpak --user install flathub org.gnome.Calculator
flatpak --user list                    # what you have
flatpak run <app-id>                   # launch (GUI apps need WSLg, which WSL2 ships)
```

System-wide flatpak (`flatpak install` without `--user`) is deliberately
unsupported: it needs `flatpak-system-helper` + polkit, neither of which
exists in this environment.
Updates:

```sh
doas apk update                   # refresh index
doas apk upgrade --available      # update everything
doas apk add <pkg>                # install
doas apk del <pkg>                # remove
apk search <term>                 # search
apk info <pkg>                    # show package info
```

WSL2's `ext4.vhdx` grows but never shrinks. Heavy package installs can
fill your system drive over time. To reclaim space (Windows side, admin):

```powershell
wsl --shutdown
diskpart
  select vdisk file="C:\WSL\chimera\ext4.vhdx"
  attach vdisk readonly
  compact vdisk
  detach vdisk
```

Or move the distro off the system drive entirely:

```powershell
wsl --export Chimera D:\wsl\chimera.tar
wsl --unregister Chimera
wsl --import Chimera D:\wsl\chimera D:\wsl\chimera.tar --version 2
```

## Tested on

- Windows 11 24H2, WSL 2.7.x
- `chimera-linux-x86_64-ROOTFS-*-full.tar.gz`

## License

MIT.
