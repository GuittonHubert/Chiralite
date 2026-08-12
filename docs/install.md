# chiralite — Installation Guide

## Platform support

| Feature | Linux | macOS | Windows |
|---|:---:|:---:|:---:|
| Client mode | ✓ | ✓ | ✓ |
| Server mode | ✓ | — | — |
| tmpfs sandbox | ✓ | — | — |
| ClamAV scanning | ✓ | optional | — |
| FSEvents / inotify | inotify | FSEvents | ReadDirChanges |

The **server** must run on Linux. macOS and Windows operate as **clients** only.

---

## Prerequisites

### All platforms

| Requirement | Minimum version | Notes |
|---|---|---|
| Python | 3.10 | 3.11+ recommended |
| git | any | needed to build xdelta3 |
| C compiler | gcc / clang / MSVC | needed for rapidhash and xdelta3 |

### Linux (server)

| Package | Purpose |
|---|---|
| `clamav`, `clamav-daemon` | AV scanning via `clamd` UNIX socket |
| `gcc`, `make` | C extension build |

### macOS (client)

[Homebrew](https://brew.sh) is required. The installer handles the rest.

### Windows (client)

- Python 3.10+ from <https://www.python.org/downloads/> or `winget install Python.Python.3.12`
- [Visual C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) for C extensions
- Git from <https://git-scm.com/>

---

## Quick install

### Linux

```bash
sudo bash scripts/install-linux.sh
```

Options:

| Flag | Effect |
|---|---|
| `--no-service` | Skip systemd unit installation |
| `--dev` | Editable install (`pip install -e .`) |

### macOS

```bash
bash scripts/install-macos.sh
```

Options:

| Flag | Effect |
|---|---|
| `--no-daemon` | Skip launchd agent installation |
| `--dev` | Editable install (`pip install -e .`) |

### Windows

Run in a **Developer PowerShell for VS** (required for C compilation):

```powershell
.\scripts\install-windows.ps1
```

Options:

| Flag | Effect |
|---|---|
| `-Dev` | Editable install (`pip install -e .`) |
| `-SkipXdelta` | Skip xdelta3 build (already installed) |

---

## xdelta3 — custom build

The PyPI package (`xdelta3==0.0.5`) links against xdelta 3.0 and is **not compatible**.
chiralite requires the `jmacd/release3_1_apl` C sources with two patches applied:

- `#include <assert.h>` added to `xdelta3.c`
- `-std=gnu11` compile flag (MSVC: `/std:c11`)

The installer scripts apply these patches automatically. To rebuild standalone:

```bash
bash scripts/build-xdelta3.sh           # build and install
bash scripts/build-xdelta3.sh --check   # verify installed version
```

To pass a specific Python interpreter:

```bash
PYTHON=python3.12 PIP="python3.12 -m pip" bash scripts/build-xdelta3.sh
```

---

## ClamAV configuration (Linux server)

The sandbox pipeline scans every received file via a `clamd` UNIX socket before
writing it to disk. The default socket path expected by chiralite is
`/run/clamav/clamd.ctl`.

Verify clamd is running and the socket exists:

```bash
systemctl status clamav-daemon
ls -la /run/clamav/clamd.ctl
```

If the socket path differs on your distribution, set it in the server config:

```yaml
# ~/.config/chiralite/config.yaml
server:
  clamd_socket: /var/run/clamav/clamd.sock
```

Update virus definitions manually:

```bash
sudo freshclam
```

---

## Sandbox tmpfs (Linux server)

The server assembles received content in a tmpfs mount before the ClamAV scan,
so that malicious files never touch persistent storage.

The installer mounts `/run/chiralite/sandbox` (256 MiB) and adds an fstab entry
for persistence across reboots. To change the size:

```bash
# /etc/fstab
tmpfs  /run/chiralite/sandbox  tmpfs  size=512m,mode=0700  0  0
```

Re-mount after editing:

```bash
sudo umount /run/chiralite/sandbox
sudo mount /run/chiralite/sandbox
```

---

## Post-install setup

### 1 — Generate keys

```bash
chiralite keygen --out-dir ~/.config/chiralite --cn my-laptop
```

This creates:
- `ca.key` / `ca.crt` — offline CA (keep the key offline)
- `client.key` / `client.crt` — client certificate (CN = `my-laptop`)

### 2 — Configure

Minimal `~/.config/chiralite/config.yaml`:

```yaml
client:
  server_url: wss://my-server.example.com:443
  ca_cert:     ~/.config/chiralite/ca.crt
  client_cert: ~/.config/chiralite/client.crt
  client_key:  ~/.config/chiralite/client.key
  silos:
    - id: "550e8400-e29b-41d4-a716-446655440000"
      local_root: ~/projects/myapp
```

### 3 — Start

```bash
chiralite start                        # foreground
chiralite start --config /path/to/config.yaml

# Linux systemd
systemctl start chiralite

# macOS launchd
launchctl load ~/Library/LaunchAgents/com.chiralite.daemon.plist
```

### 4 — Inspect and audit

```bash
chiralite status                       # active silo sessions
chiralite inspect --silo <uuid> path/to/file
chiralite audit tail                   # live audit log
chiralite force-sync --silo <uuid>     # trigger full reconciliation
```

---

## Troubleshooting

### `ModuleNotFoundError: No module named 'xdelta3'`

The PyPI package is not compatible. Rebuild from the fork:

```bash
bash scripts/build-xdelta3.sh
```

### `ModuleNotFoundError: No module named '_rapidhash_c'`

The CFFI extension was not compiled. Rebuild it:

```bash
python3 -m chiralite._rapidhash_build
```

### `ConnectionLost` on client start

- Verify the server URL and port in the config.
- Check that the server certificate is signed by the same CA as the client.
- If behind a TLS inspection proxy (ZScaler, CrowdStrike), the transport is
  plain `wss://` — application-layer auth is not affected.

### ClamAV: `ERROR: Could not connect to clamd`

- Ensure `clamav-daemon` is running: `systemctl status clamav-daemon`
- Verify the socket path matches the config (`clamd_socket` key).
- Run `sudo freshclam` if virus definitions are missing (clamd may refuse to start).

### Windows: `cl.exe not found`

Open a **Developer PowerShell for VS** (Start → Visual Studio → Developer PowerShell)
before running `install-windows.ps1`.
