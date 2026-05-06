# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> This file describes the architecture, security model, implementation decisions, and coding conventions
> for the `chiralite` project. Read it entirely before writing any code.

---

## Language

All repository content (code, comments, commit messages, PR descriptions, issue text, and documentation) must be written in **English**.

---

## Development Commands

```bash
# Install project + dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run a single test
pytest tests/test_crypto.py::test_handshake_challenge

# Type-check (must pass with --strict)
mypy --strict chiralite/

# Lint
ruff check chiralite/ tests/

# Format
ruff format chiralite/ tests/
```

The `clamd` daemon must be running for sandbox/AV tests. Test certificates live under `tests/fixtures/certs/` (not for production use).

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture Overview](#2-architecture-overview)
3. [Security Model](#3-security-model)
4. [Protocol Specification](#4-protocol-specification)
5. [Synchronization Engine](#5-synchronization-engine)
6. [Delta Transfers](#6-delta-transfers)
7. [Sandbox & Antivirus](#7-sandbox--antivirus)
8. [Filesystem & Permissions](#8-filesystem--permissions)
9. [Silo Model](#9-silo-model)
10. [Audit Logging](#10-audit-logging)
11. [Configuration](#11-configuration)
12. [Project Structure](#12-project-structure)
13. [Implementation Order](#13-implementation-order)
14. [Coding Conventions](#14-coding-conventions)
15. [Architecture Decision Records](#15-architecture-decision-records)

---

## 1. Project Overview

`chiralite` is a **real-time, bidirectional, event-driven file synchronization system** for Linux/macOS,
designed to operate securely over hostile networks (corporate proxies, TLS inspection appliances such as
ZScaler or CrowdStrike Falcon).

### Primary use case

Synchronize software project source trees between a developer workstation (macOS) and a remote VPS
(Linux), in real time, triggered by filesystem events (write, delete, rename).

### Key properties

- **Ultra-secure by design** — E2EE payload, certificate-based authentication, jail isolation,
  anti-forgery, audit trail.
- **Proxy-transparent** — transport is plain `wss://` on port 443; no mTLS at the network layer
  (broken by TLS inspection proxies); authentication is entirely applicative.
- **Delta-efficient** — only binary diffs (vcdiff, RFC 3284) are transmitted for modified files; full transfer
  is used only when no common base exists or when the delta exceeds 80% of the original size.
- **Multi-silo** — a single client manages N independent directory trees ("silos"), each on a
  dedicated WebSocket connection, with strict jail isolation on the server.
- **Antivirus gated** — all received content is reconstructed in a `tmpfs` sandbox and scanned by
  ClamAV (via `clamd`) before atomic write to disk.

---

## 2. Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│  CLIENT (macOS)                                                      │
│                                                                      │
│  watchdog (FSEvents)                                                 │
│       │  filesystem events                                           │
│       ▼                                                              │
│  Debouncer ──► SyncEngine ──► DeltaEngine ──► Transport (wss://)    │
│                    │                                                 │
│               SiloIndex (rapidhash + unix ts 64-bit UTC ns)         │
└──────────────────────────────┬───────────────────────────────────────┘
                               │  wss:// port 443  (one connection / silo)
                    ┌──────────▼──────────┐
                    │   ZScaler / proxy   │
                    │  (TLS inspection)   │
                    │  sees: binary opaque│
                    └──────────┬──────────┘
                               │
┌──────────────────────────────▼───────────────────────────────────────┐
│  SERVER (Linux VPS)                                                  │
│                                                                      │
│  Transport (wss://) ──► HandshakeHandler ──► SessionManager         │
│                                │                                     │
│                         SiloSession (jailed)                        │
│                                │                                     │
│              ┌─────────────────┼─────────────────┐                  │
│              ▼                 ▼                  ▼                  │
│         SyncEngine       DeltaEngine        Sandbox (tmpfs)         │
│         SiloIndex        vcdiff             ClamAV (clamd)          │
│              │                                    │                  │
│              └──────────► AtomicWriter ◄──────────┘                 │
│                           (chmod/chown/mtime)                        │
│                                │                                     │
│                          AuditLogger                                 │
└──────────────────────────────────────────────────────────────────────┘
```

### Layer summary

| Layer | Role | Technology |
|---|---|---|
| Transport | Bidirectional binary stream | WebSocket over TLS (`websockets`) |
| Auth | Mutual certificate challenge/response | X.509 + Ed25519 / ECDSA |
| Session key | Forward-secret symmetric key | X25519 ECDH + HKDF-SHA256 |
| Payload | Authenticated encryption | AES-256-GCM, monotonic nonce |
| Sync logic | Event ordering, conflict resolution | LWW, Unix ts 64-bit UTC ns |
| Event journal | Crash-safe async hashing, replay on start | Append-only JSONL + SQLite |
| Watcher | Filesystem event source | `watchdog` (FSEvents / inotify) |
| Delta | Binary diff/patch | `vcdiff` (RFC 3284) |
| Sandbox | Pre-write AV scan | ClamAV `clamd`, `tmpfs` |
| Filesystem | Safe atomic write | `O_CREAT` + `rename(2)` |
| Isolation | Per-silo jail | Applicative `safe_resolve()` |
| Audit | Tamper-evident event log | JSONL, gzip rotation |

---

## 3. Security Model

### 3.1 Threat model

| Threat | Mitigation |
|---|---|
| Network eavesdropping | TLS + AES-256-GCM E2EE (ZScaler sees binary opaque frames) |
| TLS interception (ZScaler) | Auth moved to application layer; TLS is tunnel only |
| Stolen client certificate | Short-lived certs (90d), CRL on CA, session token expiry |
| Replay attack | Handshake nonce (30s window) + monotonic nonce per GCM message |
| Timestamp forgery (LWW manipulation) | Server uses `recv_ts` (own clock) as LWW tiebreaker |
| Path traversal | `safe_resolve()` on every path operation; `../` and absolute paths rejected |
| UID/GID privilege escalation | Symbolic names only over wire; `root`/`sudo`/`wheel` deny list; uid 0 rejected |
| setuid/setgid escalation | Mode bits `04000`, `02000`, `01000` stripped unconditionally |
| Delta bomb | Max reconstructed size per silo; rapidhash verified after patch || Malicious file content | ClamAV scan in `tmpfs` before atomic write |
| clamd DoS | Per-file scan timeout; `MaxFileSize` configured |
| Silo escape / IDOR | `silo_id` validated against cert CN policy at handshake |
| TOCTOU race | `write(tmp) → fsync → rename(2)` — no existence checks before write |
| Audit log tampering | Append-only file, owned by `chiralite` daemon, no client write access |

### 3.2 PKI

```
offline CA (private key NEVER on server)
    │
    ├── server certificate  (Let's Encrypt, port 443 TLS)
    │
    └── client certificates (CA-signed, 90-day validity)
            Subject CN = client identity
            Used in applicative handshake only (not mTLS)
```

**CA operations must be performed offline.** See `pki/README.md` for procedures.

### 3.3 Applicative handshake

```
Client                                     Server
  │                                            │
  │──── WS Upgrade (wss://) ─────────────────►│
  │◄─── 101 Switching Protocols ───────────────│
  │                                            │
  │──── HELLO {client_cert_pem,                │
  │           nonce_c (32 bytes),              │
  │           ts_ns} ────────────────────────►│  (1) identity + freshness
  │                                            │
  │◄─── CHALLENGE {server_cert_pem,            │
  │               nonce_s (32 bytes),          │
  │               challenge (32 bytes)} ───────│  (2) server nonce + challenge
  │                                            │
  │──── RESPONSE {sig_c = sign(challenge       │
  │                      ‖ nonce_s, client_key)│
  │              ecdh_pub_c (X25519)} ────────►│  (3) proof of key possession
  │                                            │      + ephemeral DH key
  │◄─── ACCEPT {sig_s = sign(challenge         │
  │                    ‖ nonce_c, server_key)  │
  │            ecdh_pub_s (X25519),            │
  │            session_token,                  │
  │            silo_id_ack} ───────────────────│  (4) mutual proof + session
  │                                            │
  │  session_key = HKDF-SHA256(                │
  │      ECDH(ecdh_priv_c, ecdh_pub_s),        │
  │      salt = nonce_c ‖ nonce_s,             │
  │      info = b"chiralite-session-v1")        │
  │                                            │
  │  All subsequent frames: AES-256-GCM        │
  │  nonce = 96-bit, monotonically incremented │
  │  AAD   = {session_token, seq_number}       │
```

**Nonce validity window:** server rejects HELLO if `|ts_ns - server_clock| > 30_000_000_000` (30 s).

### 3.4 UID/GID policy

**Rule: numeric UID/GID values NEVER transit over the network.**

Only symbolic names (strings) are transmitted. The server applies a configurable mapping:

```python
# server-side resolution
def resolve_uid(name: str, policy: UidPolicy) -> int:
    if name in policy.deny:        # "root", "daemon", "0", ...
        raise SecurityError(f"uid name denied: {name!r}")
    mapped = policy.map.get(name, policy.default)  # "nobody" if unknown
    entry = pwd.getpwnam(mapped)
    if entry.pw_uid == 0:          # never resolve to uid 0
        raise SecurityError("resolved uid 0 is forbidden")
    return entry.pw_uid
```

Denied names (hardcoded, not overridable by config): `root`, `daemon`, `bin`, `sys`, `www-data`,
`sudo`, `wheel`, `shadow`, `0`.

### 3.5 Permission policy

```python
FORBIDDEN_BITS = 0o7000          # setuid | setgid | sticky — always stripped
MAX_FILE_MODE  = 0o644
MAX_DIR_MODE   = 0o755
SERVER_UMASK   = 0o022           # applied after mode from manifest

def sanitize_mode(raw: int, is_dir: bool) -> int:
    mode = raw & ~FORBIDDEN_BITS
    ceiling = MAX_DIR_MODE if is_dir else MAX_FILE_MODE
    return mode & ceiling & ~SERVER_UMASK
```

### 3.6 LWW tiebreaker

The server **never trusts the client's `mtime`** for conflict resolution. It uses:

```python
winner_ts = max(server_file_recv_ts, incoming_recv_ts)
```

Where `recv_ts` is the server-side Unix timestamp (nanoseconds, UTC) at the moment the COMMIT message
is processed. The client's `mtime_ns` is stored as metadata for display purposes only.

The server rejects any file entry whose `mtime_ns` is more than **300 seconds** in the future
relative to the server clock.

---

## 4. Protocol Specification

### 4.1 Message framing

All WebSocket frames after the handshake are **binary**. Each frame contains a single encrypted
message:

```
┌──────────────┬────────────────────┬───────────────────────────────┐
│  seq (8 B)   │  nonce (12 B)      │  ciphertext + GCM tag (16 B)  │
│  uint64 BE   │  monotonic counter │  AES-256-GCM encrypted JSON   │
└──────────────┴────────────────────┴───────────────────────────────┘
```

AAD (Additional Authenticated Data) = `session_token_bytes ‖ seq_bytes`

The `seq` counter starts at 0 and increments by 1 per message. The server rejects any out-of-order
or duplicate seq.

### 4.2 Message types (Pydantic models in `protocol/messages.py`)

```python
class MsgType(str, Enum):
    # Handshake
    HELLO             = "hello"
    CHALLENGE         = "challenge"
    RESPONSE          = "response"
    ACCEPT            = "accept"
    AUTH_ERROR        = "auth_error"

    # Sync control
    SYNC_REQUEST      = "sync.request"    # on (re)connect: request full index
    SYNC_STATE        = "sync.state"      # full SiloIndex snapshot
    BLACKLIST_SYNC    = "blacklist.sync"  # push updated blacklist to peer

    # File events
    FILE_WRITE        = "file.write"      # delta or full
    FILE_DELETE       = "file.delete"
    FILE_RENAME       = "file.rename"
    DIR_CREATE        = "dir.create"
    DIR_DELETE        = "dir.delete"
    DIR_RENAME        = "dir.rename"

    # Transfer
    TRANSFER_BEGIN    = "transfer.begin"  # announces incoming chunks
    TRANSFER_CHUNK    = "transfer.chunk"  # binary chunk (base64 in JSON)
    TRANSFER_COMMIT   = "transfer.commit" # all chunks sent
    TRANSFER_ACK      = "transfer.ack"    # server accepted + scan result
    TRANSFER_NACK     = "transfer.nack"   # server rejected (reason)

    # Conflict
    CONFLICT_NOTIFY   = "conflict.notify" # LWW overwrote a file

    # Session
    PING              = "ping"
    PONG              = "pong"
    SESSION_END       = "session.end"
```

### 4.3 FileEntry model

```python
class FileEntry(BaseModel):
    path: str               # relative, POSIX separators, no leading /

    # Identity is determined by the triple (path, size, rapidhash).
    # Collision probability across files of identical path+size is negligible
    # (~1/2^64). No SHA-256 anywhere in the protocol.
    rapidhash: int          # uint64, little-endian

    size: int               # bytes, of the FINAL reconstructed content
    mode: int               # POSIX octal (sanitized by server before apply)
    uid_name: str           # symbolic only
    gid_name: str           # symbolic only

    # Timestamp: split representation (Syncthing BEP style).
    # Avoids float precision loss when serialising large int64 via JSON/JS.
    mtime_s:  int           # Unix seconds     (int64)  — informational only
    mtime_ns: int           # sub-second part  (int32, 0-999_999_999)

    is_symlink: bool        # default False
    symlink_target: Optional[str]  # validated: must stay inside jail

    # Delta metadata
    delta_base_rapidhash: Optional[int]  # rapidhash of the base known by server
    is_full: bool                        # True if no delta available
```

### 4.4 State machine

```
IDLE ──► CONNECTING ──► AUTHENTICATING ──► SYNCING ──► ACTIVE
                                                │          │
                                           (reconcile)  (events)
                                                │          │
                                           ACTIVE ◄────────┘
                              │
                         RECONNECTING ──► CONNECTING
                         (on disconnect)
```

---

## 5. Synchronization Engine

### 5.1 SiloIndex

```python
@dataclass
class FileRecord:
    # Identity key: (path, size, rapidhash).
    # rapidhash is computed synchronously on every event — it is fast enough
    # (~10 GB/s) to stay on the hot path. No SHA-256 anywhere.
    rapidhash:  int         # uint64 — change-detection and wire dedup key

    size:      int
    mtime_s:   int          # Unix seconds     (int64)
    mtime_ns:  int          # sub-second part  (int32, 0–999_999_999)
    recv_ts_ns: int         # server clock at last sync (LWW tiebreaker)
    mode:      int
    uid_name:  str
    gid_name:  str
    deleted:   bool         # tombstone

class SiloIndex:
    silo_id: UUID
    node_id: str            # identifies this instance (client or server)
    records: dict[str, FileRecord]   # path → record

    def to_snapshot(self) -> dict    # serializable, for SYNC_STATE
    def apply_event(self, event) -> ConflictInfo | None
    def diff(self, remote: dict) -> list[FileEntry]   # what needs to be sent
```

The index is **persisted** on disk (SQLite, via `aiosqlite`) so it survives restarts. On reconnect,
the client sends `SYNC_REQUEST`; the server replies with `SYNC_STATE` (its current index snapshot);
the client computes the diff and sends only what changed.

> **Important:** the index is never written in-place during normal operation. All mutations go
> through the **EventJournal** first (section 5.5). The in-memory SiloIndex is authoritative;
> SQLite is the durable replay log. Because rapidhash is computed synchronously, there is no
> pending state: every `FileRecord` is complete and immediately usable for sync decisions.

### 5.2 Watcher and debouncer

```python
# sync/watcher.py
class SiloWatcher:
    """
    Wraps watchdog for a single silo root path.
    Applies blacklist filtering before emitting events.
    Debounces bursts per-file before forwarding to SyncEngine.
    """
```

**Debounce algorithm** (per file, configurable):

```
on event(path):
    mark path as dirty, record t_first[path] = now() if not already dirty
    cancel pending timer[path]
    if now() - t_first[path] > max_delay_ms:
        flush(path)           # absolute cap — flush even under load
    else:
        schedule timer[path] = flush(path) after debounce_ms

on len(dirty_set) > max_dirty_files:
    flush_all()               # git checkout / make clean protection
```

Default parameters (all configurable in YAML):

```yaml
burst:
  debounce_ms: 200
  max_delay_ms: 1500
  max_dirty_files: 50
```

### 5.3 Blacklist

Blacklist patterns are **glob-style** (same semantics as `.gitignore`). They are:
- Defined at **global level** (applies to all silos)
- Overridable per **silo** (`blacklist_extra` adds patterns, `whitelist` forces inclusion)
- **Synchronized** — when the server-side blacklist is updated, it is pushed to all connected
  clients via `BLACKLIST_SYNC`; when a client updates its local override, it is pushed to the server

**Default global blacklist:**

```yaml
ignore_global:
  blacklist:
    - "**/.git/**"
    - "**/.git"
    - "**/__pycache__/**"
    - "**/*.pyc"
    - "**/*.pyo"
    - "**/.DS_Store"
    - "**/Thumbs.db"
    - "**/*.swp"
    - "**/*~"
    - "**/.#*"
    - "**/*.tmp"
    - "**/.pytest_cache/**"
    - "**/node_modules/**"
    - "**/.venv/**"
    - "**/.mypy_cache/**"
    - "**/.ruff_cache/**"
    - "**/dist/**"
    - "**/build/**"
    - "**/*.egg-info/**"
    - "**/.idea/**"
    - "**/.vscode/**"
```

Pattern matching uses `pathspec` (gitignore-style) for consistency.

### 5.4 Conflict resolution (LWW)

```python
def resolve_conflict(
    local: FileRecord,
    remote: FileRecord,
    server_recv_ts_ns: int,    # authoritative
) -> Literal["keep_local", "apply_remote"]:
    # Server recv_ts is the tiebreaker — never the client mtime
    return "apply_remote" if server_recv_ts_ns > local.recv_ts_ns else "keep_local"
```

Every LWW overwrite is recorded in the audit log with:
- `path`, `silo_id`, `client_cn`
- `overwritten_rapidhash`, `overwritten_recv_ts_ns`
- `winner_rapidhash`, `winner_recv_ts_ns`

### 5.5 EventJournal — crash-safe index durability

#### Rationale

rapidhash is computed synchronously on the hot path (watcher event → SyncEngine). The only
remaining durability risk is the window between the in-memory index update and the SQLite commit:
if the process is killed in that window, the index is inconsistent with disk on restart.
The EventJournal eliminates this window.

#### Pipeline

```
watcher emits event
        |
        v
EventJournal.append(event)       # 1. fsync-safe JSONL append
        |                        #    rapidhash + size computed synchronously
        v
in-memory SiloIndex updated      # 2. index is immediately complete and usable
        v
SQLite upsert (async)            # 3. durable write (may lag by one event loop tick)
        |
        v
EventJournal.commit(event_id)    # 4. journal entry marked DONE
        |
        v
EventJournal.prune(event_id)     # 5. entry removed from journal
```

Because rapidhash is synchronous and fast, there is no pending state: every FileRecord is
complete from step 2 onward. The journal exists solely to recover from a crash between steps 2 and 4.

#### EventJournal entry schema (JSONL)

```jsonc
{
  "event_id":    "01J...",           // ULID: monotonic, sortable, unique
  "status":      "pending",          // pending | done | superseded
  "silo_id":     "550e8400-...",
  "path":        "src/main.py",
  "op":          "write",            // write | delete | rename | mkdir | rmdir
  "rapidhash":   12345678901234567,  // uint64
  "size":        4096,
  "mtime_s":     1714000000,
  "mtime_ns":    123456789,
  "appended_ns": 1714000000000000000,
  "committed_ns": null               // filled on commit
}
```

Journal file: `<state_dir>/silo-<silo_id>/journal.jsonl`

#### Startup replay

Before accepting watcher events or network connections:

```python
async def replay_journal(journal: EventJournal, index: SiloIndex) -> None:
    """
    1. Load all journal entries with status != 'done'.
    2. For each entry, stat() the actual file on disk.
    3a. stat matches (size, mtime_s, mtime_ns) -> unchanged since crash:
          recompute rapidhash, update index, mark done.
    3b. stat does not match (file changed or gone) -> mark 'superseded';
          emit a fresh synthetic event so SyncEngine reprocesses the file.
    4. Prune all 'done' and 'superseded' entries from the journal.
    """
```

This guarantees index consistency after any crash or unclean shutdown without a full rescan.

#### Event supersession

A pending journal entry for `path` is **superseded** (marked and pruned) when:

- A newer event for the same `path` arrives (the pending entry is no longer the latest state)
- At replay time, `(size, mtime_s, mtime_ns)` on disk differs from the entry
- A `delete` or `rename` event arrives while a `write` is still pending for that path

```python
def supersede(self, path: str, reason: str) -> None:
    """Mark all pending journal entries for path as superseded and prune."""
```

---

## 6. Delta Transfers

### 6.1 vcdiff integration

```python
# delta/differ.py
def compute_delta(old_content: bytes, new_content: bytes) -> DeltaResult:
    """
    Encodes a vcdiff (RFC 3284) delta (patch).
    Falls back to full transfer if patch_size / new_size > DELTA_THRESHOLD.
    Uses open-vcdiff encoder; output is wire-compatible with any RFC 3284 decoder.
    """

# delta/patcher.py
def apply_delta(base_content: bytes, patch: bytes, expected_rapidhash: int) -> bytes:
    """
    Decodes and applies a vcdiff patch. Verifies rapidhash of result before returning.
    Raises DeltaError on mismatch or malformed patch.
    """
```

**Fallback policy:**

```python
DELTA_THRESHOLD = 0.80   # if patch > 80% of new file size, send full
MAX_RECONSTRUCTED_SIZE = 512 * 1024 * 1024   # 512 MiB hard limit (per silo config)
```

### 6.2 Server-side base management

When the server receives `TRANSFER_BEGIN`, it looks up `delta_base_rapidhash` in the silo index.
If not found (first sync, or base was deleted), the client must send `is_full = True`.

The client queries the server's known rapidhash via `SYNC_STATE` diff before computing deltas.

### 6.3 Chunking

Large deltas or full files are chunked:

```yaml
transfer:
  chunk_size_bytes: 262144   # 256 KiB default, configurable
```

Each chunk is independently AES-256-GCM encrypted (same session key, incremented nonce).
The final `TRANSFER_COMMIT` includes the `rapidhash` of the fully reconstructed file.

---

## 7. Sandbox & Antivirus

### 7.1 Pipeline

```
chunks received → decrypt in memory → assemble in tmpfs → vcdiff decode if delta
→ rapidhash verify → ClamAV scan via clamd → atomic write to jail
                          │
                    QUARANTINE if infected
                    (outside jail, not accessible to client)
```

### 7.2 tmpfs management

```python
# sandbox/tmpfs.py
class TmpfsWorkspace:
    """
    Creates an isolated working directory under a tmpfs mount point.
    Cleaned up on __exit__ regardless of outcome.
    Never writes unverified content to the real jail.
    """
    mount_point: Path    # /run/chiralite/sandbox (pre-mounted tmpfs)
    workspace:   Path    # /run/chiralite/sandbox/<session_id>/<transfer_id>/
```

The `tmpfs` mount is **pre-mounted** at server startup (not per-transfer). Each transfer gets its
own subdirectory, cleaned up atomically after scan.

### 7.3 ClamAV client

```python
# sandbox/clamav.py
class ClamdClient:
    """
    Async client to clamd Unix socket. Never shells out to clamscan.
    Uses INSTREAM protocol for in-memory scanning.
    """
    socket_path: Path = Path("/var/run/clamav/clamd.ctl")
    scan_timeout_s: float = 30.0
```

ClamAV result → `CLEAN` | `INFECTED {virus_name}` | `ERROR {reason}`

On `INFECTED`: quarantine the file, log `CRITICAL` audit event, send `TRANSFER_NACK` with
`reason="quarantine"`.

---

## 8. Filesystem & Permissions

### 8.1 Atomic write

```python
# filesystem/writer.py
async def atomic_write(
    jail_root: Path,
    relative_path: str,
    content: bytes,
    entry: FileEntry,
    uid_policy: UidPolicy,
    gid_policy: GidPolicy,
) -> None:
    dest = safe_resolve(jail_root, relative_path)
    dest.parent.mkdir(parents=True, exist_ok=True)

    tmp = dest.parent / f".chiralite_tmp_{uuid4().hex}"
    try:
        async with aiofiles.open(tmp, "wb") as f:
            await f.write(content)
            await f.flush()
            os.fsync(f.fileno())

        uid = resolve_uid(entry.uid_name, uid_policy)
        gid = resolve_gid(entry.gid_name, gid_policy)
        mode = sanitize_mode(entry.mode, is_dir=False)

        os.chown(tmp, uid, gid)
        os.chmod(tmp, mode)

        # set mtime (informational, from client manifest)
        mtime_s = entry.mtime_ns / 1e9
        os.utime(tmp, (mtime_s, mtime_s))

        tmp.rename(dest)    # atomic on POSIX (same filesystem guaranteed)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
```

### 8.2 Path validation

```python
# filesystem/validator.py
def safe_resolve(jail_root: Path, relative: str) -> Path:
    """
    Validates and resolves a relative path within jail_root.
    Raises SecurityError on:
      - absolute paths
      - path traversal (..)
      - symlinks pointing outside jail
      - names containing null bytes
    """
    if "\x00" in relative:
        raise SecurityError("null byte in path")
    p = Path(relative)
    if p.is_absolute():
        raise SecurityError(f"absolute path rejected: {relative!r}")
    resolved = (jail_root / p).resolve()
    jail_resolved = jail_root.resolve()
    if not str(resolved).startswith(str(jail_resolved) + "/"):
        raise SecurityError(f"path traversal detected: {relative!r}")
    return resolved
```

---

## 9. Silo Model

### 9.1 One WebSocket connection per silo

Each silo is an independent session. The `silo_id` (UUID) is declared in the `HELLO` message.
The server verifies `silo_id` against the policy for the client's CN before proceeding.

A single client binary manages N concurrent silo connections.

### 9.2 Jail isolation (applicative)

```python
@dataclass
class SiloSession:
    silo_id:    UUID
    client_cn:  str
    jail_root:  Path          # absolute, resolved, never changes after handshake
    allowed_ops: set[OpType]  # READ | WRITE | DELETE | RENAME
    uid_policy:  UidPolicy
    gid_policy:  GidPolicy
    blacklist:   list[str]    # synchronized patterns
```

`jail_root` is resolved once at session creation. Every filesystem operation calls
`safe_resolve(session.jail_root, relative_path)` — no exceptions.

### 9.3 Server-side policy (YAML)

```yaml
# /etc/chiralite/server.yaml
silos:
  - id: "550e8400-e29b-41d4-a716-446655440000"
    name: "project-alpha"
    server_root: /srv/chiralite/alpha
    allowed_clients:
      - cn: "fm-macbook"
        ops: [READ, WRITE, DELETE, RENAME]
    uid_policy:
      map:
        "fm": "deploy"
      default: "nobody"
      deny: ["root", "daemon", "bin", "sys", "www-data", "sudo", "wheel", "0"]
    gid_policy:
      map:
        "staff": "chiralite"
      default: "nogroup"
      deny: ["root", "sudo", "wheel", "shadow"]
    sandbox:
      max_reconstructed_size_mb: 256
      scan_timeout_s: 30
    transfer:
      chunk_size_bytes: 262144
      delta_threshold: 0.80
    burst:
      debounce_ms: 200
      max_delay_ms: 1500
      max_dirty_files: 50
    ignore:
      blacklist_extra: []
      whitelist: []
```

---

## 10. Audit Logging

### 10.1 Format

One JSON object per line (JSONL). UTF-8, append-only.

```json
{
  "ts_ns": 1714000000000000000,
  "ts_iso": "2024-04-25T10:00:00.000000Z",
  "severity": "INFO",
  "event": "file.write",
  "client_cn": "fm-macbook",
  "silo_id": "550e8400-e29b-41d4-a716-446655440000",
  "path": "src/main.py",
  "detail": {
    "rapidhash_before": 12345678901234567,
    "rapidhash_after": 98765432109876543,
    "recv_ts_ns": 1714000000000000001,
    "delta": true,
    "size_bytes": 1234
  }
}
```

### 10.2 Event types

| Event | Severity | Description |
|---|---|---|
| `auth.ok` | INFO | Successful handshake |
| `auth.fail` | WARN | Failed handshake (reason) |
| `auth.replay` | ERROR | Nonce replay detected |
| `file.write` | INFO | File written (delta or full) |
| `file.delete` | INFO | File deleted |
| `file.rename` | INFO | File renamed |
| `conflict.lww` | WARN | LWW overwrite — includes both rapidhash values |
| `quarantine` | CRITICAL | ClamAV detection |
| `security.path_traversal` | CRITICAL | Path traversal attempt |
| `security.uid_denied` | CRITICAL | UID/GID escalation attempt |
| `security.mode_stripped` | WARN | setuid/setgid bits stripped |
| `security.ts_future` | WARN | mtime_ns > server clock + 5min |
| `session.start` | INFO | Silo session opened |
| `session.end` | INFO | Silo session closed |
| `blacklist.sync` | INFO | Blacklist update pushed |

### 10.3 Rotation

```python
# security/audit.py — uses logging.handlers.RotatingFileHandler
AUDIT_CONFIG = {
    "path":             "/var/log/chiralite/audit.jsonl",
    "max_bytes":        100 * 1024 * 1024,   # 100 MiB
    "backup_count":     10,
    "compress":         True,   # gzip via custom rotator hook
}
```

Rotation hook compresses the rolled file with `gzip` (level 9) synchronously before the next write.
Compressed files: `audit.jsonl.1.gz` … `audit.jsonl.10.gz`.

The audit log directory is owned by `chiralite:chiralite`, mode `0o750`. Log files are `0o640`.
No client process has write access to this directory.

---

## 11. Configuration

### 11.1 Client configuration

```yaml
# ~/.config/chiralite/config.yaml

identity:
  cert: ~/.config/chiralite/client.crt   # CA-signed, 90-day validity
  key:  ~/.config/chiralite/client.key   # Ed25519 private key

server:
  url:    wss://chiralite.example.com:443
  ca:     ~/.config/chiralite/ca.crt     # CA bundle for server cert validation

silos:
  - id:         "550e8400-e29b-41d4-a716-446655440000"
    name:       "project-alpha"
    local_path: ~/projects/alpha
    remote_path: /srv/chiralite/alpha
    conflict_strategy: lww

    ignore:
      blacklist_extra:
        - "**/.env"
        - "**/secrets/**"
      whitelist:
        - "**/.env.example"

    burst:
      debounce_ms: 200
      max_delay_ms: 1500
      max_dirty_files: 50
```

### 11.2 CLI commands

```
chiralite keygen                  # generate CA + client cert (offline)
chiralite sign <csr>              # sign a CSR with the CA (offline)
chiralite start                   # start daemon (all silos)
chiralite start --silo <name>     # start one silo
chiralite status                  # show silo states + last sync
chiralite inspect <silo> <path>   # show FileRecord for a path
chiralite force-sync <silo>       # trigger full reconciliation
chiralite audit tail              # tail -f audit log (formatted)
```

---

## 12. Project Structure

```
chiralite/
├── CLAUDE.md                        ← this file
├── pyproject.toml
├── pki/
│   └── README.md                    ← CA offline procedures (openssl commands)
│
├── chiralite/
│   ├── __init__.py
│   │
│   ├── crypto/
│   │   ├── certificates.py          # X.509 parse, validate, CA chain verify
│   │   ├── handshake.py             # HELLO/CHALLENGE/RESPONSE/ACCEPT logic
│   │   ├── session.py               # X25519 ECDH + HKDF-SHA256 derivation
│   │   └── payload.py               # AES-256-GCM encrypt/decrypt, seq/nonce
│   │
│   ├── protocol/
│   │   ├── messages.py              # All Pydantic message models + MsgType enum
│   │   ├── framing.py               # Binary frame encode/decode (seq+nonce+ciphertext)
│   │   └── state_machine.py         # Connection state machine (IDLE→ACTIVE→...)
│   │
│   ├── sync/
│   │   ├── watcher.py               # watchdog wrapper + blacklist filter + debouncer
│   │   ├── engine.py                # SyncEngine: orchestrates events, diffs, sends
│   │   ├── index.py                 # SiloIndex: FileRecord store, rapidhash-based
│   │   ├── journal.py               # EventJournal: crash-safe JSONL + replay + prune
│   │   ├── conflict.py              # LWW resolution + audit notification
│   │   ├── reconciler.py            # On-(re)connect full diff + selective resync
│   │   └── clock.py                 # ServerClock: recv_ts_ns, mtime validation window
│   │
│   ├── delta/
│   │   ├── differ.py                # vcdiff encoder + threshold fallback
│   │   ├── patcher.py               # vcdiff decoder + rapidhash post-verify
│   │   └── policy.py                # DELTA_THRESHOLD, MAX_RECONSTRUCTED_SIZE
│   │
│   ├── sandbox/
│   │   ├── clamav.py                # async clamd socket client (INSTREAM)
│   │   ├── tmpfs.py                 # TmpfsWorkspace context manager
│   │   └── quarantine.py            # quarantine dir management
│   │
│   ├── filesystem/
│   │   ├── writer.py                # atomic_write: tmp→fsync→rename
│   │   ├── permissions.py           # sanitize_mode, resolve_uid, resolve_gid
│   │   └── validator.py             # safe_resolve, path traversal detection
│   │
│   ├── transport/
│   │   └── websocket.py             # wss:// client+server, reconnect with backoff
│   │
│   ├── trust/
│   │   ├── store.py                 # TrustStore: CA bundle + pinned certs
│   │   └── policy.py                # SiloPolicy: CN → {silo_id, ops, uid/gid maps}
│   │
│   ├── silo/
│   │   ├── config.py                # SiloConfig Pydantic model
│   │   ├── registry.py              # SiloRegistry: manages active sessions
│   │   └── session.py               # SiloSession: jail_root, policy, ws connection
│   │
│   ├── security/
│   │   ├── audit.py                 # AuditLogger: JSONL + rotating gzip
│   │   ├── ratelimit.py             # per-CN and per-silo rate limiting
│   │   └── validator.py             # central security checks (timestamps, modes, uids)
│   │
│   ├── server.py                    # Server entry point (asyncio)
│   ├── client.py                    # Client entry point (asyncio)
│   └── cli.py                       # CLI (typer): keygen/start/status/inspect/audit
│
└── tests/
    ├── conftest.py
    ├── test_crypto.py
    ├── test_handshake.py
    ├── test_delta.py
    ├── test_sandbox.py
    ├── test_index.py
    ├── test_journal.py
    ├── test_watcher.py
    ├── test_filesystem.py
    ├── test_policy.py
    ├── test_audit.py
    └── fixtures/
        ├── certs/                   # test CA + client certs (not production)
        └── files/                   # sample files for delta tests
```

---

## 13. Implementation Order

Implement modules in this order. Each step is independently testable before proceeding.

| Step | Module(s) | Why first |
|---|---|---|
| 1 | `crypto/` | All other modules depend on it |
| 2 | `protocol/messages.py` | Defines the data contract for everything |
| 3 | `sync/index.py` | Core state — testable with no network |
| 4 | `sync/journal.py` | Crash-safety layer; depends only on index |
| 5 | `filesystem/validator.py` + `filesystem/permissions.py` | Security-critical, pure functions |
| 6 | `delta/differ.py` + `delta/patcher.py` | Testable with local files |
| 7 | `sync/watcher.py` | Testable against a local temp directory |
| 8 | `transport/websocket.py` | Thin wrapper, no business logic |
| 9 | `protocol/framing.py` + `protocol/state_machine.py` | Needs crypto + transport |
| 10 | `crypto/handshake.py` | Needs framing + certs |
| 11 | `sandbox/tmpfs.py` + `sandbox/clamav.py` | Server-side only |
| 12 | `filesystem/writer.py` | Needs validator + permissions + tmpfs |
| 13 | `sync/engine.py` + `sync/reconciler.py` | Needs index + journal + watcher + delta + transport |
| 14 | `silo/` + `trust/` | Needs session + policy |
| 15 | `security/audit.py` + `security/ratelimit.py` | Cross-cutting, add last |
| 16 | `server.py` + `client.py` | Assembles everything |
| 17 | `cli.py` | Surface; implement last |

---

## 14. Coding Conventions

### General

- **Python ≥ 3.11** — use `match`, `ExceptionGroup`, `tomllib` where appropriate
- **Async-first** — all I/O is `async`/`await`; no blocking calls in the event loop
- **Fully typed** — every function has type annotations; `mypy --strict` must pass
- **No bare `except`** — always catch specific exception types
- **No `print()`** — use `logging` in library code, `typer.echo()` in CLI only
- **Fail closed** — on any validation error, reject the operation and log; never silently degrade

### Dependencies

```toml
[project.dependencies]
websockets    = ">=12.0"
cryptography  = ">=42.0"
aiofiles      = ">=23.0"
aiosqlite     = ">=0.20"
pydantic      = ">=2.0"
watchdog      = ">=4.0"
pathspec      = ">=0.12"    # gitignore-style pattern matching
typer         = ">=0.12"
pyyaml        = ">=6.0"
open-vcdiff   = ">=1.0"     # vcdiff (VCDIFF, RFC 3284) encoder/decoder
python-rapidhash = ">=1.0"  # rapidhash (64-bit) — sole hash function, index + wire
python-ulid   = ">=3.0"     # ULID for EventJournal event_id

[project.optional-dependencies]
dev = ["pytest", "pytest-asyncio", "mypy", "ruff"]
```

**No `subprocess` for crypto operations.** All cryptography goes through the `cryptography` library.
**`vcdiff` via pure Python or C bindings.** No subprocess forking.
**`clamd` socket only** — never `subprocess.run(["clamscan", ...])`.

### Security rules (enforced in code review)

- `safe_resolve()` must be called on **every** path received from a remote peer — no exceptions
- UID/GID numeric values must **never** appear in any message model or wire format
- `sanitize_mode()` must be called on **every** mode value before `os.chmod()`
- Session keys must be **zeroed** (`ctypes.memset`) after use where possible
- Secrets (private keys, session keys) must **never** appear in log output

### Tests

- Every security-critical function (`safe_resolve`, `sanitize_mode`, `resolve_uid`, handshake
  challenge/response) must have dedicated unit tests including adversarial inputs
- Integration tests use a local `wss://` server with test certificates (fixtures/certs/)
- `pytest-asyncio` in `auto` mode

---

## 15. Architecture Decision Records

### ADR-001 — Applicative auth instead of mTLS

**Context:** TLS inspection proxies (ZScaler, CrowdStrike Falcon) terminate the client TLS session
and re-establish a new one to the server. This breaks mTLS: the client certificate is not forwarded.

**Decision:** Use standard TLS (Let's Encrypt cert on server) for transport. Implement mutual
authentication as an applicative protocol inside the WebSocket stream, using X.509 certificates
only for cryptographic identity proof (challenge/response), not for TLS handshake.

**Consequences:** The transport layer provides confidentiality against external observers (not the
proxy). The applicative layer provides mutual authentication and E2EE independently of the proxy.

**Operational requirements:**
- Client certificates must be rotated before expiry. A 90-day validity window requires renewal at
  60 days via `chiralite renew --cert <path>` (invokes the offline CA, requires manual signing).
- A server-side CRL (Certificate Revocation List) on the CA must be checked at handshake time to
  block compromised certs without redeployment.
- Graceful expiry: if a client cert is within 7 days of expiry, the server logs a WARN audit event
  but does not reject the connection. The operator is given a grace period to renew before hard
  rejection at expiry + 1 hour.
- Session tokens (issued post-handshake, ~1 hour TTL) are the short-lived credentials; certs are
  long-term identity. A revoked cert invalidates all active sessions immediately.

---

### ADR-002 — LWW with server recv_ts as tiebreaker

**Context:** Bidirectional sync with concurrent edits requires a conflict resolution strategy.
Vector clocks were considered but add complexity without benefit when a single tiebreaker suffices.

**Decision:** Last-Write-Wins. The tiebreaker is the **server's reception timestamp** (`recv_ts_ns`),
not the client's `mtime`. Client `mtime` is stored as informational metadata only.

**Consequences:** Client clock skew or timestamp forgery cannot influence conflict resolution.
A small risk of silent data loss exists if two clients write the same file within the same server
clock granularity (< 1ms in practice). Mitigated by audit log of every LWW overwrite.

**Conflict matrix and guardrails:**

| Scenario | Outcome | Detection | Recovery |
|---|---|---|---|
| Two clients write same file concurrently | One is silently overwritten (LWW) | `conflict.lww` audit event includes both rapidhash values | Operator reviews audit log; older version recoverable from VCS if client also pushes |
| Client A renames file, Client B writes it | A's rename wins (later recv_ts) or B's write wins | `conflict.lww` audit event | Both operations succeed in sequence (no data loss, metadata change) |
| Rapid edits by one client | No conflict; events debounced and serialized | N/A — single-client causality preserved | N/A |
| Network partition: both sides diverge | Resolved on reconnect via `SYNC_STATE` diff | Delta shows both versions existed; audit log has history | Full rescan and LWW resolution; older version in audit log |

**Operational guardrails:**
- No shared editing of the same file simultaneously. Enforce via code review or editor locking
  (e.g., git pre-commit hook: `if multiple .git/index.locks, fail`).
- Audit log retention must be ≥ 30 days so operators can recover from accidental overwrites.
- Client-side UI must show last-sync timestamp per file; if a file is older than local version,
  offer a "keep local" option before pull.

---

### ADR-003 — vcdiff (RFC 3284) over bsdiff and rsync

**Context:** Delta transfer is required for efficient bandwidth usage on source code. Options
considered: rsync rolling-checksum, bsdiff, and vcdiff.

**Decision:** Use **vcdiff** (RFC 3284, open-vcdiff). Rationale:
- vcdiff is standardized (RFC 3284) and widely implemented across platforms
- Binary diff quality is competitive with bsdiff (sometimes superior on structured data)
- Streaming capability: can encode/decode without holding the entire source in memory
- Industry adoption: used by Google Chrome updates, Android OTA updates
- No UNIX-specific dependencies (unlike rsync daemon)

The fallback to full transfer (delta > 80% of file size) handles cases where vcdiff underperforms.

**Consequences:** vcdiff requires both source and target in memory for computing the diff (like
bsdiff). On very large files (> 100 MiB) memory usage may be substantial. Mitigated by
`MAX_RECONSTRUCTED_SIZE` limit and the full-transfer fallback.

**DoS mitigation — vcdiff decoding:**

The vcdiff (RFC 3284) format can be exploited for denial-of-service attacks if decoded naively:

| Attack vector | Exploitation | Mitigation |
|---|---|---|
| **Expansion bomb** | Patch of 1 KB expands to 100 GB during decode | `MAX_RECONSTRUCTED_SIZE` enforced before decode; rejects if result would exceed limit |
| **Pathological decoder input** | Malformed VCDIFF magic bytes or section lengths cause infinite loops | Validate VCDIFF header magic (`0xD6 0xC3 0xC4`) and section CRC before feeding to decoder |
| **Slow decoder** | Complex pointer chains in VCDIFF instructions cause CPU spike | `DECODE_TIMEOUT_S` (default 30s) kills the decoder if decoding stalls; raises `DeltaTimeoutError` |

Implementation detail: the `apply_delta()` function must enforce all three checks:

```python
def apply_delta(base_content: bytes, patch: bytes, expected_rapidhash: int) -> bytes:
    # 1. Validate VCDIFF structure (fail fast on malformed patches)
    if not patch.startswith(b'ÖÃÄ'):
        raise DeltaError("invalid VCDIFF magic")
    
    # 2. Predict output size from VCDIFF header (before actual decode)
    predicted_size = parse_vcdiff_target_size(patch)
    if predicted_size > MAX_RECONSTRUCTED_SIZE:
        raise DeltaError(f"predicted output {predicted_size} exceeds limit")
    
    # 3. Decode with timeout
    result = asyncio.wait_for(
        vcdiff_decoder.decode_async(base_content, patch),
        timeout=DECODE_TIMEOUT_S
    )
    
    # 4. Verify result integrity
    if rapidhash(result) != expected_rapidhash:
        raise DeltaError("rapidhash mismatch after decode")
    return result
```

---

### ADR-004a — One WebSocket connection per silo

**Context:** Multi-silo support. Options: multiplex silos over one connection (e.g., with a
`silo_id` header per message) or dedicate one connection per silo.

**Decision:** One connection per silo. Rationale: simpler state machine (no mux/demux); failure
isolation (one silo disconnect does not affect others); cleaner jail binding at session level;
`silo_id` declared once in `HELLO` and never re-verified per message.

**Consequences:** N silos = N TCP connections. Acceptable for typical use (2–5 silos per client).

---

### ADR-004b — Applicative silo jail isolation (limits and hardening)

**Context:** Multi-silo support requires isolation: Client A should not access Silo B's files.
The question is what threat model the isolation protects against.

**Decision:** Implement **applicative sandbox** via `safe_resolve()` path validation and dedicated
`jail_root` per silo. This prevents application-level attacks (path traversal, symlink escape, IDOR).

**Threat model protected against:**
- Malicious client sending `path = "../../etc/passwd"`
- Symlink attack: client creates symlink in silo root pointing to `/etc/shadow`
- IDOR: client trying to access another silo's files via crafted `silo_id`
- Directory traversal via `.` and `..`

**Threat model NOT protected against (by design):**
- Kernel exploits (Dirty COW, io_uring CVE, etc.) — these are OS-level risks, not application bugs
- Physical access to the VPS
- Compromised OS or hypervisor

**Operational hardening (recommended):**

The applicative sandbox must be **paired with OS-level sandboxing** for production deployment:

1. **Run daemon under dedicated user** — `chiralite` user, no shell, UID > 1000:
   ```bash
   useradd -r -s /usr/sbin/nologin chiralite
   chown chiralite:chiralite /srv/chiralite
   chmod 0700 /srv/chiralite
   ```

2. **Apply AppArmor or SELinux policy** — restrict the daemon process:
   ```
   /usr/local/bin/chiralite-server {
     /srv/chiralite/** rw,
     /var/log/chiralite/** rw,
     /run/chiralite/ rw,
     deny /etc/** r,
     deny /home/** r,
   }
   ```

3. **Enable seccomp-bpf** — restrict system calls (e.g., reject `fork`, `exec`, raw network):
   ```python
   # In server startup: prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)
   # Allow: mmap, read, write, mprotect, poll, epoll_wait, openat, stat, close
   # Deny: fork, execve, ptrace, socket (via vcdiff decoder only)
   ```

4. **Set `no_new_privs`** — prevent privilege escalation via setuid/setgid:
   ```bash
   prctl(PR_SET_NO_NEW_PRIVS, 1)
   ```

5. **Use read-only root filesystem** — mount `/srv/chiralite` on a separate volume, mark rest as `ro`:
   ```bash
   mount / -o remount,ro
   mount /srv/chiralite -o defaults
   ```

**Consequences:**
- The applicative jail prevents accidental misconfiguration or logic bugs from leaking data between
  silos.
- OS-level sandboxing (AppArmor, seccomp) prevents OS-level attacks from being leveraged to escape
  the jail.
- Together they provide **defense in depth**. If one layer is breached, the other mitigates impact.

### ADR-005 — ClamAV via clamd socket (not clamscan subprocess)

**Context:** Antivirus scan of received files before write.

**Decision:** Use `clamd` Unix socket with INSTREAM protocol. Never fork `clamscan` per file.

**Rationale:** `clamscan` startup overhead (~300ms) is prohibitive for frequent small file events.
`clamd` keeps signatures loaded in memory; scan latency is ~5ms for small files.

**Consequences:** `clamd` must be running and its socket accessible. Server startup must check
clamd availability and refuse to start (or warn) if not reachable.

---

### ADR-006 — Symbolic UID/GID names only on the wire

**Context:** macOS and Linux use different numeric UID/GID namespaces. Transferring numeric IDs
would either cause mismatches or, worse, grant files the wrong ownership (including root if uid=0
happens to collide).

**Decision:** Only symbolic names (strings) transit the wire. The server resolves names to local
numeric IDs using a configurable mapping with an explicit deny list. UID 0 is never assigned
regardless of mapping.

**Consequences:** Unknown user/group names map to `nobody`/`nogroup` (configurable default).
The operator must configure the mapping when client and server use different usernames.

---

### ADR-007 — rapidhash as the sole hash function (index and wire)

**Context:** SHA-256 was initially considered for wire integrity. The comparison sequence used to
detect file identity is `(path, size, rapidhash)`. Given that path and size are already compared
first, the probability of a false match on rapidhash alone (collision across two files of identical
path and size but different content) is ~1/2^64 per pair — negligible in practice.

**Decision:** Use **rapidhash** (64-bit) everywhere — local index and wire protocol. No SHA-256
anywhere in the codebase. The identity triple `(path, size, rapidhash)` is the sole change-detection
key. rapidhash is computed synchronously on the hot path (~10 GB/s, no async needed).

The **EventJournal** (append-only JSONL, fsync'd) provides crash-safety for the narrow window
between in-memory index update and SQLite commit. On startup the journal is replayed; entries are
pruned once confirmed in SQLite.

**Rationale for rapidhash over xxHash3/BLAKE3:** single 64-bit output, ~10 GB/s throughput, zero
allocation, no external C dependency. The 64-bit width is sufficient given the `(path, size)` prefix
already constrains the collision domain. xxHash3-128 is an acceptable alternative if 128-bit output
is preferred.

**Consequences:**
- `cryptography` library is no longer needed for hashing (still needed for AES-GCM, ECDH, certs).
- delta_base identified by `delta_base_rapidhash` (uint64) instead of a hex SHA-256 string.
- Tests must cover the crash-replay path: kill between `journal.append` and SQLite commit,
  then verify `replay_journal` produces a consistent index.
- The vcdiff post-decode step recomputes rapidhash of the reconstructed file and compares
  with `FileEntry.rapidhash` before the ClamAV scan.

---

### ADR-008 — Split mtime into mtime_s (int64) + mtime_ns (int32)

**Context:** A single `mtime_ns` int64 (nanosecond Unix timestamp) loses precision when serialised
through JSON parsers that use IEEE 754 doubles (JavaScript engines, some Python json libraries in
edge cases). Values above 2^53 are not exactly representable as float64.

**Decision:** Split into `mtime_s` (int64, Unix seconds) and `mtime_ns` (int32, sub-second
nanoseconds, 0–999_999_999), following the Syncthing BEP convention. Both fields appear in
`FileEntry` (wire) and `FileRecord` (index). Reconstruction: `mtime = mtime_s + mtime_ns / 1e9`.

**Consequences:** Slightly larger message payload (+4 bytes per entry). All code reading or writing
mtime must use the two-field form. `os.utime()` call: `ns=(mtime_s * 10**9 + mtime_ns, ...)`.

---


### ADR-009 — WebSocket ordering guarantee and per-path serialization

**Context:** WebSocket (RFC 6455) guarantees ordering within a single TCP connection, but does not
guarantee causality across asynchronous operations. Example: Client sends `WRITE /foo` followed
immediately by `RENAME /foo → /bar`. If the WRITE is still being chunked while RENAME is processed,
the RENAME may be applied first, leading to a file named `/bar` with old content.

**Decision:** Enforce **per-path serialization** at the **sender side**. A client may not start
transferring a new operation on `path` until the previous operation on that path has been ACKed
or NACKed by the server.

Implementation: the `SyncEngine` (client-side) maintains a `in_flight: dict[str, Future]` tracking
active transfers. Before emitting a new event for a path, it waits for the previous transfer to
complete:

```python
async def emit_event(self, path: str, event_type: EventType, ...) -> None:
    # Block until previous operation on this path is done
    if path in self.in_flight:
        await self.in_flight[path]  # wait for ACK/NACK
    
    # Now emit the new event
    transfer_future = asyncio.create_task(self.send_event(event_type, ...))
    self.in_flight[path] = transfer_future
    await transfer_future
    del self.in_flight[path]
```

**Consequences:**
- Operations on the same file are always ordered as sent by the client.
- Operations on different files can be concurrent (no performance regression).
- The server receives operations in the order the client issued them (modulo network reordering,
  which TCP prevents anyway).
- Rapid edits on the same file (e.g., autocomplete, vim swap) are naturally throttled by the
  debouncer and then strictly ordered — no risk of out-of-order application.

**Trade-off:** A slow network or a problematic server ACK can block the entire client on one file,
making other files wait. Mitigated by reasonable ACK timeouts (5–10s) and server-side fast ACK
(before ClamAV scan).


*End of CLAUDE.md*
