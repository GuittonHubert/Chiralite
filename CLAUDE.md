# CLAUDE.md — chiralite

> **Context document for Claude Code.**
> This file describes the architecture, security model, implementation decisions, and coding conventions
> for the `chiralite` project. Read it entirely before writing any code.

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

### 4.3 FileEntry model

class FileEntry


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

The index is **persisted** on disk (SQLite, via `aiosqlite`) so it survives restarts. On reconnect,
the client sends `SYNC_REQUEST`; the server replies with `SYNC_STATE` (its current index snapshot);
the client computes the diff and sends only what changed.

> **Important:** the index is never written in-place during normal operation. All mutations go
> through the **EventJournal** first (section 5.5). The in-memory SiloIndex is authoritative;
> SQLite is the durable replay log. Because rapidhash is computed synchronously, there is no
> pending state: every `FileRecord` is complete and immediately usable for sync decisions.

### 5.2 Watcher and debouncer

  Wraps watchdog for a single silo root path.
  Applies blacklist filtering before emitting events.
  Debounces bursts per-file before forwarding to SyncEngine.

**Debounce algorithm** (per file, configurable)

### 5.3 Blacklist

Blacklist patterns are **glob-style** (same semantics as `.gitignore`). They are:
- Defined at **global level** (applies to all silos)
- Overridable per **silo** (`blacklist_extra` adds patterns, `whitelist` forces inclusion)
- **Synchronized** — when the server-side blacklist is updated, it is pushed to all connected
  clients via `BLACKLIST_SYNC`; when a client updates its local override, it is pushed to the server

### 5.4 Conflict resolution (LWW)

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

#### EventJournal entry schema (JSONL)

Journal file: `<state_dir>/silo-<silo_id>/journal.jsonl`

#### Startup replay

Before accepting watcher events or network connections:

    1. Load all journal entries with status != 'done'.
    2. For each entry, stat() the actual file on disk.
    3a. stat matches (size, mtime_s, mtime_ns) -> unchanged since crash:
          recompute rapidhash, update index, mark done.
    3b. stat does not match (file changed or gone) -> mark 'superseded';
          emit a fresh synthetic event so SyncEngine reprocesses the file.
    4. Prune all 'done' and 'superseded' entries from the journal.


#### Event supersession

A pending journal entry for `path` is **superseded** (marked and pruned) when:

- A newer event for the same `path` arrives (the pending entry is no longer the latest state)
- At replay time, `(size, mtime_s, mtime_ns)` on disk differs from the entry
- A `delete` or `rename` event arrives while a `write` is still pending for that path

---

## 6. Delta Transfers

### 6.1 vcdiff integration

### 6.2 Server-side base management

When the server receives `TRANSFER_BEGIN`, it looks up `delta_base_rapidhash` in the silo index.
If not found (first sync, or base was deleted), the client must send `is_full = True`.

The client queries the server's known rapidhash via `SYNC_STATE` diff before computing deltas.

### 6.3 Chunking

Large deltas or full files are chunked:

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

The `tmpfs` mount is **pre-mounted** at server startup (not per-transfer). Each transfer gets its
own subdirectory, cleaned up atomically after scan.

### 7.3 ClamAV client


ClamAV result → `CLEAN` | `INFECTED {virus_name}` | `ERROR {reason}`

On `INFECTED`: quarantine the file, log `CRITICAL` audit event, send `TRANSFER_NACK` with
`reason="quarantine"`.

---

## 8. Filesystem & Permissions

  1. Atomic write
  2. Path validation


---

## 9. Silo Model

### 9.1 One WebSocket connection per silo

Each silo is an independent session. The `silo_id` (UUID) is declared in the `HELLO` message.
The server verifies `silo_id` against the policy for the client's CN before proceeding.

A single client binary manages N concurrent silo connections.

---

## 10. Audit Logging

One JSON object per line (JSONL). UTF-8, append-only.

---

## 14. Coding Conventions

### General

- **Python ≥ 3.10** (3.11+ recommended) — use `match`, `ExceptionGroup`, `tomllib` where available; provide fallbacks for 3.10 where needed
- **Async-first** — all I/O is `async`/`await`; no blocking calls in the event loop
- **Fully typed** — every function has type annotations; `mypy --strict` must pass
- **No bare `except`** — always catch specific exception types
- **No `print()`** — use `logging` in library code, `typer.echo()` in CLI only
- **Fail closed** — on any validation error, reject the operation and log; never silently degrade
- **Language** - write every file, commit message, GitHub issue, and PR description in English. No exceptions, even when the user writes in French.
- **CLAUDE.md reference** - write issue/PR descriptions, commit messages, and comments as if CLAUDE.md does not exist. Refer to architecture decisions, implementation order, or protocol specs by their substance, not by the file that documents them
- **Testing strategies** - unit tests must exist for every feature and all run without any error

*End of CLAUDE.md*
