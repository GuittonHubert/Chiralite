"""chiralite CLI — entry point for all operator commands.

Commands
--------
keygen      Generate CA + client keypair and certificates (offline).
sign        Sign a client CSR with the offline CA key.
start       Start the sync daemon (server or client mode).
status      Show active silo sessions.
inspect     Show the FileRecord for a specific path in a silo index.
force-sync  Trigger a full reconciliation for a silo.
audit tail  Tail and pretty-print the audit JSONL log.
"""
from __future__ import annotations

import asyncio
import datetime
import importlib.metadata
import json
import sys
from pathlib import Path
from typing import Optional

import typer
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

__all__ = ["app"]

_DEFAULT_CONFIG = Path("~/.config/chiralite/config.yaml")
_DEFAULT_AUDIT_LOG = Path("/var/log/chiralite/audit.jsonl")
_DEFAULT_OUT_DIR = Path("~/.config/chiralite")

app = typer.Typer(
    name="chiralite",
    help="Real-time bidirectional file synchronisation daemon.",
    no_args_is_help=True,
)
_audit_app = typer.Typer(help="Audit log commands.")
app.add_typer(_audit_app, name="audit")


def _version_callback(value: bool) -> None:
    if value:
        version = importlib.metadata.version("chiralite")
        typer.echo(f"chiralite {version}")
        raise typer.Exit()


@app.callback()
def _main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    pass


# ---------------------------------------------------------------------------
# keygen
# ---------------------------------------------------------------------------

@app.command()
def keygen(
    out_dir: Path = typer.Option(
        _DEFAULT_OUT_DIR,
        "--out-dir", "-o",
        help="Directory to write generated keys and certificates.",
    ),
    cn: str = typer.Option(
        "chiralite-client",
        "--cn",
        help="Common Name for the client certificate.",
    ),
    days: int = typer.Option(90, "--days", help="Client cert validity in days."),
) -> None:
    """Generate an offline CA keypair and a CA-signed client certificate.

    Output files (created inside OUT_DIR):

    \b
    ca.key      CA Ed25519 private key (PKCS8 PEM, no passphrase)
    ca.crt      CA self-signed certificate (PEM)
    client.key  Client Ed25519 private key (PKCS8 PEM, no passphrase)
    client.crt  Client certificate signed by the CA (PEM)
    """
    out = out_dir.expanduser()
    out.mkdir(parents=True, exist_ok=True)

    now = datetime.datetime.now(datetime.timezone.utc)

    # --- CA ---
    ca_key = ed25519.Ed25519PrivateKey.generate()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "chiralite-ca")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, algorithm=None)
    )
    _write_private_key(out / "ca.key", ca_key)
    _write_cert(out / "ca.crt", ca_cert)

    # --- Client ---
    client_key = ed25519.Ed25519PrivateKey.generate()
    client_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(client_name)
        .issuer_name(ca_name)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
        .sign(ca_key, algorithm=None)
    )
    _write_private_key(out / "client.key", client_key)
    _write_cert(out / "client.crt", client_cert)

    typer.echo(f"CA key:      {out / 'ca.key'}")
    typer.echo(f"CA cert:     {out / 'ca.crt'}")
    typer.echo(f"Client key:  {out / 'client.key'}")
    typer.echo(f"Client cert: {out / 'client.crt'}")
    typer.echo(f"CN: {cn!r}  validity: {days} days")


# ---------------------------------------------------------------------------
# sign
# ---------------------------------------------------------------------------

@app.command()
def sign(
    csr_file: Path = typer.Argument(..., help="Path to the PEM CSR file to sign."),
    ca_key_file: Path = typer.Option(
        _DEFAULT_OUT_DIR / "ca.key",
        "--ca-key",
        help="CA private key file (PEM).",
    ),
    ca_cert_file: Path = typer.Option(
        _DEFAULT_OUT_DIR / "ca.crt",
        "--ca-cert",
        help="CA certificate file (PEM).",
    ),
    days: int = typer.Option(90, "--days", help="Signed cert validity in days."),
    out: Optional[Path] = typer.Option(
        None, "--out", "-o",
        help="Output path for signed cert (default: <csr>.crt).",
    ),
) -> None:
    """Sign a client CSR with the offline CA key, producing a PEM certificate."""
    csr_path = csr_file.expanduser()
    ca_key_path = ca_key_file.expanduser()
    ca_cert_path = ca_cert_file.expanduser()

    for p in (csr_path, ca_key_path, ca_cert_path):
        if not p.exists():
            typer.echo(f"Error: file not found: {p}", err=True)
            raise typer.Exit(1)

    try:
        csr = x509.load_pem_x509_csr(csr_path.read_bytes())
        ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
        ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
    except Exception as exc:
        typer.echo(f"Error loading files: {exc}", err=True)
        raise typer.Exit(1)

    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=days))
            .sign(ca_key, algorithm=None)  # type: ignore[arg-type]
        )
    except Exception as exc:
        typer.echo(f"Error signing CSR: {exc}", err=True)
        raise typer.Exit(1)

    dest = out or csr_path.with_suffix(".crt")
    _write_cert(dest, cert)
    typer.echo(f"Signed certificate written to: {dest}")
    cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        typer.echo(f"CN: {cn_attrs[0].value!r}  validity: {days} days")


# ---------------------------------------------------------------------------
# start
# ---------------------------------------------------------------------------

@app.command()
def start(
    silo: Optional[str] = typer.Option(
        None, "--silo", help="Name of the silo to start (default: all silos)."
    ),
    config: Path = typer.Option(
        _DEFAULT_CONFIG,
        "--config", "-c",
        help="Path to the YAML configuration file.",
    ),
    mode: str = typer.Option(
        "client",
        "--mode",
        help="Run as 'client' or 'server'.",
    ),
) -> None:
    """Start the chiralite sync daemon.

    Reads configuration from CONFIG, sets up silo connections, and runs
    until interrupted (Ctrl-C / SIGTERM).
    """
    cfg_path = config.expanduser()
    if not cfg_path.exists():
        typer.echo(f"Config file not found: {cfg_path}", err=True)
        typer.echo("Run 'chiralite keygen' first, then create a config file.", err=True)
        raise typer.Exit(1)

    try:
        import yaml  # type: ignore[import-untyped]
        raw = yaml.safe_load(cfg_path.read_text())
    except Exception as exc:
        typer.echo(f"Failed to load config: {exc}", err=True)
        raise typer.Exit(1)

    typer.echo(f"Starting chiralite ({mode} mode)...")
    if silo:
        typer.echo(f"Silo filter: {silo!r}")

    try:
        asyncio.run(_run_daemon(raw, mode=mode, silo_filter=silo))
    except KeyboardInterrupt:
        typer.echo("\nStopped.")


async def _run_daemon(raw_config: dict, *, mode: str, silo_filter: Optional[str]) -> None:
    """Async entry point for the daemon — placeholder for full wiring."""
    typer.echo("Daemon started. Press Ctrl-C to stop.")
    try:
        await asyncio.sleep(float("inf"))
    except asyncio.CancelledError:
        pass


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

@app.command()
def status(
    config: Path = typer.Option(
        _DEFAULT_CONFIG, "--config", "-c", help="Configuration file."
    ),
) -> None:
    """Show the state of all active silo sessions."""
    # In a deployed system this would query a running daemon via a control
    # socket.  For now we display config-based information only.
    cfg_path = config.expanduser()
    if not cfg_path.exists():
        typer.echo("No configuration found. Run 'chiralite start' first.")
        raise typer.Exit(1)

    try:
        import yaml
        raw = yaml.safe_load(cfg_path.read_text())
    except Exception as exc:
        typer.echo(f"Failed to load config: {exc}", err=True)
        raise typer.Exit(1)

    silos = raw.get("silos", [])
    if not silos:
        typer.echo("No silos configured.")
        return

    for s in silos:
        typer.echo(f"Silo: {s.get('name', '(unnamed)')} ({s.get('id', '?')})")
        typer.echo(f"  Path:  {s.get('local_path', s.get('server_root', '?'))}")
        typer.echo(f"  State: configured")


# ---------------------------------------------------------------------------
# inspect
# ---------------------------------------------------------------------------

@app.command()
def inspect(
    silo: str = typer.Argument(..., help="Silo name or UUID."),
    path: str = typer.Argument(..., help="File path relative to the silo root."),
    index_dir: Path = typer.Option(
        Path("~/.local/share/chiralite"),
        "--index-dir",
        help="Directory containing persisted silo indexes.",
    ),
) -> None:
    """Show the FileRecord for PATH in SILO's index."""
    # Load the in-memory index from a SQLite state file if available.
    # In this implementation we display a not-found message when no persisted
    # state is present (the running daemon owns the live index).
    typer.echo(f"Silo:  {silo}")
    typer.echo(f"Path:  {path}")
    state_path = index_dir.expanduser() / silo / "index.db"
    if not state_path.exists():
        typer.echo("No persisted index found for this silo.")
        typer.echo("Hint: attach to the running daemon or use 'chiralite force-sync'.")
        raise typer.Exit(1)

    # When the daemon is running it persists the index to SQLite.  A future
    # version of this command will query that database directly.
    typer.echo(f"(Index at {state_path} — live query not yet implemented.)")


# ---------------------------------------------------------------------------
# force-sync
# ---------------------------------------------------------------------------

@app.command(name="force-sync")
def force_sync(
    silo: str = typer.Argument(..., help="Silo name or UUID to reconcile."),
    config: Path = typer.Option(
        _DEFAULT_CONFIG, "--config", "-c", help="Configuration file."
    ),
) -> None:
    """Trigger a full reconciliation (SYNC_REQUEST → SYNC_STATE) for SILO.

    This sends a signal to the running daemon.  If no daemon is active it
    prints an informational message.
    """
    typer.echo(f"Requesting force-sync for silo: {silo!r}")
    # A production implementation would write a request to the daemon's
    # control socket (e.g. /run/chiralite/control.sock) and wait for an ack.
    typer.echo("(Control socket not yet implemented — restart the daemon to resync.)")


# ---------------------------------------------------------------------------
# audit tail
# ---------------------------------------------------------------------------

@_audit_app.command("tail")
def audit_tail(
    file: Path = typer.Option(
        _DEFAULT_AUDIT_LOG,
        "--file", "-f",
        help="Path to the audit JSONL log file.",
    ),
    lines: int = typer.Option(
        20, "--lines", "-n",
        help="Number of most recent lines to display initially.",
    ),
    follow: bool = typer.Option(
        False, "--follow", "-F",
        help="Continue streaming new events (like tail -f).",
    ),
) -> None:
    """Display and optionally stream the audit log.

    Each event is printed as a human-readable line::

        2024-04-25T10:00:00Z  INFO  file.write  fm-macbook  src/main.py
    """
    log_path = file.expanduser()
    if not log_path.exists():
        typer.echo(f"Audit log not found: {log_path}", err=True)
        raise typer.Exit(1)

    raw_lines = log_path.read_text(encoding="utf-8").splitlines()
    recent = raw_lines[-lines:] if len(raw_lines) > lines else raw_lines

    for raw in recent:
        raw = raw.strip()
        if not raw:
            continue
        try:
            _print_audit_line(raw)
        except (json.JSONDecodeError, KeyError):
            typer.echo(raw)

    if follow:
        import time
        typer.echo("--- streaming (Ctrl-C to stop) ---")
        try:
            with log_path.open(encoding="utf-8") as fh:
                fh.seek(0, 2)  # seek to end
                while True:
                    line = fh.readline()
                    if line:
                        line = line.strip()
                        if line:
                            try:
                                _print_audit_line(line)
                            except (json.JSONDecodeError, KeyError):
                                typer.echo(line)
                    else:
                        time.sleep(0.2)
        except KeyboardInterrupt:
            pass


def _print_audit_line(raw: str) -> None:
    """Format one JSONL audit record as a human-readable line."""
    record = json.loads(raw)
    ts = record.get("ts_iso", "")[:19].replace("T", " ")
    severity = record.get("severity", "INFO").ljust(8)
    event = record.get("event", "").ljust(30)
    cn = record.get("client_cn", "")
    path = record.get("path", "")

    parts = [ts, severity, event]
    if cn:
        parts.append(cn)
    if path:
        parts.append(path)

    detail = record.get("detail")
    if detail:
        extra = "  ".join(f"{k}={v}" for k, v in detail.items())
        parts.append(f"[{extra}]")

    typer.echo("  ".join(parts))


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _write_private_key(path: Path, key: ed25519.Ed25519PrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    app()


if __name__ == "__main__":
    main()
