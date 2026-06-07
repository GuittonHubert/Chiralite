"""Tests for chiralite/cli.py."""
from __future__ import annotations

import datetime
import json
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
from typer.testing import CliRunner

from chiralite.cli import app, _print_audit_line

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _make_ca(tmp_path: Path) -> tuple[Path, Path]:
    """Generate ca.key + ca.crt in tmp_path and return their paths."""
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now())
        .not_valid_after(_now() + datetime.timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, algorithm=None)
    )
    key_path = tmp_path / "ca.key"
    cert_path = tmp_path / "ca.crt"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key_path, cert_path


def _make_csr(tmp_path: Path, cn: str = "test-client") -> Path:
    """Generate a client key + CSR in tmp_path and return the CSR path."""
    key = ed25519.Ed25519PrivateKey.generate()
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .sign(key, algorithm=None)
    )
    key_path = tmp_path / "client.key"
    csr_path = tmp_path / "client.csr"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    return csr_path


def _audit_record(**kwargs) -> str:
    base = {
        "ts_ns": 1714000000000000000,
        "ts_iso": "2024-04-25T10:00:00.123456Z",
        "severity": "INFO",
        "event": "file.write",
    }
    base.update(kwargs)
    return json.dumps(base)


# ---------------------------------------------------------------------------
# keygen
# ---------------------------------------------------------------------------

class TestKeygen:
    def test_creates_four_files(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["keygen", "--out-dir", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert (tmp_path / "ca.key").exists()
        assert (tmp_path / "ca.crt").exists()
        assert (tmp_path / "client.key").exists()
        assert (tmp_path / "client.crt").exists()

    def test_ca_cert_is_valid_pem(self, tmp_path: Path) -> None:
        runner.invoke(app, ["keygen", "--out-dir", str(tmp_path)])
        cert = x509.load_pem_x509_certificate((tmp_path / "ca.crt").read_bytes())
        assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "chiralite-ca"

    def test_client_cert_cn_matches(self, tmp_path: Path) -> None:
        runner.invoke(app, ["keygen", "--out-dir", str(tmp_path), "--cn", "my-laptop"])
        cert = x509.load_pem_x509_certificate((tmp_path / "client.crt").read_bytes())
        assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "my-laptop"

    def test_ca_key_is_chmod_600(self, tmp_path: Path) -> None:
        runner.invoke(app, ["keygen", "--out-dir", str(tmp_path)])
        import stat
        mode = (tmp_path / "ca.key").stat().st_mode
        assert stat.S_IMODE(mode) == 0o600

    def test_client_key_is_chmod_600(self, tmp_path: Path) -> None:
        runner.invoke(app, ["keygen", "--out-dir", str(tmp_path)])
        import stat
        mode = (tmp_path / "client.key").stat().st_mode
        assert stat.S_IMODE(mode) == 0o600

    def test_client_cert_signed_by_ca(self, tmp_path: Path) -> None:
        runner.invoke(app, ["keygen", "--out-dir", str(tmp_path)])
        from chiralite.crypto.certificates import verify_chain
        ca_cert = x509.load_pem_x509_certificate((tmp_path / "ca.crt").read_bytes())
        client_cert = x509.load_pem_x509_certificate((tmp_path / "client.crt").read_bytes())
        verify_chain(client_cert, ca_cert)  # no exception

    def test_output_mentions_files(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["keygen", "--out-dir", str(tmp_path)])
        assert "ca.key" in result.output
        assert "client.crt" in result.output

    def test_creates_output_dir(self, tmp_path: Path) -> None:
        new_dir = tmp_path / "new" / "subdir"
        result = runner.invoke(app, ["keygen", "--out-dir", str(new_dir)])
        assert result.exit_code == 0
        assert new_dir.is_dir()

    def test_custom_validity(self, tmp_path: Path) -> None:
        runner.invoke(app, ["keygen", "--out-dir", str(tmp_path), "--days", "30"])
        cert = x509.load_pem_x509_certificate((tmp_path / "client.crt").read_bytes())
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert delta.days == 30


# ---------------------------------------------------------------------------
# sign
# ---------------------------------------------------------------------------

class TestSign:
    def test_creates_crt_file(self, tmp_path: Path) -> None:
        ca_key_path, ca_cert_path = _make_ca(tmp_path)
        csr_path = _make_csr(tmp_path)
        result = runner.invoke(app, [
            "sign", str(csr_path),
            "--ca-key", str(ca_key_path),
            "--ca-cert", str(ca_cert_path),
        ])
        assert result.exit_code == 0, result.output
        assert (tmp_path / "client.crt").exists()

    def test_signed_cert_cn_matches_csr(self, tmp_path: Path) -> None:
        ca_key_path, ca_cert_path = _make_ca(tmp_path)
        csr_path = _make_csr(tmp_path, cn="my-device")
        runner.invoke(app, [
            "sign", str(csr_path),
            "--ca-key", str(ca_key_path),
            "--ca-cert", str(ca_cert_path),
        ])
        cert = x509.load_pem_x509_certificate((tmp_path / "client.crt").read_bytes())
        assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "my-device"

    def test_signed_cert_verifies_against_ca(self, tmp_path: Path) -> None:
        ca_key_path, ca_cert_path = _make_ca(tmp_path)
        csr_path = _make_csr(tmp_path)
        runner.invoke(app, [
            "sign", str(csr_path),
            "--ca-key", str(ca_key_path),
            "--ca-cert", str(ca_cert_path),
        ])
        from chiralite.crypto.certificates import verify_chain
        ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
        client_cert = x509.load_pem_x509_certificate((tmp_path / "client.crt").read_bytes())
        verify_chain(client_cert, ca_cert)

    def test_custom_out_path(self, tmp_path: Path) -> None:
        ca_key_path, ca_cert_path = _make_ca(tmp_path)
        csr_path = _make_csr(tmp_path)
        out_path = tmp_path / "signed.crt"
        result = runner.invoke(app, [
            "sign", str(csr_path),
            "--ca-key", str(ca_key_path),
            "--ca-cert", str(ca_cert_path),
            "--out", str(out_path),
        ])
        assert result.exit_code == 0
        assert out_path.exists()

    def test_missing_csr_exits_1(self, tmp_path: Path) -> None:
        ca_key_path, ca_cert_path = _make_ca(tmp_path)
        result = runner.invoke(app, [
            "sign", str(tmp_path / "nonexistent.csr"),
            "--ca-key", str(ca_key_path),
            "--ca-cert", str(ca_cert_path),
        ])
        assert result.exit_code == 1

    def test_missing_ca_key_exits_1(self, tmp_path: Path) -> None:
        _, ca_cert_path = _make_ca(tmp_path)
        csr_path = _make_csr(tmp_path)
        result = runner.invoke(app, [
            "sign", str(csr_path),
            "--ca-key", str(tmp_path / "missing.key"),
            "--ca-cert", str(ca_cert_path),
        ])
        assert result.exit_code == 1

    def test_custom_days(self, tmp_path: Path) -> None:
        ca_key_path, ca_cert_path = _make_ca(tmp_path)
        csr_path = _make_csr(tmp_path)
        runner.invoke(app, [
            "sign", str(csr_path),
            "--ca-key", str(ca_key_path),
            "--ca-cert", str(ca_cert_path),
            "--days", "45",
        ])
        cert = x509.load_pem_x509_certificate((tmp_path / "client.crt").read_bytes())
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert delta.days == 45


# ---------------------------------------------------------------------------
# start
# ---------------------------------------------------------------------------

class TestStart:
    def test_missing_config_exits_1(self, tmp_path: Path) -> None:
        result = runner.invoke(app, [
            "start", "--config", str(tmp_path / "missing.yaml")
        ])
        assert result.exit_code == 1
        assert "not found" in result.output.lower() or "not found" in (result.stderr or "")


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

class TestStatus:
    def test_missing_config_exits_1(self, tmp_path: Path) -> None:
        result = runner.invoke(app, [
            "status", "--config", str(tmp_path / "missing.yaml")
        ])
        assert result.exit_code == 1

    def test_shows_silo_names(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config.yaml"
        cfg.write_text(
            "silos:\n"
            "  - id: 550e8400-e29b-41d4-a716-446655440001\n"
            "    name: project-alpha\n"
            "    local_path: /tmp/alpha\n"
        )
        result = runner.invoke(app, ["status", "--config", str(cfg)])
        assert result.exit_code == 0
        assert "project-alpha" in result.output

    def test_empty_silos_message(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config.yaml"
        cfg.write_text("silos: []\n")
        result = runner.invoke(app, ["status", "--config", str(cfg)])
        assert result.exit_code == 0
        assert "No silos" in result.output


# ---------------------------------------------------------------------------
# inspect
# ---------------------------------------------------------------------------

class TestInspect:
    def test_missing_index_exits_1(self, tmp_path: Path) -> None:
        result = runner.invoke(app, [
            "inspect", "my-silo", "src/main.py",
            "--index-dir", str(tmp_path),
        ])
        assert result.exit_code == 1
        assert "No persisted index" in result.output

    def test_shows_silo_and_path(self, tmp_path: Path) -> None:
        result = runner.invoke(app, [
            "inspect", "my-silo", "src/main.py",
            "--index-dir", str(tmp_path),
        ])
        assert "my-silo" in result.output
        assert "src/main.py" in result.output


# ---------------------------------------------------------------------------
# force-sync
# ---------------------------------------------------------------------------

class TestForceSync:
    def test_prints_silo_name(self) -> None:
        result = runner.invoke(app, ["force-sync", "project-alpha"])
        assert result.exit_code == 0
        assert "project-alpha" in result.output


# ---------------------------------------------------------------------------
# audit tail
# ---------------------------------------------------------------------------

class TestAuditTail:
    def test_missing_file_exits_1(self, tmp_path: Path) -> None:
        result = runner.invoke(app, [
            "audit", "tail", "--file", str(tmp_path / "missing.jsonl")
        ])
        assert result.exit_code == 1

    def test_prints_recent_lines(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        log.write_text(
            _audit_record(event="file.write", client_cn="alice", path="x.py") + "\n"
            + _audit_record(event="file.delete", client_cn="alice", path="y.py") + "\n"
        )
        result = runner.invoke(app, ["audit", "tail", "--file", str(log), "--lines", "10"])
        assert result.exit_code == 0
        assert "file.write" in result.output
        assert "file.delete" in result.output

    def test_lines_limit_respected(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        lines = "\n".join(
            _audit_record(event=f"event.{i}") for i in range(10)
        )
        log.write_text(lines + "\n")
        result = runner.invoke(app, ["audit", "tail", "--file", str(log), "--lines", "3"])
        assert result.exit_code == 0
        # Only the last 3 events should appear
        assert "event.7" in result.output
        assert "event.8" in result.output
        assert "event.9" in result.output
        assert "event.0" not in result.output

    def test_invalid_json_lines_printed_raw(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        log.write_text("not-json-at-all\n")
        result = runner.invoke(app, ["audit", "tail", "--file", str(log)])
        assert result.exit_code == 0
        assert "not-json-at-all" in result.output


# ---------------------------------------------------------------------------
# _print_audit_line helper
# ---------------------------------------------------------------------------

class TestPrintAuditLine:
    def test_basic_fields_formatted(self, capsys) -> None:
        raw = _audit_record(
            event="session.start",
            severity="INFO",
            client_cn="bob",
            path="src/main.py",
        )
        _print_audit_line(raw)
        out = capsys.readouterr().out
        assert "session.start" in out
        assert "INFO" in out
        assert "bob" in out
        assert "src/main.py" in out

    def test_detail_included(self, capsys) -> None:
        raw = _audit_record(
            event="quarantine",
            severity="CRITICAL",
            detail={"virus": "Eicar"},
        )
        _print_audit_line(raw)
        out = capsys.readouterr().out
        assert "quarantine" in out
        assert "Eicar" in out

    def test_optional_fields_absent_no_error(self, capsys) -> None:
        raw = json.dumps({"ts_iso": "2024-01-01T00:00:00Z", "severity": "INFO", "event": "ping"})
        _print_audit_line(raw)
        out = capsys.readouterr().out
        assert "ping" in out


# ---------------------------------------------------------------------------
# help / structure
# ---------------------------------------------------------------------------

class TestHelp:
    def test_root_help(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "keygen" in result.output

    def test_keygen_help(self) -> None:
        result = runner.invoke(app, ["keygen", "--help"])
        assert result.exit_code == 0
        assert "--out-dir" in result.output

    def test_sign_help(self) -> None:
        result = runner.invoke(app, ["sign", "--help"])
        assert result.exit_code == 0
        assert "--ca-key" in result.output

    def test_audit_tail_help(self) -> None:
        result = runner.invoke(app, ["audit", "tail", "--help"])
        assert result.exit_code == 0
        assert "--lines" in result.output

    def test_force_sync_help(self) -> None:
        result = runner.invoke(app, ["force-sync", "--help"])
        assert result.exit_code == 0
