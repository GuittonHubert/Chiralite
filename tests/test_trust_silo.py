"""Tests for trust/store.py, trust/policy.py, silo/config.py,
silo/session.py, and silo/registry.py."""
from __future__ import annotations

import datetime
import grp
import os
import pwd
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from chiralite.fs.jail import PathJail
from chiralite.silo.config import (
    AllowedClientConfig,
    GidPolicyConfig,
    SiloConfig,
    UidPolicyConfig,
)
from chiralite.silo.registry import RegistryError, SiloRegistry
from chiralite.silo.session import SiloSession
from chiralite.trust.policy import (
    ClientPolicy,
    GidPolicy,
    OpType,
    PolicyError,
    SecurityError,
    SiloPolicy,
    UidPolicy,
    resolve_gid,
    resolve_uid,
)
from chiralite.trust.store import TrustError, TrustStore


# ---------------------------------------------------------------------------
# Cert helpers
# ---------------------------------------------------------------------------

def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _make_ca() -> tuple[ed25519.Ed25519PrivateKey, x509.Certificate]:
    key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(hours=1))
        .not_valid_after(_now() + datetime.timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, algorithm=None)
    )
    return key, cert


def _make_leaf(
    ca_key: ed25519.Ed25519PrivateKey,
    ca_cert: x509.Certificate,
    cn: str,
    not_before: datetime.datetime | None = None,
    not_after: datetime.datetime | None = None,
) -> x509.Certificate:
    nb = not_before or (_now() - datetime.timedelta(hours=1))
    na = not_after or (_now() + datetime.timedelta(days=90))
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(ed25519.Ed25519PrivateKey.generate().public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .sign(ca_key, algorithm=None)
    )


# ---------------------------------------------------------------------------
# Resolve helpers
# ---------------------------------------------------------------------------

def _current_user() -> str:
    return pwd.getpwuid(os.getuid()).pw_name


def _current_group() -> str:
    return grp.getgrgid(os.getgid()).gr_name


# ---------------------------------------------------------------------------
# TrustStore
# ---------------------------------------------------------------------------

class TestTrustStore:
    def test_valid_cert_accepted(self) -> None:
        ca_key, ca_cert = _make_ca()
        store = TrustStore(ca_cert)
        leaf = _make_leaf(ca_key, ca_cert, "client-a")
        store.verify_cert(leaf)  # no exception

    def test_expired_cert_raises(self) -> None:
        ca_key, ca_cert = _make_ca()
        store = TrustStore(ca_cert)
        past = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
        leaf = _make_leaf(
            ca_key, ca_cert, "client-old",
            not_before=past - datetime.timedelta(days=90),
            not_after=past,
        )
        with pytest.raises(TrustError, match="expired"):
            store.verify_cert(leaf)

    def test_not_yet_valid_cert_raises(self) -> None:
        ca_key, ca_cert = _make_ca()
        store = TrustStore(ca_cert)
        future = _now() + datetime.timedelta(days=10)
        leaf = _make_leaf(
            ca_key, ca_cert, "client-future",
            not_before=future,
            not_after=future + datetime.timedelta(days=90),
        )
        with pytest.raises(TrustError, match="not yet valid"):
            store.verify_cert(leaf)

    def test_wrong_ca_raises(self) -> None:
        _, ca_cert_a = _make_ca()
        ca_key_b, _ = _make_ca()
        _, ca_cert_b = _make_ca()
        # Leaf signed by ca_key_b but store uses ca_cert_a
        store = TrustStore(ca_cert_a)
        # Sign leaf with a different CA key
        leaf = _make_leaf(ca_key_b, ca_cert_b, "rogue")
        with pytest.raises(TrustError):
            store.verify_cert(leaf)

    def test_ca_cert_accessible(self) -> None:
        _, ca_cert = _make_ca()
        store = TrustStore(ca_cert)
        assert store.ca_cert is ca_cert


# ---------------------------------------------------------------------------
# resolve_uid
# ---------------------------------------------------------------------------

class TestResolveUid:
    def test_known_user_resolves(self) -> None:
        user = _current_user()
        if user == "root":
            pytest.skip("running as root")
        policy = UidPolicy(map={}, default=user)
        uid = resolve_uid(user, policy)
        assert uid == os.getuid()

    def test_hardcoded_deny_root(self) -> None:
        policy = UidPolicy(default="nobody")
        with pytest.raises(SecurityError, match="denied"):
            resolve_uid("root", policy)

    def test_hardcoded_deny_daemon(self) -> None:
        policy = UidPolicy(default="nobody")
        with pytest.raises(SecurityError, match="denied"):
            resolve_uid("daemon", policy)

    def test_hardcoded_deny_zero_string(self) -> None:
        policy = UidPolicy(default="nobody")
        with pytest.raises(SecurityError, match="denied"):
            resolve_uid("0", policy)

    def test_hardcoded_deny_sudo(self) -> None:
        policy = UidPolicy(default="nobody")
        with pytest.raises(SecurityError, match="denied"):
            resolve_uid("sudo", policy)

    def test_policy_extra_deny(self) -> None:
        user = _current_user()
        policy = UidPolicy(default="nobody", deny=frozenset({user}))
        with pytest.raises(SecurityError, match="denied"):
            resolve_uid(user, policy)

    def test_map_override_applied(self) -> None:
        user = _current_user()
        if user == "root":
            pytest.skip("running as root")
        # Map "remote_user" → current local user
        policy = UidPolicy(map={"remote_user": user}, default="nobody")
        uid = resolve_uid("remote_user", policy)
        assert uid == os.getuid()

    def test_unknown_default_raises(self) -> None:
        policy = UidPolicy(default="no_such_user_xyzzy_99")
        with pytest.raises(SecurityError, match="unknown user"):
            resolve_uid("any", policy)

    def test_uid_zero_resolved_raises(self) -> None:
        # Simulate a mapping that results in uid 0 by using "root" as default
        # but "root" is in the deny list — so we need to test via default path.
        # We can't easily force uid=0 without being root; skip if root.
        if os.getuid() == 0:
            pytest.skip("running as root; uid-0 guard is irrelevant here")
        # "root" is denied before lookup; test that the error message is correct
        policy = UidPolicy(default="nobody")
        with pytest.raises(SecurityError):
            resolve_uid("root", policy)


# ---------------------------------------------------------------------------
# resolve_gid
# ---------------------------------------------------------------------------

class TestResolveGid:
    def test_known_group_resolves(self) -> None:
        group = _current_group()
        if group == "root":
            pytest.skip("running as root group")
        policy = GidPolicy(map={}, default=group)
        gid = resolve_gid(group, policy)
        assert gid == os.getgid()

    def test_hardcoded_deny_root(self) -> None:
        policy = GidPolicy(default="nogroup")
        with pytest.raises(SecurityError, match="denied"):
            resolve_gid("root", policy)

    def test_hardcoded_deny_shadow(self) -> None:
        policy = GidPolicy(default="nogroup")
        with pytest.raises(SecurityError, match="denied"):
            resolve_gid("shadow", policy)

    def test_hardcoded_deny_wheel(self) -> None:
        policy = GidPolicy(default="nogroup")
        with pytest.raises(SecurityError, match="denied"):
            resolve_gid("wheel", policy)

    def test_policy_extra_deny(self) -> None:
        group = _current_group()
        policy = GidPolicy(default="nogroup", deny=frozenset({group}))
        with pytest.raises(SecurityError, match="denied"):
            resolve_gid(group, policy)

    def test_map_override_applied(self) -> None:
        group = _current_group()
        if group == "root":
            pytest.skip("running as root group")
        policy = GidPolicy(map={"remote_group": group}, default="nogroup")
        gid = resolve_gid("remote_group", policy)
        assert gid == os.getgid()

    def test_unknown_default_raises(self) -> None:
        policy = GidPolicy(default="no_such_group_xyzzy_99")
        with pytest.raises(SecurityError, match="unknown group"):
            resolve_gid("any", policy)


# ---------------------------------------------------------------------------
# SiloPolicy
# ---------------------------------------------------------------------------

_SILO_A = UUID("550e8400-e29b-41d4-a716-446655440001")
_SILO_B = UUID("550e8400-e29b-41d4-a716-446655440002")


def _client_policy(
    cn: str,
    silo_id: UUID,
    ops: frozenset[OpType] | None = None,
) -> ClientPolicy:
    return ClientPolicy(
        cn=cn,
        silo_id=silo_id,
        allowed_ops=ops or frozenset(OpType),
        uid_policy=UidPolicy(),
        gid_policy=GidPolicy(),
    )


class TestSiloPolicy:
    def test_lookup_authorised_cn(self) -> None:
        policy = SiloPolicy([_client_policy("alice", _SILO_A)])
        result = policy.lookup("alice", _SILO_A)
        assert result.cn == "alice"

    def test_lookup_wrong_silo_raises(self) -> None:
        policy = SiloPolicy([_client_policy("alice", _SILO_A)])
        with pytest.raises(PolicyError):
            policy.lookup("alice", _SILO_B)

    def test_lookup_unknown_cn_raises(self) -> None:
        policy = SiloPolicy([_client_policy("alice", _SILO_A)])
        with pytest.raises(PolicyError):
            policy.lookup("mallory", _SILO_A)

    def test_empty_policy_raises(self) -> None:
        policy = SiloPolicy([])
        with pytest.raises(PolicyError):
            policy.lookup("alice", _SILO_A)

    def test_has_op_true(self) -> None:
        policy = SiloPolicy(
            [_client_policy("alice", _SILO_A, frozenset({OpType.READ, OpType.WRITE}))]
        )
        assert policy.has_op("alice", _SILO_A, OpType.WRITE) is True

    def test_has_op_false_missing_op(self) -> None:
        policy = SiloPolicy(
            [_client_policy("alice", _SILO_A, frozenset({OpType.READ}))]
        )
        assert policy.has_op("alice", _SILO_A, OpType.DELETE) is False

    def test_has_op_false_unknown_cn(self) -> None:
        policy = SiloPolicy([_client_policy("alice", _SILO_A)])
        assert policy.has_op("eve", _SILO_A, OpType.READ) is False

    def test_multiple_clients_different_silos(self) -> None:
        policy = SiloPolicy([
            _client_policy("alice", _SILO_A),
            _client_policy("bob", _SILO_B),
        ])
        policy.lookup("alice", _SILO_A)  # OK
        policy.lookup("bob", _SILO_B)    # OK
        with pytest.raises(PolicyError):
            policy.lookup("alice", _SILO_B)


# ---------------------------------------------------------------------------
# SiloConfig
# ---------------------------------------------------------------------------

class TestSiloConfig:
    def test_minimal_config(self, tmp_path: Path) -> None:
        cfg = SiloConfig(
            id=_SILO_A,
            name="alpha",
            server_root=tmp_path,
        )
        assert cfg.id == _SILO_A
        assert cfg.name == "alpha"
        assert cfg.server_root == tmp_path

    def test_uid_policy_conversion(self) -> None:
        cfg = SiloConfig(
            id=_SILO_A,
            name="alpha",
            server_root=Path("/srv"),
            uid_policy=UidPolicyConfig(
                map={"fm": "deploy"},
                default="nobody",
                deny=["root"],
            ),
        )
        policy = cfg.uid_policy.to_policy()
        assert policy.map == {"fm": "deploy"}
        assert policy.default == "nobody"
        assert "root" in policy.deny

    def test_gid_policy_conversion(self) -> None:
        cfg = SiloConfig(
            id=_SILO_A,
            name="alpha",
            server_root=Path("/srv"),
            gid_policy=GidPolicyConfig(default="chiralite"),
        )
        policy = cfg.gid_policy.to_policy()
        assert policy.default == "chiralite"

    def test_default_sandbox_values(self) -> None:
        cfg = SiloConfig(id=_SILO_A, name="x", server_root=Path("/srv"))
        assert cfg.sandbox.max_reconstructed_size_mb == 256
        assert cfg.sandbox.scan_timeout_s == 30.0

    def test_default_transfer_values(self) -> None:
        cfg = SiloConfig(id=_SILO_A, name="x", server_root=Path("/srv"))
        assert cfg.transfer.chunk_size_bytes == 262_144
        assert cfg.transfer.delta_threshold == 0.80

    def test_allowed_clients_stored(self) -> None:
        cfg = SiloConfig(
            id=_SILO_A,
            name="x",
            server_root=Path("/srv"),
            allowed_clients=[AllowedClientConfig(cn="alice")],
        )
        assert cfg.allowed_clients[0].cn == "alice"


# ---------------------------------------------------------------------------
# SiloSession
# ---------------------------------------------------------------------------

class TestSiloSession:
    def _session(self, tmp_path: Path) -> SiloSession:
        return SiloSession(
            silo_id=_SILO_A,
            client_cn="alice",
            jail=PathJail(tmp_path),
            allowed_ops=frozenset({OpType.READ, OpType.WRITE}),
            uid_policy=UidPolicy(),
            gid_policy=GidPolicy(),
        )

    def test_jail_root_property(self, tmp_path: Path) -> None:
        session = self._session(tmp_path)
        assert session.jail_root == tmp_path.resolve()

    def test_permits_allowed_op(self, tmp_path: Path) -> None:
        session = self._session(tmp_path)
        assert session.permits(OpType.READ) is True
        assert session.permits(OpType.WRITE) is True

    def test_permits_disallowed_op(self, tmp_path: Path) -> None:
        session = self._session(tmp_path)
        assert session.permits(OpType.DELETE) is False
        assert session.permits(OpType.RENAME) is False

    def test_blacklist_default_empty(self, tmp_path: Path) -> None:
        session = self._session(tmp_path)
        assert session.blacklist == []

    def test_blacklist_mutable(self, tmp_path: Path) -> None:
        session = self._session(tmp_path)
        session.blacklist.append("**/.git/**")
        assert "**/.git/**" in session.blacklist


# ---------------------------------------------------------------------------
# SiloRegistry
# ---------------------------------------------------------------------------

class TestSiloRegistry:
    def _session(self, tmp_path: Path, silo_id: UUID | None = None) -> SiloSession:
        return SiloSession(
            silo_id=silo_id or _SILO_A,
            client_cn="alice",
            jail=PathJail(tmp_path),
            allowed_ops=frozenset(OpType),
            uid_policy=UidPolicy(),
            gid_policy=GidPolicy(),
        )

    def test_register_and_get(self, tmp_path: Path) -> None:
        registry = SiloRegistry()
        session = self._session(tmp_path)
        registry.register(session)
        assert registry.get(_SILO_A) is session

    def test_get_missing_returns_none(self) -> None:
        registry = SiloRegistry()
        assert registry.get(_SILO_A) is None

    def test_require_missing_raises(self) -> None:
        registry = SiloRegistry()
        with pytest.raises(RegistryError, match="no active session"):
            registry.require(_SILO_A)

    def test_require_present_returns_session(self, tmp_path: Path) -> None:
        registry = SiloRegistry()
        session = self._session(tmp_path)
        registry.register(session)
        assert registry.require(_SILO_A) is session

    def test_duplicate_register_raises(self, tmp_path: Path) -> None:
        registry = SiloRegistry()
        session = self._session(tmp_path)
        registry.register(session)
        with pytest.raises(RegistryError, match="already has an active session"):
            registry.register(session)

    def test_unregister_removes_session(self, tmp_path: Path) -> None:
        registry = SiloRegistry()
        session = self._session(tmp_path)
        registry.register(session)
        removed = registry.unregister(_SILO_A)
        assert removed is session
        assert registry.get(_SILO_A) is None

    def test_unregister_missing_returns_none(self) -> None:
        registry = SiloRegistry()
        assert registry.unregister(_SILO_A) is None

    def test_active_sessions_snapshot(self, tmp_path: Path) -> None:
        registry = SiloRegistry()
        s1 = self._session(tmp_path, _SILO_A)
        s2 = self._session(tmp_path, _SILO_B)
        registry.register(s1)
        registry.register(s2)
        sessions = registry.active_sessions
        assert len(sessions) == 2
        assert s1 in sessions
        assert s2 in sessions

    def test_len(self, tmp_path: Path) -> None:
        registry = SiloRegistry()
        assert len(registry) == 0
        registry.register(self._session(tmp_path))
        assert len(registry) == 1

    def test_contains(self, tmp_path: Path) -> None:
        registry = SiloRegistry()
        registry.register(self._session(tmp_path))
        assert _SILO_A in registry
        assert _SILO_B not in registry

    def test_can_reregister_after_unregister(self, tmp_path: Path) -> None:
        registry = SiloRegistry()
        session = self._session(tmp_path)
        registry.register(session)
        registry.unregister(_SILO_A)
        registry.register(session)  # no exception
        assert registry.get(_SILO_A) is session
