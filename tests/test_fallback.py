"""Tests for the WebSocket → HTTP SSE fallback logic in ChiraliteClient."""
from __future__ import annotations

import pytest

from chiralite.client import _is_upgrade_refusal
from chiralite.transport.websocket import ConnectionLost


class TestIsUpgradeRefusal:
    def test_403_detected(self) -> None:
        assert _is_upgrade_refusal(ConnectionLost("HTTP 403 Forbidden"))

    def test_407_detected(self) -> None:
        assert _is_upgrade_refusal(ConnectionLost("proxy returned 407"))

    def test_invalid_status_code_detected(self) -> None:
        assert _is_upgrade_refusal(ConnectionLost("invalid status code: 403"))

    def test_upgrade_keyword_detected(self) -> None:
        assert _is_upgrade_refusal(ConnectionLost("upgrade header rejected by proxy"))

    def test_plain_connection_error_not_refusal(self) -> None:
        assert not _is_upgrade_refusal(ConnectionLost("Connection refused"))

    def test_timeout_not_refusal(self) -> None:
        assert not _is_upgrade_refusal(ConnectionLost("timed out connecting to host"))

    def test_dns_failure_not_refusal(self) -> None:
        assert not _is_upgrade_refusal(ConnectionLost("Name or service not known"))
