"""Binary frame codec for one chiralite WebSocket session.

Two modes:

Plain mode (handshake phase)
    ``send_plain`` / ``recv_plain`` transmit Pydantic messages as raw JSON
    bytes inside a binary WebSocket frame, with no encryption.  Used for
    HELLO → CHALLENGE → RESPONSE → ACCEPT / AUTH_ERROR.

Encrypted mode (session phase)
    ``send`` / ``recv`` transmit Pydantic messages as AES-256-GCM encrypted
    frames (seq + nonce + ciphertext) via ``PayloadCodec``.  Activated by
    calling ``activate(codec)`` after the handshake completes.
"""
from __future__ import annotations

from pydantic import BaseModel

from chiralite.crypto.payload import FrameError, PayloadCodec, ReplayError
from chiralite.protocol.messages import AnyMsg, parse_json
from chiralite.transport.websocket import Connection

__all__ = ["FrameError", "FramedConnection", "ReplayError"]


class FramedConnection:
    """Encrypted message channel over a raw WebSocket ``Connection``.

    Typical lifecycle::

        framed = FramedConnection(conn)

        # --- handshake (unencrypted) ---
        await framed.send_plain(HelloMsg(...))
        challenge = await framed.recv_plain()   # ChallengeMsg expected

        # --- session activated ---
        framed.activate(PayloadCodec(session_key, session_token))

        # --- encrypted session ---
        await framed.send(PingMsg(ts_ns=...))
        msg = await framed.recv()
    """

    def __init__(self, conn: Connection) -> None:
        self._conn = conn
        self._codec: PayloadCodec | None = None

    # ------------------------------------------------------------------
    # Codec activation
    # ------------------------------------------------------------------

    def activate(self, codec: PayloadCodec) -> None:
        """Switch to encrypted mode.  Must be called exactly once, after ACCEPT."""
        if self._codec is not None:
            raise FrameError("codec already activated")
        self._codec = codec

    @property
    def is_encrypted(self) -> bool:
        return self._codec is not None

    # ------------------------------------------------------------------
    # Plain mode — handshake phase
    # ------------------------------------------------------------------

    async def send_plain(self, msg: BaseModel) -> None:
        """Serialize *msg* as JSON and send as a raw binary frame (no GCM)."""
        await self._conn.send(msg.model_dump_json().encode())

    async def recv_plain(self) -> AnyMsg:
        """Receive a raw binary frame and parse it as a typed message."""
        data = await self._conn.recv()
        return parse_json(data)

    # ------------------------------------------------------------------
    # Encrypted mode — session phase
    # ------------------------------------------------------------------

    async def send(self, msg: BaseModel) -> None:
        """Serialize *msg* as JSON, encrypt with GCM, and send.

        Raises:
            FrameError: if ``activate()`` has not been called.
        """
        if self._codec is None:
            raise FrameError("cannot send encrypted frame: codec not activated")
        plaintext = msg.model_dump_json().encode()
        frame = self._codec.encrypt(plaintext)
        await self._conn.send(frame)

    async def recv(self) -> AnyMsg:
        """Receive a GCM frame, decrypt, and parse as a typed message.

        Raises:
            FrameError:  if ``activate()`` has not been called, the frame is
                         malformed, or GCM authentication fails.
            ReplayError: if the seq counter is out of order.
        """
        if self._codec is None:
            raise FrameError("cannot receive encrypted frame: codec not activated")
        frame = await self._conn.recv()
        plaintext = self._codec.decrypt(frame)
        return parse_json(plaintext)

    # ------------------------------------------------------------------
    # Delegation
    # ------------------------------------------------------------------

    async def close(self) -> None:
        await self._conn.close()

    @property
    def remote_addr(self) -> str:
        return self._conn.remote_addr
