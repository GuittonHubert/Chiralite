from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class IConnection(Protocol):
    """Minimal transport interface satisfied by both WebSocket and HTTP SSE connections."""

    remote_addr: str

    async def send(self, data: bytes) -> None: ...
    async def recv(self) -> bytes: ...
    async def close(self) -> None: ...
