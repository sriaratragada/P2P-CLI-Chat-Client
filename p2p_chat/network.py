"""Async TCP networking primitives for the P2P chat client."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from protocol import pack_message, unpack_message


MessageCallback = Callable[[dict[str, Any]], Awaitable[None]]
ConnectCallback = Callable[["PeerConnection"], Awaitable[None]]


class PeerDisconnectedError(Exception):
    """Raised when the peer disconnects during a read operation."""


class PeerConnection:
    """A bidirectional connection to a single peer."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        username: str,
        on_message_cb: MessageCallback,
    ) -> None:
        """Store stream handles and the async message callback."""

        self.reader = reader
        self.writer = writer
        self.username = username
        self.on_message_cb = on_message_cb

    async def send_message(self, msg_dict: dict[str, Any]) -> bool:
        """Send a framed message to the peer and return success status."""

        try:
            self.writer.write(pack_message(msg_dict))
            await self.writer.drain()
            return True
        except (BrokenPipeError, ConnectionResetError):
            return False

    async def read_message(self) -> dict[str, Any]:
        """Read and decode a single message from the peer."""

        try:
            header = await self.reader.readexactly(4)
            length = int.from_bytes(header, byteorder="big")
            payload = await self.reader.readexactly(length)
        except (asyncio.IncompleteReadError, ConnectionResetError) as exc:
            raise PeerDisconnectedError from exc
        return unpack_message(payload)

    async def receive_loop(self) -> None:
        """Continuously receive messages and dispatch them to the callback."""

        while True:
            message = await self.read_message()
            await self.on_message_cb(message)

    async def close(self) -> None:
        """Close the underlying writer cleanly."""

        self.writer.close()
        try:
            await self.writer.wait_closed()
        except ConnectionResetError:
            return None


async def start_server(host: str, port: int, on_connect_cb: ConnectCallback) -> asyncio.AbstractServer:
    """Start an asyncio TCP server and invoke the callback per connection."""

    async def _handle_client(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        connection = PeerConnection(reader, writer, username="peer", on_message_cb=_noop_message)
        await on_connect_cb(connection)

    return await asyncio.start_server(_handle_client, host=host, port=port)


async def connect_to_peer(host: str, port: int, on_connect_cb: ConnectCallback) -> PeerConnection:
    """Connect to a remote peer and invoke the connection callback."""

    reader, writer = await asyncio.open_connection(host=host, port=port)
    connection = PeerConnection(reader, writer, username="peer", on_message_cb=_noop_message)
    await on_connect_cb(connection)
    return connection


async def _noop_message(_: dict[str, Any]) -> None:
    """Default callback used until the real message handler is attached."""

    return None
