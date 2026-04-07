"""Entry point for the P2P CLI chat client."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from cryptography.exceptions import InvalidTag

from crypto import (
    aes_decrypt,
    aes_encrypt,
    decrypt_with_rsa,
    deserialize_public_key,
    encrypt_with_rsa,
    generate_aes_key,
    generate_rsa_keypair,
    serialize_public_key,
)
from network import PeerConnection, PeerDisconnectedError, connect_to_peer, start_server
from ui import ConsoleUI, read_input


@dataclass
class ChatState:
    """Runtime state for a single chat session."""

    username: str
    ui: ConsoleUI
    private_key: Any
    public_key: Any
    session_key: bytes | None
    peer_username: str | None = None


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for listen or connect mode."""

    parser = argparse.ArgumentParser(description="P2P CLI chat client")
    parser.add_argument("--username", required=True, help="Your chat username")
    parser.add_argument("--port", required=True, type=int, help="Port to listen on or connect to")
    parser.add_argument("--host", help="Peer host to connect to; omit to listen")
    return parser.parse_args()


async def perform_handshake(
    connection: PeerConnection,
    state: ChatState,
    incoming: asyncio.Queue[dict[str, Any]],
    is_client: bool,
) -> None:
    """Exchange public keys and establish the shared AES session key."""

    pubkey_message = {
        "type": "pubkey",
        "pubkey": serialize_public_key(state.public_key).decode("utf-8"),
    }
    peer_pubkey_task = asyncio.create_task(wait_for_message_type(incoming, "pubkey"))
    send_pubkey_task = asyncio.create_task(connection.send_message(pubkey_message))
    send_ok, peer_pubkey_message = await asyncio.gather(send_pubkey_task, peer_pubkey_task)
    if not send_ok:
        raise PeerDisconnectedError

    peer_public_key = deserialize_public_key(peer_pubkey_message["pubkey"].encode("utf-8"))

    if is_client:
        state.session_key = generate_aes_key()
        aes_payload = {
            "type": "aes_key",
            "encrypted_key": encrypt_with_rsa(peer_public_key, state.session_key).hex(),
        }
        sent = await connection.send_message(aes_payload)
        if not sent:
            raise PeerDisconnectedError
    else:
        aes_message = await wait_for_message_type(incoming, "aes_key")
        state.session_key = decrypt_with_rsa(
            state.private_key,
            bytes.fromhex(aes_message["encrypted_key"]),
        )


async def wait_for_message_type(
    incoming: asyncio.Queue[dict[str, Any]],
    expected_type: str,
) -> dict[str, Any]:
    """Wait until a message of the requested type arrives."""

    while True:
        message = await incoming.get()
        if message.get("type") == "system":
            raise PeerDisconnectedError
        if message.get("type") == expected_type:
            return message


async def connection_receive_loop(
    connection: PeerConnection,
    state: ChatState,
    incoming: asyncio.Queue[dict[str, Any]],
    stop_event: asyncio.Event,
) -> None:
    """Receive messages until the connection closes."""

    async def _handle_message(message: dict[str, Any]) -> None:
        msg_type = message.get("type")
        if msg_type in {"pubkey", "aes_key"}:
            await incoming.put(message)
            return
        if msg_type == "chat":
            await handle_chat_message(state, message)
            return
        if msg_type == "system":
            state.ui.print_system(message.get("text", "Peer disconnected."))
            stop_event.set()

    connection.on_message_cb = _handle_message

    try:
        await connection.receive_loop()
    except PeerDisconnectedError:
        await incoming.put({"type": "system", "text": "Peer disconnected."})
        state.ui.print_system("Peer disconnected.")
        stop_event.set()


async def handle_chat_message(state: ChatState, message: dict[str, Any]) -> None:
    """Decrypt and display an incoming chat message."""

    sender = message.get("sender", "peer")
    state.peer_username = sender

    try:
        if state.session_key is None:
            raise ValueError("Missing session key.")
        plaintext = aes_decrypt(
            state.session_key,
            message["iv"],
            message["ciphertext"],
            message["tag"],
        )
    except InvalidTag:
        state.ui.print_system("Message authentication failed — dropping packet.")
        return

    state.ui.print_message(sender, plaintext, message.get("timestamp", state.ui.current_timestamp()))


async def chat_loop(
    connection: PeerConnection,
    state: ChatState,
    stop_event: asyncio.Event,
) -> None:
    """Read user input, encrypt it, and send chat messages."""

    while not stop_event.is_set():
        input_task = asyncio.create_task(read_input(state.ui.prompt))
        stop_task = asyncio.create_task(stop_event.wait())
        done, pending = await asyncio.wait(
            {input_task, stop_task},
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

        if stop_task in done and stop_event.is_set():
            input_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await input_task
            break

        text = input_task.result().strip()
        if not text:
            continue

        if state.session_key is None:
            state.ui.print_system("No active session key; unable to send message.")
            continue

        encrypted = aes_encrypt(state.session_key, text)
        payload = {
            "type": "chat",
            **encrypted,
            "sender": state.username,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
        }
        sent = await connection.send_message(payload)
        if not sent:
            state.ui.print_system("Peer disconnected.")
            stop_event.set()
            break


async def run_session(connection: PeerConnection, username: str, is_client: bool) -> None:
    """Run handshake, receive loop, and user chat loop for a connection."""

    ui = ConsoleUI(username)
    private_key, public_key = generate_rsa_keypair()
    state = ChatState(
        username=username,
        ui=ui,
        private_key=private_key,
        public_key=public_key,
        session_key=None,
    )
    incoming: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
    stop_event = asyncio.Event()

    receiver_task = asyncio.create_task(connection_receive_loop(connection, state, incoming, stop_event))
    try:
        await perform_handshake(connection, state, incoming, is_client=is_client)
        state.ui.print_system("Secure session established.")
        await chat_loop(connection, state, stop_event)
    except asyncio.CancelledError:
        await connection.send_message({"type": "system", "text": "Peer disconnected."})
        raise
    finally:
        stop_event.set()
        receiver_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await receiver_task
        await connection.close()


async def run_server(args: argparse.Namespace) -> None:
    """Run the application in listen mode and accept a single peer."""

    connected = asyncio.Event()
    session_complete = asyncio.Future()
    server_holder: dict[str, Any] = {}

    async def _on_connect(connection: PeerConnection) -> None:
        if connected.is_set():
            await connection.send_message({"type": "system", "text": "Another peer is already connected."})
            await connection.close()
            return

        connected.set()
        server = server_holder["server"]
        server.close()
        try:
            await run_session(connection, args.username, is_client=False)
            session_complete.set_result(None)
        except Exception as exc:  # pragma: no cover - surfaced to caller
            if not session_complete.done():
                session_complete.set_exception(exc)

    try:
        server = await start_server("0.0.0.0", args.port, _on_connect)
    except OSError as exc:
        if exc.errno in {48, 98}:
            print(f"[system] Port {args.port} is already in use. Try a different port.")
            return
        raise

    server_holder["server"] = server
    print(f"[system] Listening on 0.0.0.0:{args.port}")
    try:
        await session_complete
    finally:
        server.close()
        await server.wait_closed()


async def run_client(args: argparse.Namespace) -> None:
    """Run the application in connect mode."""

    async def _on_connect(_: PeerConnection) -> None:
        return None

    connection = await connect_to_peer(args.host, args.port, _on_connect)
    await run_session(connection, args.username, is_client=True)


async def async_main() -> int:
    """Run the chat application and return a process exit code."""

    args = parse_args()

    try:
        if args.host:
            await run_client(args)
        else:
            await run_server(args)
    except KeyboardInterrupt:
        print("\n[system] Disconnecting.")
        return 0
    except ConnectionRefusedError:
        print(f"[system] Unable to connect to {args.host}:{args.port}.")
        return 1
    except PeerDisconnectedError:
        print("[system] Peer disconnected.")
        return 0
    return 0


def main() -> None:
    """Run the asyncio entry point."""

    raise SystemExit(asyncio.run(async_main()))


if __name__ == "__main__":
    main()
