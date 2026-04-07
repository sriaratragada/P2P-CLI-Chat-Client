"""Entry point for the P2P CLI chat client."""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

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


MAX_FILE_SIZE = 256 * 1024


@dataclass
class PendingDelivery:
    """Track acknowledgments for a locally-originated payload."""

    message_id: str
    label: str
    acked_by: set[str] = field(default_factory=set)


@dataclass
class SessionContext:
    """Runtime state for a single network session."""

    connection: PeerConnection
    incoming: asyncio.Queue[dict[str, Any]]
    session_key: bytes | None = None
    peer_username: str = "peer"
    peer_id: str = ""
    receiver_task: asyncio.Task[None] | None = None


@dataclass
class AppState:
    """Shared runtime state for the local process."""

    username: str
    participant_id: str
    is_host: bool
    ui: ConsoleUI
    private_key: Any
    public_key: Any
    received_dir: Path
    stop_event: asyncio.Event
    sessions: dict[str, SessionContext] = field(default_factory=dict)
    pending_deliveries: dict[str, PendingDelivery] = field(default_factory=dict)
    message_counter: int = 0


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for listen or connect mode."""

    parser = argparse.ArgumentParser(description="P2P CLI chat client")
    parser.add_argument("--username", required=True, help="Your chat username")
    parser.add_argument("--port", required=True, type=int, help="Port to listen on or connect to")
    parser.add_argument("--host", help="Peer host to connect to; omit to listen and host a room")
    return parser.parse_args()


def current_timestamp() -> str:
    """Return the current local timestamp used in message displays."""

    return datetime.now().strftime("%H:%M:%S")


def next_message_id(state: AppState) -> str:
    """Generate a unique local message identifier."""

    state.message_counter += 1
    return f"{state.participant_id}-{state.message_counter}"


def create_state(username: str, is_host: bool) -> AppState:
    """Create the top-level runtime state for the process."""

    private_key, public_key = generate_rsa_keypair()
    received_dir = Path.cwd() / "received_files"
    received_dir.mkdir(exist_ok=True)
    return AppState(
        username=username,
        participant_id=uuid4().hex,
        is_host=is_host,
        ui=ConsoleUI(username),
        private_key=private_key,
        public_key=public_key,
        received_dir=received_dir,
        stop_event=asyncio.Event(),
    )


async def perform_handshake(
    session: SessionContext,
    state: AppState,
    is_client: bool,
) -> None:
    """Exchange public keys, usernames, and establish a shared AES key."""

    pubkey_message = {
        "type": "pubkey",
        "username": state.username,
        "participant_id": state.participant_id,
        "pubkey": serialize_public_key(state.public_key).decode("utf-8"),
    }
    receive_task = asyncio.create_task(wait_for_message_type(session.incoming, "pubkey"))
    send_task = asyncio.create_task(session.connection.send_message(pubkey_message))
    send_ok, peer_pubkey_message = await asyncio.gather(send_task, receive_task)
    if not send_ok:
        raise PeerDisconnectedError

    session.peer_username = peer_pubkey_message["username"]
    session.peer_id = peer_pubkey_message["participant_id"]
    peer_public_key = deserialize_public_key(peer_pubkey_message["pubkey"].encode("utf-8"))

    if is_client:
        session.session_key = generate_aes_key()
        aes_payload = {
            "type": "aes_key",
            "encrypted_key": encrypt_with_rsa(peer_public_key, session.session_key).hex(),
        }
        sent = await session.connection.send_message(aes_payload)
        if not sent:
            raise PeerDisconnectedError
    else:
        aes_message = await wait_for_message_type(session.incoming, "aes_key")
        session.session_key = decrypt_with_rsa(
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


async def send_secure_payload(
    session: SessionContext,
    payload: dict[str, Any],
) -> bool:
    """Encrypt and send an application payload over an established session."""

    if session.session_key is None:
        return False
    encrypted = aes_encrypt(session.session_key, json.dumps(payload))
    return await session.connection.send_message({"type": "secure", **encrypted})


def parse_secure_payload(session: SessionContext, envelope: dict[str, Any]) -> dict[str, Any]:
    """Decrypt and decode an application payload from a secure envelope."""

    if session.session_key is None:
        raise ValueError("Missing session key.")
    plaintext = aes_decrypt(
        session.session_key,
        envelope["iv"],
        envelope["ciphertext"],
        envelope["tag"],
    )
    return json.loads(plaintext)


def record_pending_delivery(state: AppState, message_id: str, label: str) -> None:
    """Track a local message so acknowledgments can be surfaced to the sender."""

    state.pending_deliveries[message_id] = PendingDelivery(message_id=message_id, label=label)
    if len(state.pending_deliveries) > 200:
        oldest_id = next(iter(state.pending_deliveries))
        del state.pending_deliveries[oldest_id]


def note_delivery_ack(state: AppState, ack_payload: dict[str, Any]) -> None:
    """Record and display a delivery acknowledgment."""

    pending = state.pending_deliveries.get(ack_payload["acked_id"])
    if pending is None:
        return

    ack_key = ack_payload["acked_by_id"]
    if ack_key in pending.acked_by:
        return

    pending.acked_by.add(ack_key)
    state.ui.print_system(
        f"Delivered {pending.label} to {ack_payload['acked_by']} "
        f"(id {ack_payload['acked_id']})."
    )


async def send_ack(
    session: SessionContext,
    state: AppState,
    acked_id: str,
    origin_id: str,
) -> None:
    """Send a delivery acknowledgment for a routed payload."""

    ack_payload = {
        "kind": "ack",
        "acked_id": acked_id,
        "origin_id": origin_id,
        "acked_by_id": state.participant_id,
        "acked_by": state.username,
        "timestamp": current_timestamp(),
    }
    await send_secure_payload(session, ack_payload)


async def broadcast_payload(
    state: AppState,
    payload: dict[str, Any],
    *,
    exclude_peer_id: str | None = None,
) -> None:
    """Send an encrypted payload to every connected peer except an optional exclusion."""

    sessions = [
        session
        for peer_id, session in state.sessions.items()
        if peer_id != exclude_peer_id
    ]
    if not sessions:
        return

    results = await asyncio.gather(
        *(send_secure_payload(session, payload) for session in sessions),
        return_exceptions=True,
    )
    for session, result in zip(sessions, results):
        if result is True:
            continue
        await drop_session(state, session.peer_id, f"{session.peer_username} disconnected.")


async def broadcast_roster(state: AppState) -> None:
    """Broadcast the current room membership list to all connected peers."""

    members = [{"id": state.participant_id, "username": state.username, "role": "host"}]
    members.extend(
        {"id": peer_id, "username": session.peer_username, "role": "peer"}
        for peer_id, session in state.sessions.items()
    )
    payload = {
        "kind": "roster",
        "members": members,
        "timestamp": current_timestamp(),
    }
    await broadcast_payload(state, payload)


def sanitize_filename(filename: str) -> str:
    """Reduce a received filename to a safe local basename."""

    clean_name = Path(filename).name
    return clean_name or "received.bin"


def save_incoming_file(state: AppState, payload: dict[str, Any]) -> Path:
    """Persist an incoming file transfer to the local received-files directory."""

    raw_bytes = base64.b64decode(payload["content_b64"].encode("ascii"))
    target = state.received_dir / f"{payload['sender']}_{sanitize_filename(payload['filename'])}"
    suffix = 1
    while target.exists():
        stem = target.stem
        extension = target.suffix
        target = state.received_dir / f"{stem}_{suffix}{extension}"
        suffix += 1
    target.write_bytes(raw_bytes)
    return target


async def handle_client_payload(
    state: AppState,
    session: SessionContext,
    payload: dict[str, Any],
) -> None:
    """Handle an application payload while running in client mode."""

    kind = payload.get("kind")
    if kind == "chat":
        state.ui.print_message(payload["sender"], payload["text"], payload["timestamp"])
        await send_ack(session, state, payload["message_id"], payload["sender_id"])
        return
    if kind == "file":
        saved_path = save_incoming_file(state, payload)
        state.ui.print_system(
            f"Received file {payload['filename']} from {payload['sender']} "
            f"-> {saved_path}"
        )
        await send_ack(session, state, payload["message_id"], payload["sender_id"])
        return
    if kind == "nick":
        state.ui.print_system(
            f"{payload['old_username']} is now known as {payload['new_username']}."
        )
        await send_ack(session, state, payload["message_id"], payload["sender_id"])
        return
    if kind == "ack":
        note_delivery_ack(state, payload)
        return
    if kind == "roster":
        roster = ", ".join(member["username"] for member in payload["members"])
        state.ui.print_system(f"Connected users: {roster}")
        return
    if kind == "system":
        state.ui.print_system(payload["text"])


async def route_ack_to_origin(state: AppState, payload: dict[str, Any]) -> None:
    """Route an acknowledgment to the original sender of a relayed payload."""

    if payload["origin_id"] == state.participant_id:
        note_delivery_ack(state, payload)
        return

    origin_session = state.sessions.get(payload["origin_id"])
    if origin_session is None:
        return
    await send_secure_payload(origin_session, payload)


async def handle_host_payload(
    state: AppState,
    session: SessionContext,
    payload: dict[str, Any],
) -> None:
    """Handle an application payload while running in host mode."""

    kind = payload.get("kind")
    if kind == "chat":
        state.ui.print_message(payload["sender"], payload["text"], payload["timestamp"])
        await send_ack(session, state, payload["message_id"], payload["sender_id"])
        await broadcast_payload(state, payload, exclude_peer_id=session.peer_id)
        return
    if kind == "file":
        saved_path = save_incoming_file(state, payload)
        state.ui.print_system(
            f"Received file {payload['filename']} from {payload['sender']} "
            f"-> {saved_path}"
        )
        await send_ack(session, state, payload["message_id"], payload["sender_id"])
        await broadcast_payload(state, payload, exclude_peer_id=session.peer_id)
        return
    if kind == "nick":
        old_username = session.peer_username
        session.peer_username = payload["new_username"]
        state.ui.print_system(f"{old_username} is now known as {session.peer_username}.")
        await send_ack(session, state, payload["message_id"], payload["sender_id"])
        await broadcast_payload(state, payload, exclude_peer_id=session.peer_id)
        await broadcast_roster(state)
        return
    if kind == "ack":
        await route_ack_to_origin(state, payload)
        return


async def handle_secure_message(
    state: AppState,
    session: SessionContext,
    envelope: dict[str, Any],
) -> None:
    """Decrypt and dispatch an incoming secure envelope."""

    try:
        payload = parse_secure_payload(session, envelope)
    except InvalidTag:
        state.ui.print_system("Message authentication failed — dropping packet.")
        return

    if state.is_host:
        await handle_host_payload(state, session, payload)
    else:
        await handle_client_payload(state, session, payload)


async def drop_session(state: AppState, peer_id: str, reason: str) -> None:
    """Remove a session from the active connection map and surface the change."""

    session = state.sessions.pop(peer_id, None)
    if session is None:
        return

    state.ui.print_system(reason)
    await session.connection.close()
    if state.is_host:
        await broadcast_roster(state)
    else:
        state.stop_event.set()


async def session_receive_loop(state: AppState, session: SessionContext) -> None:
    """Receive messages for a single session until the peer disconnects."""

    async def _handle_message(message: dict[str, Any]) -> None:
        msg_type = message.get("type")
        if msg_type in {"pubkey", "aes_key"}:
            await session.incoming.put(message)
            return
        if msg_type == "secure":
            await handle_secure_message(state, session, message)
            return
        if msg_type == "system":
            await session.incoming.put(message)
            state.ui.print_system(message.get("text", "Peer disconnected."))
            if not state.is_host:
                state.stop_event.set()

    session.connection.on_message_cb = _handle_message

    try:
        await session.connection.receive_loop()
    except PeerDisconnectedError:
        await session.incoming.put({"type": "system", "text": "Peer disconnected."})
        if state.is_host and session.peer_id:
            await drop_session(state, session.peer_id, f"{session.peer_username} disconnected.")
        else:
            state.ui.print_system("Peer disconnected.")
            state.stop_event.set()


async def accept_host_connection(state: AppState, connection: PeerConnection) -> None:
    """Perform handshake and attach a new peer to the hosted chat room."""

    session = SessionContext(connection=connection, incoming=asyncio.Queue())
    session.receiver_task = asyncio.create_task(session_receive_loop(state, session))
    try:
        await perform_handshake(session, state, is_client=False)
        state.sessions[session.peer_id] = session
        state.ui.print_system(f"{session.peer_username} joined the room.")
        await broadcast_roster(state)
    except PeerDisconnectedError:
        await session.connection.close()
    except Exception:
        await session.connection.close()
        raise


async def connect_client(state: AppState, host: str, port: int) -> SessionContext:
    """Connect to the host and establish the encrypted session."""

    async def _on_connect(_: PeerConnection) -> None:
        return None

    connection = await connect_to_peer(host, port, _on_connect)
    session = SessionContext(connection=connection, incoming=asyncio.Queue())
    session.receiver_task = asyncio.create_task(session_receive_loop(state, session))
    await perform_handshake(session, state, is_client=True)
    state.sessions[session.peer_id] = session
    state.ui.print_system(f"Secure session established with {session.peer_username}.")
    return session


async def shutdown_state(state: AppState) -> None:
    """Close all active sessions and stop background receiver tasks."""

    state.stop_event.set()
    sessions = list(state.sessions.values())
    for session in sessions:
        if session.session_key is not None:
            await send_secure_payload(
                session,
                {"kind": "system", "text": "Peer disconnected.", "timestamp": current_timestamp()},
            )
    for session in sessions:
        if session.receiver_task is not None:
            session.receiver_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await session.receiver_task
        await session.connection.close()
    state.sessions.clear()


async def handle_local_chat(state: AppState, text: str) -> None:
    """Display and route a local chat message."""

    if not state.sessions:
        state.ui.print_system("No connected peers.")
        return

    payload = {
        "kind": "chat",
        "message_id": next_message_id(state),
        "sender_id": state.participant_id,
        "sender": state.username,
        "text": text,
        "timestamp": current_timestamp(),
    }
    state.ui.print_message(state.username, text, payload["timestamp"])
    record_pending_delivery(state, payload["message_id"], f"chat '{text[:24]}'")

    if state.is_host:
        await broadcast_payload(state, payload)
    else:
        session = next(iter(state.sessions.values()))
        sent = await send_secure_payload(session, payload)
        if not sent:
            state.ui.print_system("Peer disconnected.")
            state.stop_event.set()


async def handle_local_nick(state: AppState, new_username: str) -> None:
    """Update the local display name and propagate the change."""

    if not new_username:
        state.ui.print_system("Usage: /nick NEW_NAME")
        return

    old_username = state.username
    state.username = new_username
    state.ui.set_username(new_username)
    payload = {
        "kind": "nick",
        "message_id": next_message_id(state),
        "sender_id": state.participant_id,
        "sender": new_username,
        "old_username": old_username,
        "new_username": new_username,
        "timestamp": current_timestamp(),
    }
    record_pending_delivery(state, payload["message_id"], f"nick change to {new_username}")

    if state.is_host:
        state.ui.print_system(f"You are now known as {new_username}.")
        await broadcast_payload(state, payload)
        await broadcast_roster(state)
        return

    session = next(iter(state.sessions.values()), None)
    if session is None:
        state.ui.print_system("No connected peers.")
        return
    sent = await send_secure_payload(session, payload)
    if sent:
        state.ui.print_system(f"You are now known as {new_username}.")
    else:
        state.ui.print_system("Peer disconnected.")
        state.stop_event.set()


async def handle_local_file(state: AppState, raw_path: str) -> None:
    """Send a small file to every connected peer."""

    if not raw_path:
        state.ui.print_system("Usage: /sendfile PATH")
        return
    if not state.sessions:
        state.ui.print_system("No connected peers.")
        return

    path = Path(raw_path).expanduser()
    if not path.is_file():
        state.ui.print_system(f"File not found: {path}")
        return
    if path.stat().st_size > MAX_FILE_SIZE:
        state.ui.print_system(f"File exceeds {MAX_FILE_SIZE // 1024} KB limit: {path.name}")
        return

    content_b64 = base64.b64encode(path.read_bytes()).decode("ascii")
    payload = {
        "kind": "file",
        "message_id": next_message_id(state),
        "sender_id": state.participant_id,
        "sender": state.username,
        "filename": path.name,
        "size": path.stat().st_size,
        "content_b64": content_b64,
        "timestamp": current_timestamp(),
    }
    state.ui.print_system(f"Sending file {path.name} ({payload['size']} bytes).")
    record_pending_delivery(state, payload["message_id"], f"file {path.name}")

    if state.is_host:
        await broadcast_payload(state, payload)
        return

    session = next(iter(state.sessions.values()))
    sent = await send_secure_payload(session, payload)
    if not sent:
        state.ui.print_system("Peer disconnected.")
        state.stop_event.set()


def print_who(state: AppState) -> None:
    """Show the currently connected users in the room."""

    members = [state.username]
    members.extend(session.peer_username for session in state.sessions.values())
    state.ui.print_system(f"Connected users: {', '.join(members)}")


def print_help(state: AppState) -> None:
    """Display the supported slash commands."""

    state.ui.print_system("Commands: /nick NAME, /sendfile PATH, /who, /help, /quit")


async def handle_command(state: AppState, raw_text: str) -> None:
    """Parse and execute a slash command."""

    command, _, remainder = raw_text.partition(" ")
    argument = remainder.strip()

    if command == "/quit":
        state.stop_event.set()
        return
    if command == "/nick":
        await handle_local_nick(state, argument)
        return
    if command == "/sendfile":
        await handle_local_file(state, argument)
        return
    if command == "/who":
        print_who(state)
        return
    if command == "/help":
        print_help(state)
        return

    state.ui.print_system(f"Unknown command: {command}")


async def local_input_loop(state: AppState) -> None:
    """Read local terminal input until the session is stopped."""

    while not state.stop_event.is_set():
        try:
            text = (await read_input(state.ui.prompt)).strip()
        except EOFError:
            state.stop_event.set()
            return

        if not text:
            continue
        if text.startswith("/"):
            await handle_command(state, text)
            continue
        await handle_local_chat(state, text)


async def run_host(args: argparse.Namespace) -> None:
    """Run the application in room-hosting mode."""

    state = create_state(args.username, is_host=True)

    try:
        server = await start_server("0.0.0.0", args.port, lambda conn: accept_host_connection(state, conn))
    except OSError as exc:
        if exc.errno in {48, 98}:
            print(f"[system] Port {args.port} is already in use. Try a different port.")
            return
        raise

    print(f"[system] Hosting chat room on 0.0.0.0:{args.port}")
    input_task = asyncio.create_task(local_input_loop(state))
    try:
        await state.stop_event.wait()
    finally:
        input_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await input_task
        server.close()
        await server.wait_closed()
        await shutdown_state(state)


async def run_client(args: argparse.Namespace) -> None:
    """Run the application in client mode."""

    state = create_state(args.username, is_host=False)
    try:
        await connect_client(state, args.host, args.port)
    except ConnectionRefusedError:
        print(f"[system] Unable to connect to {args.host}:{args.port}.")
        return

    input_task = asyncio.create_task(local_input_loop(state))
    try:
        await state.stop_event.wait()
    finally:
        input_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await input_task
        await shutdown_state(state)


async def async_main() -> int:
    """Run the chat application and return a process exit code."""

    args = parse_args()
    try:
        if args.host:
            await run_client(args)
        else:
            await run_host(args)
    except KeyboardInterrupt:
        print("\n[system] Disconnecting.")
        return 0
    return 0


def main() -> None:
    """Run the asyncio entry point."""

    raise SystemExit(asyncio.run(async_main()))


if __name__ == "__main__":
    main()
