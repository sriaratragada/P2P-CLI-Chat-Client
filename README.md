# P2P CLI Chat Client

Encrypted LAN chat in Python with:

- async TCP networking via `asyncio`
- RSA public key exchange
- AES-256-GCM encrypted session payloads
- room hosting for multiple peers
- `/nick` display-name changes
- delivery acknowledgments with message IDs
- small file transfer over the LAN

## Project Layout

```text
p2p_chat/
├── main.py
├── network.py
├── crypto.py
├── protocol.py
├── ui.py
└── requirements.txt
```

## Requirements

- Python 3.11+
- `cryptography==42.0.8`

## Setup

```bash
cd "/Users/sriatragada/Downloads/P2P Servent/p2p_chat"
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run Locally

### Host a Room

Terminal 1:

```bash
cd "/Users/sriatragada/Downloads/P2P Servent/p2p_chat"
source .venv/bin/activate
python main.py --username alice --port 5555
```

### Join the Room

Terminal 2:

```bash
cd "/Users/sriatragada/Downloads/P2P Servent/p2p_chat"
source .venv/bin/activate
python main.py --username bob --host 127.0.0.1 --port 5555
```

Terminal 3:

```bash
cd "/Users/sriatragada/Downloads/P2P Servent/p2p_chat"
source .venv/bin/activate
python main.py --username carol --host 127.0.0.1 --port 5555
```

## Test Flow

1. Start the host in one terminal.
2. Start one or more clients against the host IP and port.
3. Send messages from any terminal.
4. Confirm messages are relayed to the rest of the room.
5. Run `/nick new_name` in one terminal and confirm other peers see the rename.
6. Run `/sendfile path/to/file.txt` and confirm receivers get the file in `p2p_chat/received_files/`.
7. Press `Ctrl+C` or run `/quit` to disconnect.

## Commands

- `/nick NEW_NAME`: change your display name mid-session
- `/sendfile PATH`: send a file up to 256 KB to the room
- `/who`: print connected users
- `/help`: print supported commands
- `/quit`: exit the application

## How It Works

1. Each process creates an RSA keypair on startup.
2. When a TCP connection is established, both sides immediately send a `pubkey` packet containing:
   - username
   - participant ID
   - PEM-encoded public key
3. The connecting side generates the AES session key and sends it in an `aes_key` packet encrypted with the peer's RSA public key.
4. After the handshake, application payloads are encrypted with AES-256-GCM and sent inside secure envelopes.
5. The room host decrypts client payloads and re-encrypts them for each connected peer.

## Message Types

Handshake packets:

- `pubkey`
- `aes_key`

Encrypted application payload kinds:

- `chat`
- `file`
- `nick`
- `ack`
- `roster`
- `system`

## Delivery Acknowledgments

- Every chat message, file transfer, and nick change gets a message ID.
- Receivers send an `ack` back after they process the payload.
- The original sender sees delivery confirmations in the CLI.

## File Transfer

- Files are base64-encoded inside the encrypted payload.
- Maximum file size is 256 KB.
- Received files are written to:

```text
p2p_chat/received_files/
```

- If a filename already exists, the client writes a numbered copy instead of overwriting it.

## Troubleshooting

- `ModuleNotFoundError: cryptography`
  - Activate the virtual environment and run `pip install -r requirements.txt`.
- `Port 5555 is already in use`
  - Pick a different port and use the same one for host and clients.
- `Unable to connect`
  - Make sure the host process is already running and the host IP is reachable.
- No messages appear
  - Confirm every terminal is using the virtualenv interpreter and that local firewall settings are not blocking the TCP port.

## LAN Usage

To connect from another machine on the same network:

1. Start the host:

```bash
python main.py --username alice --port 5555
```

2. Find the host machine's LAN IP, for example `192.168.1.20`.
3. On another machine, join the room:

```bash
python main.py --username bob --host 192.168.1.20 --port 5555
```
