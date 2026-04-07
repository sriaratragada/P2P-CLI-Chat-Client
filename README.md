# P2P CLI Chat Client

This project contains a peer-to-peer command-line chat client built with Python 3.11+, `asyncio`, and `cryptography`.

## Setup

```bash
cd /Users/sriatragada/Downloads/P2P\ Servent/p2p_chat
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Test Locally

1. Open two terminals on the same machine or two machines on the same LAN.
2. In Terminal 1, run `python main.py --username alice --port 5555`.
3. In Terminal 2, run `python main.py --username bob --host 127.0.0.1 --port 5555`.
4. Type messages in either terminal and confirm they appear in the other.
5. Press `Ctrl+C` in either terminal to disconnect gracefully.
