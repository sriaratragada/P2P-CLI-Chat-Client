"""Wire protocol helpers for framing JSON messages."""

from __future__ import annotations

import json
import struct
from typing import Any


def pack_message(msg_dict: dict[str, Any]) -> bytes:
    """Pack a message dict into a length-prefixed JSON byte sequence."""

    payload = json.dumps(msg_dict).encode("utf-8")
    return struct.pack(">I", len(payload)) + payload


def unpack_message(raw_bytes: bytes) -> dict[str, Any]:
    """Decode a JSON payload into a message dict."""

    return json.loads(raw_bytes.decode("utf-8"))
