"""Wire-format helpers for newline-delimited JSON protocol messages."""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any

PROTOCOL_VERSION = 1
MAX_CLOCK_SKEW_SECONDS = 180


class ProtocolError(ValueError):
    """Raised when incoming wire data is malformed or invalid."""


@dataclass(frozen=True)
class Envelope:
    version: int
    msg_type: str
    payload: dict[str, Any]


def now_ts() -> int:
    return int(time.time())


def b64e(blob: bytes) -> str:
    return base64.b64encode(blob).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def canonical_payload_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def encode_message(msg_type: str, payload: dict[str, Any]) -> bytes:
    if not isinstance(payload, dict):
        raise TypeError("Payload must be a dictionary.")
    envelope = {"v": PROTOCOL_VERSION, "type": msg_type, "payload": payload}
    return (json.dumps(envelope, separators=(",", ":")) + "\n").encode("utf-8")


def decode_message(line: bytes) -> Envelope:
    try:
        decoded = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"Invalid message encoding: {exc}") from exc

    if not isinstance(decoded, dict):
        raise ProtocolError("Envelope is not a JSON object.")

    version = decoded.get("v")
    msg_type = decoded.get("type")
    payload = decoded.get("payload")

    if version != PROTOCOL_VERSION:
        raise ProtocolError(f"Unsupported protocol version: {version}")
    if not isinstance(msg_type, str) or not msg_type:
        raise ProtocolError("Envelope 'type' must be a non-empty string.")
    if not isinstance(payload, dict):
        raise ProtocolError("Envelope 'payload' must be a JSON object.")

    return Envelope(version=version, msg_type=msg_type, payload=payload)


def is_fresh(timestamp: int, now: int | None = None, max_skew: int = MAX_CLOCK_SKEW_SECONDS) -> bool:
    if now is None:
        now = now_ts()
    return abs(now - int(timestamp)) <= max_skew
