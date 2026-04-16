#!/usr/bin/env python3
"""Modular encrypted P2P chat application."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import sys
import threading
from dataclasses import dataclass
from typing import Callable, Optional

from ui import ChatInput, Console
from crypto import (
    AES_KEY_BYTES,
    RSAKeyPair,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    fingerprint_for_pem,
    generate_rsa_keypair,
    load_public_key,
    random_session_key,
    rsa_decrypt,
    rsa_encrypt,
    sign_bytes,
    verify_signature,
)
from protocol import (
    Envelope,
    ProtocolError,
    b64d,
    b64e,
    canonical_payload_bytes,
    decode_message,
    encode_message,
    is_fresh,
    now_ts,
)

DEFAULT_PORT = 5000
MAX_HISTORY = 500


@dataclass
class ChatRecord:
    timestamp: int
    incoming: bool
    sender: str
    text: str
    encrypted: bool


@dataclass
class PendingInitiator:
    nonce_a: str
    started_at: int
    nonce_b: Optional[str] = None
    session_key: Optional[bytes] = None
    key_id: Optional[str] = None


@dataclass
class PendingResponder:
    nonce_a: str
    nonce_b: str
    started_at: int


class SecureChatClient:
    def __init__(
        self,
        sock: socket.socket,
        peer_addr: tuple[str, int],
        nickname: str,
        console: Console,
    ):
        self.sock = sock
        self.peer_addr = peer_addr
        self.nickname = nickname
        self.peer_nickname = f"{peer_addr[0]}:{peer_addr[1]}"
        self.console = console

        self.my_keys: Optional[RSAKeyPair] = None
        self.peer_public_key = None
        self.peer_public_pem: Optional[str] = None
        self.peer_fingerprint: Optional[str] = None
        self.peer_verified = False

        self.session_key: Optional[bytes] = None
        self.session_key_id: Optional[str] = None
        self.session_established = False
        self.sec_send_seq = 0
        self.sec_recv_seq = 0

        self.pending_initiator: Optional[PendingInitiator] = None
        self.pending_responder: Optional[PendingResponder] = None

        self.history: list[ChatRecord] = []
        self.msg_sent = 0
        self.msg_recv = 0

        self._send_lock = threading.Lock()
        self._state_lock = threading.RLock()
        self._running = True
        self._receiver_thread: Optional[threading.Thread] = None

    @staticmethod
    def _normalize_fingerprint(value: str) -> str:
        return value.replace(":", "").strip().lower()

    @staticmethod
    def _derive_key_id(session_key: bytes) -> str:
        return hashlib.sha256(session_key).hexdigest()[:16]

    @staticmethod
    def _aad(purpose: str, key_id: str) -> bytes:
        return f"P2P-CHAT-V2|{purpose}|{key_id}".encode("utf-8")

    def _record_history(self, *, incoming: bool, sender: str, text: str, encrypted: bool, ts: int) -> None:
        self.history.append(
            ChatRecord(
                timestamp=ts,
                incoming=incoming,
                sender=sender,
                text=text,
                encrypted=encrypted,
            )
        )
        if len(self.history) > MAX_HISTORY:
            self.history.pop(0)

    def _ensure_local_keys(self, *, announce: bool) -> None:
        with self._state_lock:
            if self.my_keys is None:
                self.my_keys = generate_rsa_keypair()
                if announce:
                    self.console.success("Generated local RSA-2048 key pair.")
                    self.console.info(f"My key fingerprint: {self.my_keys.fingerprint}")
            elif announce:
                self.console.info("Local RSA key pair already exists.")

    def _send_envelope(self, msg_type: str, payload: dict) -> None:
        packet = encode_message(msg_type, payload)
        with self._send_lock:
            self.sock.sendall(packet)
            self.msg_sent += 1

    def _send_hello(self) -> None:
        payload = {
            "sender": self.nickname,
            "ts": now_ts(),
            "features": [
                "public-key-exchange",
                "shared-key-challenge",
                "aes-256-gcm-chat",
                "rekey",
                "fingerprint-verify",
            ],
        }
        self._send_envelope("HELLO", payload)

    def _send_public_key(self, *, reply_expected: bool, reason: str) -> None:
        self._ensure_local_keys(announce=False)
        if self.my_keys is None:
            raise RuntimeError("Local keys are unavailable.")
        payload = {
            "sender": self.nickname,
            "ts": now_ts(),
            "pem": self.my_keys.public_pem,
            "fingerprint": self.my_keys.fingerprint,
            "reply_expected": reply_expected,
            "reason": reason,
        }
        self._send_envelope("PUBKEY", payload)
        self.console.success("Public key sent.")
        self.console.info(f"My key fingerprint: {self.my_keys.fingerprint}")

    def _start_key_share(self, *, rekey: bool) -> None:
        self._ensure_local_keys(announce=False)
        with self._state_lock:
            if self.peer_public_key is None:
                self.console.warn("Peer public key is missing. Use /sendpub first.")
                return
            if self.pending_initiator is not None:
                self.console.warn("Already waiting for key-challenge response.")
                return
            nonce_a = b64e(os.urandom(16))
            self.pending_initiator = PendingInitiator(nonce_a=nonce_a, started_at=now_ts())
        self._send_envelope(
            "KEY_REQ",
            {
                "sender": self.nickname,
                "ts": now_ts(),
                "nonce_a": nonce_a,
                "rekey": rekey,
            },
        )
        action = "re-key" if rekey else "shared-key"
        self.console.info(f"Sent {action} request. Waiting for challenge.")

    def _send_plain_chat(self, text: str) -> None:
        ts = now_ts()
        self._send_envelope("PLAIN_CHAT", {"sender": self.nickname, "ts": ts, "text": text})
        self._record_history(incoming=False, sender=self.nickname, text=text, encrypted=False, ts=ts)
        self.console.chat(incoming=False, sender=self.nickname, text=text, encrypted=False, ts=ts)

    def _send_secure_chat(self, text: str) -> None:
        with self._state_lock:
            session_key = self.session_key
            key_id = self.session_key_id
            secure_ready = self.session_established and session_key is not None and key_id is not None
            if secure_ready:
                self.sec_send_seq += 1
                seq = self.sec_send_seq
            else:
                seq = 0
        if not secure_ready or session_key is None or key_id is None:
            self.console.warn("No active session key. Sending plaintext instead.")
            self._send_plain_chat(text)
            return
        inner = {"sender": self.nickname, "ts": now_ts(), "seq": seq, "text": text}
        inner_raw = json.dumps(inner, separators=(",", ":")).encode("utf-8")
        blob = aes_gcm_encrypt(session_key, inner_raw, aad=self._aad("SEC_CHAT", key_id))
        outer_ts = now_ts()
        self._send_envelope(
            "SEC_CHAT",
            {
                "sender": self.nickname,
                "ts": outer_ts,
                "key_id": key_id,
                "blob": b64e(blob),
            },
        )
        self._record_history(incoming=False, sender=self.nickname, text=text, encrypted=True, ts=inner["ts"])
        self.console.chat(incoming=False, sender=self.nickname, text=text, encrypted=True, ts=inner["ts"])

    def _send_message(self, text: str) -> None:
        with self._state_lock:
            secure_ready = self.session_established and self.session_key is not None
        if secure_ready:
            self._send_secure_chat(text)
        else:
            self._send_plain_chat(text)

    def _activate_session(self, session_key: bytes, key_id: str) -> None:
        with self._state_lock:
            old_id = self.session_key_id
            self.session_key = session_key
            self.session_key_id = key_id
            self.session_established = True
            self.sec_send_seq = 0
            self.sec_recv_seq = 0
            self.pending_initiator = None
            self.pending_responder = None
        if old_id and old_id != key_id:
            self.console.success(f"Session key rotated. New key id: {key_id}")
        else:
            self.console.success(f"Secure session established. Key id: {key_id}")

    def _show_help(self) -> None:
        commands = [
            "/help                       Show this help text",
            "/status                     Show peer info and message counters",
            "/genkeys                    Generate local RSA key pair",
            "/sendpub                    Send your public key (peer auto-replies once)",
            "/showkeys                   Show local and peer public keys + fingerprints",
            "/showsession                Show detailed session and handshake state",
            "/verify [fingerprint]       Mark peer key as verified",
            "/share                      Start shared-key setup",
            "/rekey                      Rotate shared-key setup",
            "/nick <new_name>            Change local nickname",
            "/history [count]            Show latest chat history",
            "/quit                       Exit chat",
        ]
        for row in commands:
            self.console.system(row)
        self.console.system("Input tips: left/right move cursor, up/down browse recent inputs.")

    def _show_status(self) -> None:
        with self._state_lock:
            local_key = self.my_keys is not None
            peer_key = self.peer_public_key is not None
            pending_i = self.pending_initiator is not None
            pending_r = self.pending_responder is not None
            secure = self.session_established and self.session_key is not None
            key_id = self.session_key_id or "-"
            verified = "YES" if self.peer_verified else "NO"

        self.console.info(f"Peer: {self.peer_addr[0]}:{self.peer_addr[1]} ({self.peer_nickname})")
        self.console.info(f"Nickname: {self.nickname}")
        self.console.info(f"Local key loaded: {'YES' if local_key else 'NO'}")
        self.console.info(f"Peer key loaded: {'YES' if peer_key else 'NO'} | verified: {verified}")
        self.console.info(f"Pending initiator flow: {'YES' if pending_i else 'NO'}")
        self.console.info(f"Pending responder flow: {'YES' if pending_r else 'NO'}")
        self.console.info(f"Secure session: {'YES' if secure else 'NO'} | key_id: {key_id}")
        self.console.info(f"Messages sent: {self.msg_sent} | received: {self.msg_recv}")
        self.console.info(f"History items: {len(self.history)}")

    def _show_keys(self) -> None:
        with self._state_lock:
            my_fingerprint = self.my_keys.fingerprint if self.my_keys else None
            my_pem = self.my_keys.public_pem if self.my_keys else None
            peer_fingerprint = self.peer_fingerprint
            peer_pem = self.peer_public_pem
            peer_verified = self.peer_verified
        if my_pem:
            self.console.system("[My Public Key]")
            for line in my_pem.splitlines():
                self.console.system(line)
            self.console.info(f"My fingerprint: {my_fingerprint}")
        else:
            self.console.warn("My key is not generated yet. Use /genkeys or /sendpub.")
        if peer_pem:
            self.console.system("[Peer Public Key]")
            for line in peer_pem.splitlines():
                self.console.system(line)
            self.console.info(f"Peer fingerprint: {peer_fingerprint}")
            self.console.info(f"Peer fingerprint verified: {'YES' if peer_verified else 'NO'}")
        else:
            self.console.warn("No peer key stored yet.")

    def _show_session(self) -> None:
        with self._state_lock:
            has_key = self.session_key is not None
            established = self.session_established
            key_id = self.session_key_id or "-"
            is_initiator = self.pending_initiator is not None
            is_responder = self.pending_responder is not None
            send_seq = self.sec_send_seq
            recv_seq = self.sec_recv_seq
        self.console.system("[Session Status]")
        self.console.info(f"  Session key present: {'YES' if has_key else 'NO'}")
        self.console.info(f"  Session established: {'YES' if established else 'NO'}")
        self.console.info(f"  Key ID: {key_id}")
        if is_initiator:
            self.console.info("  Role: A (initiator) — waiting for KEY_CHALLENGE / KEY_ACK")
        elif is_responder:
            self.console.info("  Role: B (responder) — waiting for KEY_SET")
        else:
            self.console.info("  Role: None (no pending handshake)")
        self.console.info(f"  Send sequence: {send_seq} | Recv sequence: {recv_seq}")

    def _verify_peer(self, expected: Optional[str]) -> None:
        with self._state_lock:
            fingerprint = self.peer_fingerprint
        if fingerprint is None:
            self.console.warn("Cannot verify. Peer fingerprint is unavailable.")
            return
        if expected:
            if self._normalize_fingerprint(expected) != self._normalize_fingerprint(fingerprint):
                self.console.error("Fingerprint mismatch. Peer key remains unverified.")
                return
        with self._state_lock:
            self.peer_verified = True
        self.console.success(f"Peer fingerprint verified: {fingerprint}")

    def _show_history(self, count: int) -> None:
        if count <= 0:
            self.console.warn("History count must be positive.")
            return
        items = self.history[-count:]
        if not items:
            self.console.info("History is empty.")
            return
        for row in items:
            self.console.chat(
                incoming=row.incoming,
                sender=row.sender,
                text=row.text,
                encrypted=row.encrypted,
                ts=row.timestamp,
            )

    def _set_nickname(self, new_name: str) -> None:
        candidate = new_name.strip()
        if not candidate:
            self.console.warn("Nickname cannot be empty.")
            return
        if len(candidate) > 24:
            self.console.warn("Nickname length must be <= 24 characters.")
            return
        self.nickname = candidate
        self._send_envelope("NICK_UPDATE", {"sender": self.nickname, "ts": now_ts()})
        self.console.success(f"Nickname updated to: {self.nickname}")

    def _handle_command(self, line: str) -> bool:
        parts = line.split()
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd == "/quit":
            return True
        if cmd == "/help":
            self._show_help()
            return False
        if cmd == "/status":
            self._show_status()
            return False
        if cmd == "/genkeys":
            self._ensure_local_keys(announce=True)
            return False
        if cmd == "/sendpub":
            self._send_public_key(reply_expected=True, reason="manual")
            return False
        if cmd == "/showkeys":
            self._show_keys()
            return False
        if cmd == "/showsession":
            self._show_session()
            return False
        if cmd == "/verify":
            self._verify_peer(args[0] if args else None)
            return False
        if cmd == "/share":
            self._start_key_share(rekey=False)
            return False
        if cmd == "/rekey":
            self._start_key_share(rekey=True)
            return False
        if cmd == "/nick":
            if not args:
                self.console.warn("Usage: /nick <new_name>")
                return False
            self._set_nickname(" ".join(args))
            return False
        if cmd == "/history":
            amount = 20
            if args:
                try:
                    amount = int(args[0])
                except ValueError:
                    self.console.warn("History count must be an integer.")
                    return False
            self._show_history(amount)
            return False

        self.console.warn(f"Unknown command: {cmd}. Use /help.")
        return False

    def _recv_loop(self) -> None:
        buffer = b""
        while self._running:
            try:
                chunk = self.sock.recv(4096)
            except OSError as exc:
                if self._running:
                    self.console.error(f"Socket receive failed: {exc}")
                self._running = False
                break

            if not chunk:
                if self._running:
                    self.console.warn("Peer disconnected.")
                self._running = False
                break

            buffer += chunk
            while True:
                newline_index = buffer.find(b"\n")
                if newline_index == -1:
                    break
                line = buffer[:newline_index]
                buffer = buffer[newline_index + 1 :]
                if not line:
                    continue
                self._process_line(line)

    def _process_line(self, line: bytes) -> None:
        try:
            envelope = decode_message(line)
        except ProtocolError as exc:
            self.console.warn(f"Protocol decode warning: {exc}")
            return

        handlers: dict[str, Callable[[Envelope], None]] = {
            "HELLO": self._on_hello,
            "NICK_UPDATE": self._on_nick_update,
            "PUBKEY": self._on_pubkey,
            "KEY_REQ": self._on_key_req,
            "KEY_CHALLENGE": self._on_key_challenge,
            "KEY_SET": self._on_key_set,
            "KEY_ACK": self._on_key_ack,
            "PLAIN_CHAT": self._on_plain_chat,
            "SEC_CHAT": self._on_sec_chat,
        }
        handler = handlers.get(envelope.msg_type)
        if handler is None:
            self.console.warn(f"Ignoring unknown message type: {envelope.msg_type}")
            return

        try:
            handler(envelope)
        except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            self.console.warn(f"Invalid {envelope.msg_type} payload: {exc}")

    def _on_hello(self, envelope: Envelope) -> None:
        sender = envelope.payload.get("sender")
        if isinstance(sender, str) and sender:
            self.peer_nickname = sender
        self.console.system(f"Peer hello received from {self.peer_nickname}.")

    def _on_nick_update(self, envelope: Envelope) -> None:
        sender = envelope.payload.get("sender")
        if isinstance(sender, str) and sender:
            self.peer_nickname = sender
            self.console.info(f"Peer nickname changed to {sender}.")

    def _on_pubkey(self, envelope: Envelope) -> None:
        payload = envelope.payload
        sender = payload.get("sender")
        pem = payload.get("pem")
        claimed_fp = payload.get("fingerprint")
        reply_expected = bool(payload.get("reply_expected", False))

        if not isinstance(sender, str) or not sender:
            raise ValueError("PUBKEY sender missing.")
        if not isinstance(pem, str) or "BEGIN PUBLIC KEY" not in pem:
            raise ValueError("PUBKEY PEM is invalid.")
        if not isinstance(claimed_fp, str):
            raise ValueError("PUBKEY fingerprint is invalid.")

        calculated_fp = fingerprint_for_pem(pem)
        if self._normalize_fingerprint(calculated_fp) != self._normalize_fingerprint(claimed_fp):
            self.console.warn("Peer fingerprint claim did not match computed fingerprint.")

        public_key = load_public_key(pem)
        with self._state_lock:
            changed = self.peer_fingerprint is not None and (
                self._normalize_fingerprint(self.peer_fingerprint) != self._normalize_fingerprint(calculated_fp)
            )
            self.peer_public_key = public_key
            self.peer_public_pem = pem
            self.peer_fingerprint = calculated_fp
            self.peer_nickname = sender
            if changed:
                self.peer_verified = False
                self.console.warn("Peer key changed. Verification reset.")

        self.console.success(f"Stored peer public key from {sender}.")
        self.console.info(f"Peer fingerprint: {calculated_fp}")

        if reply_expected:
            self._send_public_key(reply_expected=False, reason="auto-response")
            self.console.info("Sent key exchange reply to peer.")

    def _on_key_req(self, envelope: Envelope) -> None:
        payload = envelope.payload
        sender = payload.get("sender")
        nonce_a = payload.get("nonce_a")
        req_ts = payload.get("ts")
        is_rekey = bool(payload.get("rekey", False))

        if not isinstance(sender, str) or not sender:
            raise ValueError("KEY_REQ sender missing.")
        if not isinstance(nonce_a, str) or not nonce_a:
            raise ValueError("KEY_REQ nonce_a missing.")
        if not isinstance(req_ts, int) or not is_fresh(req_ts):
            raise ValueError("KEY_REQ timestamp is stale.")

        self.peer_nickname = sender
        self._ensure_local_keys(announce=False)
        with self._state_lock:
            if self.peer_public_key is None:
                self.console.warn("KEY_REQ received before peer key exchange. Ignoring.")
                return
            nonce_b = b64e(os.urandom(16))
            self.pending_responder = PendingResponder(
                nonce_a=nonce_a,
                nonce_b=nonce_b,
                started_at=now_ts(),
            )

        self._send_envelope(
            "KEY_CHALLENGE",
            {
                "sender": self.nickname,
                "ts": now_ts(),
                "nonce_a": nonce_a,
                "nonce_b": nonce_b,
                "rekey": is_rekey,
            },
        )
        action = "re-key" if is_rekey else "shared-key"
        self.console.info(f"Accepted {action} request and sent challenge.")

    def _on_key_challenge(self, envelope: Envelope) -> None:
        payload = envelope.payload
        sender = payload.get("sender")
        nonce_a = payload.get("nonce_a")
        nonce_b = payload.get("nonce_b")
        challenge_ts = payload.get("ts")

        if not isinstance(sender, str) or not sender:
            raise ValueError("KEY_CHALLENGE sender missing.")
        if not isinstance(nonce_a, str) or not nonce_a:
            raise ValueError("KEY_CHALLENGE nonce_a missing.")
        if not isinstance(nonce_b, str) or not nonce_b:
            raise ValueError("KEY_CHALLENGE nonce_b missing.")
        if not isinstance(challenge_ts, int) or not is_fresh(challenge_ts):
            raise ValueError("KEY_CHALLENGE timestamp is stale.")

        self.peer_nickname = sender
        self._ensure_local_keys(announce=False)

        with self._state_lock:
            pending = self.pending_initiator
            peer_key = self.peer_public_key
            my_keys = self.my_keys
        if pending is None or pending.nonce_a != nonce_a:
            self.console.warn("Unexpected KEY_CHALLENGE received. Ignoring.")
            return
        if peer_key is None:
            self.console.warn("Cannot continue key exchange without peer public key.")
            return
        if my_keys is None:
            self.console.warn("Cannot continue key exchange without local private key.")
            return

        session_key = random_session_key()
        key_id = self._derive_key_id(session_key)
        encrypted_key = rsa_encrypt(peer_key, session_key)
        signed_payload = {
            "sender": self.nickname,
            "ts": now_ts(),
            "nonce_a": nonce_a,
            "nonce_b": nonce_b,
            "key_id": key_id,
            "ek": b64e(encrypted_key),
        }
        signature = sign_bytes(my_keys.private_key, canonical_payload_bytes(signed_payload))
        outbound = dict(signed_payload)
        outbound["sig"] = b64e(signature)
        self._send_envelope("KEY_SET", outbound)

        with self._state_lock:
            pending.nonce_b = nonce_b
            pending.session_key = session_key
            pending.key_id = key_id
        self.console.info("Sent signed shared session key to peer. Waiting for acknowledgement.")

    def _on_key_set(self, envelope: Envelope) -> None:
        payload = envelope.payload
        sender = payload.get("sender")
        key_ts = payload.get("ts")
        nonce_a = payload.get("nonce_a")
        nonce_b = payload.get("nonce_b")
        key_id = payload.get("key_id")
        encrypted_key = payload.get("ek")
        signature_b64 = payload.get("sig")

        if not isinstance(sender, str) or not sender:
            raise ValueError("KEY_SET sender missing.")
        if not isinstance(key_ts, int) or not is_fresh(key_ts):
            raise ValueError("KEY_SET timestamp is stale.")
        if not isinstance(nonce_a, str) or not nonce_a:
            raise ValueError("KEY_SET nonce_a missing.")
        if not isinstance(nonce_b, str) or not nonce_b:
            raise ValueError("KEY_SET nonce_b missing.")
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("KEY_SET key_id missing.")
        if not isinstance(encrypted_key, str) or not encrypted_key:
            raise ValueError("KEY_SET encrypted key missing.")
        if not isinstance(signature_b64, str) or not signature_b64:
            raise ValueError("KEY_SET signature missing.")

        with self._state_lock:
            pending = self.pending_responder
            peer_key = self.peer_public_key
            my_keys = self.my_keys
        if pending is None:
            self.console.warn("Unexpected KEY_SET received. No responder state pending.")
            return
        if pending.nonce_a != nonce_a or pending.nonce_b != nonce_b:
            self.console.warn("KEY_SET nonce mismatch. Ignoring message.")
            return
        if peer_key is None or my_keys is None:
            self.console.warn("Cannot verify KEY_SET without both peer key and local private key.")
            return

        signed_payload = {
            "sender": sender,
            "ts": key_ts,
            "nonce_a": nonce_a,
            "nonce_b": nonce_b,
            "key_id": key_id,
            "ek": encrypted_key,
        }
        signature = b64d(signature_b64)
        if not verify_signature(peer_key, canonical_payload_bytes(signed_payload), signature):
            self.console.error("KEY_SET signature verification failed.")
            return

        session_key = rsa_decrypt(my_keys.private_key, b64d(encrypted_key))
        if len(session_key) != AES_KEY_BYTES:
            self.console.error("Recovered shared key length is invalid.")
            return
        computed_id = self._derive_key_id(session_key)
        if computed_id != key_id:
            self.console.error("KEY_SET key_id mismatch.")
            return

        self._activate_session(session_key, key_id)

        ack_payload = {
            "sender": self.nickname,
            "ts": now_ts(),
            "nonce_b": nonce_b,
            "key_id": key_id,
        }
        ack_raw = json.dumps(ack_payload, separators=(",", ":")).encode("utf-8")
        blob = aes_gcm_encrypt(session_key, ack_raw, aad=self._aad("KEY_ACK", key_id))
        self._send_envelope(
            "KEY_ACK",
            {
                "sender": self.nickname,
                "ts": now_ts(),
                "key_id": key_id,
                "blob": b64e(blob),
            },
        )
        self.console.success("Shared key accepted and acknowledgement sent.")

    def _on_key_ack(self, envelope: Envelope) -> None:
        payload = envelope.payload
        sender = payload.get("sender")
        key_id = payload.get("key_id")
        blob_b64 = payload.get("blob")

        if not isinstance(sender, str) or not sender:
            raise ValueError("KEY_ACK sender missing.")
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("KEY_ACK key_id missing.")
        if not isinstance(blob_b64, str) or not blob_b64:
            raise ValueError("KEY_ACK blob missing.")

        with self._state_lock:
            pending = self.pending_initiator
        if pending is None or pending.session_key is None or pending.key_id is None or pending.nonce_b is None:
            self.console.warn("Unexpected KEY_ACK. No initiator state pending.")
            return
        if pending.key_id != key_id:
            self.console.warn("KEY_ACK key_id does not match pending handshake.")
            return

        raw = aes_gcm_decrypt(
            pending.session_key,
            b64d(blob_b64),
            aad=self._aad("KEY_ACK", pending.key_id),
        )
        ack_payload = json.loads(raw.decode("utf-8"))

        ack_nonce_b = ack_payload.get("nonce_b")
        ack_key_id = ack_payload.get("key_id")
        ack_ts = ack_payload.get("ts")
        if ack_nonce_b != pending.nonce_b:
            self.console.error("KEY_ACK nonce verification failed.")
            return
        if ack_key_id != pending.key_id:
            self.console.error("KEY_ACK key id verification failed.")
            return
        if not isinstance(ack_ts, int) or not is_fresh(ack_ts):
            self.console.error("KEY_ACK timestamp is stale.")
            return

        self._activate_session(pending.session_key, pending.key_id)
        self.peer_nickname = sender
        self.console.success("Peer confirmed shared key exchange.")

    def _on_plain_chat(self, envelope: Envelope) -> None:
        payload = envelope.payload
        sender = payload.get("sender")
        text = payload.get("text")
        ts = payload.get("ts")

        if not isinstance(sender, str) or not sender:
            raise ValueError("PLAIN_CHAT sender missing.")
        if not isinstance(text, str):
            raise ValueError("PLAIN_CHAT text missing.")
        if not isinstance(ts, int):
            raise ValueError("PLAIN_CHAT timestamp missing.")

        self.peer_nickname = sender
        self.msg_recv += 1
        self._record_history(incoming=True, sender=sender, text=text, encrypted=False, ts=ts)
        self.console.chat(incoming=True, sender=sender, text=text, encrypted=False, ts=ts)

    def _on_sec_chat(self, envelope: Envelope) -> None:
        payload = envelope.payload
        sender = payload.get("sender")
        key_id = payload.get("key_id")
        blob_b64 = payload.get("blob")

        if not isinstance(sender, str) or not sender:
            raise ValueError("SEC_CHAT sender missing.")
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("SEC_CHAT key_id missing.")
        if not isinstance(blob_b64, str) or not blob_b64:
            raise ValueError("SEC_CHAT blob missing.")

        with self._state_lock:
            active_key = self.session_key
            active_key_id = self.session_key_id
        if active_key is None or active_key_id is None or not self.session_established:
            self.console.warn("Received encrypted message but no secure session is active.")
            return
        if key_id != active_key_id:
            self.console.warn(f"Ignoring SEC_CHAT for stale key id {key_id}.")
            return

        raw = aes_gcm_decrypt(active_key, b64d(blob_b64), aad=self._aad("SEC_CHAT", key_id))
        inner = json.loads(raw.decode("utf-8"))
        text = inner.get("text")
        ts = inner.get("ts")
        seq = inner.get("seq")
        inner_sender = inner.get("sender")
        if not isinstance(text, str):
            raise ValueError("SEC_CHAT decrypted text missing.")
        if not isinstance(ts, int):
            raise ValueError("SEC_CHAT decrypted timestamp missing.")
        if not isinstance(seq, int) or seq <= 0:
            raise ValueError("SEC_CHAT decrypted sequence missing.")
        with self._state_lock:
            expected_seq = self.sec_recv_seq + 1
            if seq <= self.sec_recv_seq:
                self.console.warn(f"Ignoring replayed SEC_CHAT seq {seq}. Last accepted: {self.sec_recv_seq}.")
                return
            if seq != expected_seq:
                self.console.warn(f"Ignoring out-of-order SEC_CHAT seq {seq}. Expected: {expected_seq}.")
                return
            self.sec_recv_seq = seq
        if isinstance(inner_sender, str) and inner_sender:
            sender = inner_sender

        self.peer_nickname = sender
        self.msg_recv += 1
        self._record_history(incoming=True, sender=sender, text=text, encrypted=True, ts=ts)
        self.console.chat(incoming=True, sender=sender, text=text, encrypted=True, ts=ts)

    def _close_socket(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    @staticmethod
    def _read_line_or_quit(chat_input: ChatInput) -> str:
        try:
            return chat_input.read_line().strip()
        except (EOFError, KeyboardInterrupt):
            return "/quit"

    def run(self) -> None:
        self._receiver_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._receiver_thread.start()

        self._send_hello()
        self.console.system("Connected. Type /help for commands.")
        self._show_status()

        try:
            chat_input = ChatInput(prompt="chat> ")
        except RuntimeError as exc:
            self.console.error(str(exc))
            self._running = False

        while self._running:
            line = self._read_line_or_quit(chat_input)

            if not line:
                continue

            if line.startswith("/"):
                try:
                    should_quit = self._handle_command(line)
                except OSError as exc:
                    self.console.error(f"Command failed due to socket error: {exc}")
                    should_quit = True
                if should_quit:
                    self._running = False
                    break
            else:
                try:
                    self._send_message(line)
                except OSError as exc:
                    self.console.error(f"Message send failed: {exc}")
                    self._running = False
                    break

        self._close_socket()
        self.console.system("Chat client exited.")


def parse_port(raw: str) -> int:
    port = int(raw)
    if not (1 <= port <= 65535):
        raise ValueError("Port must be between 1 and 65535.")
    return port


def listen_once(port: int, console: Console) -> tuple[socket.socket, tuple[str, int]]:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(1)
    console.system(f"Listening on 0.0.0.0:{port} ...")
    sock, addr = server.accept()
    server.close()
    console.success(f"Peer connected from {addr[0]}:{addr[1]}")
    return sock, (addr[0], addr[1])


def connect_to(host: str, port: int, console: Console) -> tuple[socket.socket, tuple[str, int]]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    console.success(f"Connected to {host}:{port}")
    return sock, (host, port)


def default_nickname() -> str:
    user = os.getenv("USER") or os.getenv("USERNAME") or "user"
    suffix = os.urandom(2).hex()
    return f"{user}-{suffix}"


def prompt_connection_mode(console: Console) -> tuple[str, str, int]:
    console.system("Setup mode: [L]isten or [C]onnect")
    mode_input = input("setup> ").strip().lower()
    if mode_input.startswith("l"):
        console.system(f"Listen port [{DEFAULT_PORT}]")
        port_raw = input("setup> ").strip() or str(DEFAULT_PORT)
        return ("listen", "0.0.0.0", parse_port(port_raw))
    if mode_input.startswith("c"):
        console.system("Peer IP address (for example, 127.0.0.1):")
        host = input("setup> ").strip()
        console.system(f"Peer port [{DEFAULT_PORT}]")
        port_raw = input("setup> ").strip() or str(DEFAULT_PORT)
        if not host:
            raise ValueError("Peer host cannot be empty.")
        return ("connect", host, parse_port(port_raw))
    raise ValueError("Unknown mode selection.")


def resolve_connection_args(args: argparse.Namespace, console: Console) -> tuple[str, str, int]:
    if args.mode is None:
        return prompt_connection_mode(console)

    mode = args.mode.lower()
    if mode == "listen":
        if args.addr_or_port is None:
            raise ValueError("Usage: main.py listen <port>")
        if args.port is not None:
            raise ValueError("Listen mode only accepts one numeric port argument.")
        return ("listen", "0.0.0.0", parse_port(args.addr_or_port))

    if mode == "connect":
        if args.addr_or_port is None or args.port is None:
            raise ValueError("Usage: main.py connect <ip> <port>")
        return ("connect", args.addr_or_port, parse_port(args.port))

    raise ValueError("Mode must be either 'listen' or 'connect'.")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Modular encrypted chat (RSA + AES-256-GCM).",
    )
    parser.add_argument("mode", nargs="?", help="listen or connect")
    parser.add_argument("addr_or_port", nargs="?", help="listen:<port> or connect:<host>")
    parser.add_argument("port", nargs="?", help="connect port")
    parser.add_argument("--nick", default=None, help="Local nickname")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    return parser


def main(argv: list[str]) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv[1:])

    console = Console(use_color=not args.no_color)
    try:
        mode, host, port = resolve_connection_args(args, console)
    except ValueError as exc:
        console.error(str(exc))
        return 2

    nickname = args.nick.strip() if isinstance(args.nick, str) and args.nick.strip() else default_nickname()
    console.info(f"Local nickname: {nickname}")

    try:
        if mode == "listen":
            sock, peer_addr = listen_once(port, console)
        else:
            sock, peer_addr = connect_to(host, port, console)
    except OSError as exc:
        console.error(f"Connection setup failed: {exc}")
        return 3

    client = SecureChatClient(sock=sock, peer_addr=peer_addr, nickname=nickname, console=console)
    client.run()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
