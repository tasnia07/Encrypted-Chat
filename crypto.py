"""Cryptographic helpers for the modular encrypted chat application."""

from __future__ import annotations

import os
from dataclasses import dataclass

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss

AES_KEY_BYTES = 32
GCM_NONCE_BYTES = 12
GCM_TAG_BYTES = 16


@dataclass(frozen=True)
class RSAKeyPair:
    private_key: RSA.RsaKey
    public_key: RSA.RsaKey
    public_pem: str
    fingerprint: str


def fingerprint_for_pem(pem_text: str) -> str:
    digest = SHA256.new(pem_text.encode("utf-8")).hexdigest()
    return ":".join(digest[index : index + 2] for index in range(0, len(digest), 2))


def generate_rsa_keypair(bits: int = 2048) -> RSAKeyPair:
    private_key = RSA.generate(bits)
    public_key = private_key.publickey()
    public_pem = public_key.export_key().decode("utf-8")
    return RSAKeyPair(
        private_key=private_key,
        public_key=public_key,
        public_pem=public_pem,
        fingerprint=fingerprint_for_pem(public_pem),
    )


def load_public_key(pem_text: str) -> RSA.RsaKey:
    return RSA.import_key(pem_text.encode("utf-8"))


def rsa_encrypt(public_key: RSA.RsaKey, plaintext: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    return cipher.encrypt(plaintext)


def rsa_decrypt(private_key: RSA.RsaKey, ciphertext: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    return cipher.decrypt(ciphertext)


def sign_bytes(private_key: RSA.RsaKey, payload: bytes) -> bytes:
    digest = SHA256.new(payload)
    signer = pss.new(private_key)
    return signer.sign(digest)


def verify_signature(public_key: RSA.RsaKey, payload: bytes, signature: bytes) -> bool:
    digest = SHA256.new(payload)
    verifier = pss.new(public_key)
    try:
        verifier.verify(digest, signature)
        return True
    except (ValueError, TypeError):
        return False


def random_session_key() -> bytes:
    return os.urandom(AES_KEY_BYTES)


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    nonce = os.urandom(GCM_NONCE_BYTES)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + tag + ciphertext


def aes_gcm_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    min_length = GCM_NONCE_BYTES + GCM_TAG_BYTES
    if len(blob) < min_length:
        raise ValueError("Invalid AES-GCM payload length.")
    nonce = blob[:GCM_NONCE_BYTES]
    tag = blob[GCM_NONCE_BYTES : GCM_NONCE_BYTES + GCM_TAG_BYTES]
    ciphertext = blob[GCM_NONCE_BYTES + GCM_TAG_BYTES :]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)
