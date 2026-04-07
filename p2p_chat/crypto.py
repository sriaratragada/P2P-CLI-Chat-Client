"""Cryptographic helpers for the P2P chat client."""

from __future__ import annotations

import os
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def generate_rsa_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate a new 2048-bit RSA private/public key pair."""

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def serialize_public_key(pub_key: rsa.RSAPublicKey) -> bytes:
    """Serialize an RSA public key to PEM-encoded bytes."""

    return pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(pem_bytes: bytes) -> rsa.RSAPublicKey:
    """Deserialize a PEM-encoded RSA public key."""

    public_key = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Loaded key is not an RSA public key.")
    return public_key


def encrypt_with_rsa(pub_key: rsa.RSAPublicKey, plaintext_bytes: bytes) -> bytes:
    """Encrypt bytes using an RSA public key and OAEP-SHA256."""

    return pub_key.encrypt(
        plaintext_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt_with_rsa(priv_key: rsa.RSAPrivateKey, ciphertext_bytes: bytes) -> bytes:
    """Decrypt bytes using an RSA private key and OAEP-SHA256."""

    return priv_key.decrypt(
        ciphertext_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def generate_aes_key() -> bytes:
    """Generate a fresh 256-bit AES session key."""

    return os.urandom(32)


def aes_encrypt(key: bytes, plaintext_str: str) -> dict[str, str]:
    """Encrypt a UTF-8 string with AES-256-GCM."""

    iv = os.urandom(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(plaintext_str.encode("utf-8")) + encryptor.finalize()
    return {
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": encryptor.tag.hex(),
    }


def aes_decrypt(key: bytes, iv_hex: str, ciphertext_hex: str, tag_hex: str) -> str:
    """Decrypt an AES-256-GCM payload and return the UTF-8 plaintext."""

    iv = bytes.fromhex(iv_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    tag = bytes.fromhex(tag_hex)
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode("utf-8")
