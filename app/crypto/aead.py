"""Authenticated Encryption with Associated Data (AEAD) implementations.

Supports:
- AES-256-GCM (NIST SP 800-38D)
- ChaCha20-Poly1305 (RFC 8439)
"""

from typing import Dict, List, Optional
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


class AEADError(Exception):
    """Base exception for AEAD operations."""
    pass


class AEADKeyError(AEADError):
    """Raised when key is invalid or wrong length."""
    pass


class AEADNonceError(AEADError):
    """Raised when nonce is invalid or wrong length."""
    pass


class AEADDecryptionError(AEADError):
    """Raised when authentication tag verification or decryption fails."""
    pass


def _normalize_cipher_name(cipher: str) -> str:
    """Normalize cipher name to standard identifier."""
    c = cipher.strip().upper().replace(" ", "").replace("_", "-")
    if c in ("AES-256-GCM", "AES256GCM", "AES-GCM", "AESGCM"):
        return "AES-256-GCM"
    if c in ("CHACHA20-POLY1305", "CHACHA20POLY1305", "CHACHA20"):
        return "ChaCha20-Poly1305"
    raise AEADError(f"Unsupported AEAD cipher '{cipher}'. Supported: AES-256-GCM, ChaCha20-Poly1305")


def encrypt_aead(
    key: bytes,
    plaintext: bytes,
    associated_data: Optional[bytes] = None,
    nonce: Optional[bytes] = None,
    cipher_name: str = "AES-256-GCM",
) -> Dict[str, bytes]:
    """Encrypt and authenticate plaintext using specified AEAD cipher.

    Args:
        key: 32-byte (256-bit) symmetric key.
        plaintext: Plaintext bytes to encrypt.
        associated_data: Optional authenticated but unencrypted metadata.
        nonce: Optional 12-byte nonce (if None, a cryptographically secure random nonce is generated).
        cipher_name: 'AES-256-GCM' or 'ChaCha20-Poly1305'.

    Returns:
        Dictionary with:
            - 'ciphertext': Encrypted data bytes (without tag).
            - 'nonce': 12-byte nonce used.
            - 'tag': 16-byte authentication tag.
            - 'cipher': Normalized cipher name string.

    Raises:
        AEADError, AEADKeyError, AEADNonceError: On validation or encryption errors.
    """
    if not isinstance(key, (bytes, bytearray)):
        raise AEADKeyError("Encryption key must be bytes")
    if len(key) != 32:
        raise AEADKeyError(f"AEAD key must be exactly 32 bytes (256 bits), got {len(key)}")

    if not isinstance(plaintext, (bytes, bytearray)):
        raise AEADError("Plaintext must be bytes")

    if nonce is None:
        nonce = os.urandom(12)
    else:
        if not isinstance(nonce, (bytes, bytearray)):
            raise AEADNonceError("Nonce must be bytes")
        if len(nonce) != 12:
            raise AEADNonceError(f"AEAD nonce must be exactly 12 bytes, got {len(nonce)}")

    aad = bytes(associated_data) if associated_data is not None else None
    norm_cipher = _normalize_cipher_name(cipher_name)

    try:
        if norm_cipher == "AES-256-GCM":
            cipher_obj = AESGCM(bytes(key))
        else:
            cipher_obj = ChaCha20Poly1305(bytes(key))

        combined = cipher_obj.encrypt(bytes(nonce), bytes(plaintext), aad)
        ciphertext = combined[:-16]
        tag = combined[-16:]

        return {
            "ciphertext": ciphertext,
            "nonce": bytes(nonce),
            "tag": tag,
            "cipher": norm_cipher.encode("utf-8"),
        }
    except Exception as e:
        if isinstance(e, AEADError):
            raise
        raise AEADError(f"AEAD encryption error: {str(e)}") from e


def decrypt_aead(
    key: bytes,
    ciphertext: bytes,
    nonce: bytes,
    tag: bytes,
    associated_data: Optional[bytes] = None,
    cipher_name: str = "AES-256-GCM",
) -> bytes:
    """Decrypt and verify ciphertext using specified AEAD cipher and authentication tag.

    Args:
        key: 32-byte symmetric key.
        ciphertext: Encrypted payload bytes.
        nonce: 12-byte nonce used during encryption.
        tag: 16-byte authentication tag.
        associated_data: Associated data authenticated during encryption.
        cipher_name: 'AES-256-GCM' or 'ChaCha20-Poly1305'.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        AEADDecryptionError: If authentication verification fails or payload was tampered with.
        AEADError, AEADKeyError, AEADNonceError: If inputs are invalid.
    """
    if not isinstance(key, (bytes, bytearray)):
        raise AEADKeyError("Decryption key must be bytes")
    if len(key) != 32:
        raise AEADKeyError(f"AEAD key must be exactly 32 bytes (256 bits), got {len(key)}")

    if not isinstance(ciphertext, (bytes, bytearray)):
        raise AEADError("Ciphertext must be bytes")

    if not isinstance(nonce, (bytes, bytearray)):
        raise AEADNonceError("Nonce must be bytes")
    if len(nonce) != 12:
        raise AEADNonceError(f"AEAD nonce must be exactly 12 bytes, got {len(nonce)}")

    if not isinstance(tag, (bytes, bytearray)):
        raise AEADDecryptionError("Authentication tag must be bytes")
    if len(tag) != 16:
        raise AEADDecryptionError(f"Authentication tag must be exactly 16 bytes, got {len(tag)}")

    aad = bytes(associated_data) if associated_data is not None else None
    norm_cipher = _normalize_cipher_name(cipher_name)

    combined = bytes(ciphertext) + bytes(tag)

    try:
        if norm_cipher == "AES-256-GCM":
            cipher_obj = AESGCM(bytes(key))
        else:
            cipher_obj = ChaCha20Poly1305(bytes(key))

        plaintext = cipher_obj.decrypt(bytes(nonce), combined, aad)
        return plaintext
    except Exception as e:
        raise AEADDecryptionError(
            f"Decryption / integrity authentication failed: ciphertext or tag has been tampered with ({str(e)})"
        ) from e


def list_supported_aead_ciphers() -> List[dict]:
    """List metadata for supported AEAD ciphers."""
    return [
        {
            "cipher": "AES-256-GCM",
            "standard": "NIST SP 800-38D",
            "key_bytes": 32,
            "nonce_bytes": 12,
            "tag_bytes": 16,
            "description": "Galois/Counter Mode with 256-bit AES key",
        },
        {
            "cipher": "ChaCha20-Poly1305",
            "standard": "RFC 8439",
            "key_bytes": 32,
            "nonce_bytes": 12,
            "tag_bytes": 16,
            "description": "ChaCha20 stream cipher with Poly1305 authenticator",
        },
    ]
