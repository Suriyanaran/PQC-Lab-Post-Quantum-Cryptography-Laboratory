"""Key Derivation Functions (KDF) using RFC 5869 HKDF."""

from typing import Dict, Optional
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class KDFError(Exception):
    """Exception raised when key derivation fails."""
    pass


_HASH_MAP = {
    "SHA256": hashes.SHA256(),
    "SHA-256": hashes.SHA256(),
    "SHA384": hashes.SHA384(),
    "SHA-384": hashes.SHA384(),
    "SHA512": hashes.SHA512(),
    "SHA-512": hashes.SHA512(),
}


def derive_key(
    secret: bytes,
    salt: Optional[bytes] = None,
    info: bytes = b"pqc-lab-default-kdf-v1",
    length: int = 32,
    algorithm: str = "SHA256",
) -> bytes:
    """Derive cryptographic key material from a shared secret using HKDF (RFC 5869).

    Args:
        secret: High-entropy or encapsulated input key material (IKM).
        salt: Optional non-secret random salt. If None, a zero-filled salt is used per RFC 5869.
        info: Optional context and application specific information.
        length: Number of bytes to output.
        algorithm: Hash algorithm ('SHA256', 'SHA384', 'SHA512').

    Returns:
        Derived key bytes of specified length.

    Raises:
        KDFError: If inputs are invalid or derivation fails.
    """
    if not isinstance(secret, (bytes, bytearray)):
        raise KDFError("Secret key material must be bytes")
    if len(secret) == 0:
        raise KDFError("Secret key material cannot be empty")
    if length <= 0:
        raise KDFError("Derived key length must be strictly positive")

    algo_norm = algorithm.strip().upper()
    hash_algorithm = _HASH_MAP.get(algo_norm)
    if hash_algorithm is None:
        valid_algos = ", ".join(sorted(_HASH_MAP.keys()))
        raise KDFError(f"Unsupported KDF hash algorithm '{algorithm}'. Supported: {valid_algos}")

    max_len = 255 * hash_algorithm.digest_size
    if length > max_len:
        raise KDFError(f"Requested key length {length} exceeds maximum possible {max_len} bytes")

    try:
        hkdf = HKDF(
            algorithm=hash_algorithm,
            length=length,
            salt=bytes(salt) if salt is not None else None,
            info=bytes(info),
        )
        return hkdf.derive(bytes(secret))
    except Exception as e:
        raise KDFError(f"HKDF derivation failed: {str(e)}") from e


def derive_session_keys(
    shared_secret: bytes,
    salt: Optional[bytes] = None,
    session_id: str = "",
    context: str = "pqc-secure-channel",
    key_length: int = 32,
    algorithm: str = "SHA256",
) -> Dict[str, bytes]:
    """Derive distinct cryptographically independent session keys from shared secret.

    Derives:
    1. 'encryption_key': Primary symmetric key for AEAD cipher (e.g. AES-256-GCM).
    2. 'confirmation_tag': Key confirmation tag for verifying mutual handshake completion.
    3. 'salt': The salt used during derivation.

    Args:
        shared_secret: Shared secret produced by KEM decapsulation.
        salt: Salt value (if None, a cryptographically secure 32-byte salt is generated).
        session_id: Identifier of the session for domain separation.
        context: Context label for domain separation.
        key_length: Desired length for the encryption key (default: 32 bytes).
        algorithm: Hash algorithm for HKDF.

    Returns:
        Dictionary containing 'encryption_key', 'confirmation_tag', and 'salt'.
    """
    if salt is None:
        salt = os.urandom(32)

    session_bytes = session_id.encode("utf-8") if isinstance(session_id, str) else bytes(session_id)
    context_bytes = context.encode("utf-8") if isinstance(context, str) else bytes(context)

    # Derive separate keys using context domain separation in info parameter
    enc_info = b"enc:" + context_bytes + b":" + session_bytes
    conf_info = b"confirm:" + context_bytes + b":" + session_bytes

    enc_key = derive_key(
        secret=shared_secret,
        salt=salt,
        info=enc_info,
        length=key_length,
        algorithm=algorithm,
    )
    confirm_tag = derive_key(
        secret=shared_secret,
        salt=salt,
        info=conf_info,
        length=16,
        algorithm=algorithm,
    )

    return {
        "encryption_key": enc_key,
        "confirmation_tag": confirm_tag,
        "salt": salt,
    }
