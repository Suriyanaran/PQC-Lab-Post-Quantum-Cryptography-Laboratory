"""Cryptographic primitives package: KEM, KDF, and AEAD."""

from app.crypto.kem import (
    KEMProvider,
    get_kem_provider,
    list_supported_kem_algorithms,
    KEMError,
)
from app.crypto.kdf import (
    derive_key,
    derive_session_keys,
    KDFError,
)
from app.crypto.aead import (
    encrypt_aead,
    decrypt_aead,
    AEADError,
)

__all__ = [
    "KEMProvider",
    "get_kem_provider",
    "list_supported_kem_algorithms",
    "KEMError",
    "derive_key",
    "derive_session_keys",
    "KDFError",
    "encrypt_aead",
    "decrypt_aead",
    "AEADError",
]
