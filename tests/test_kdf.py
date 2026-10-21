"""Unit tests for Key Derivation Function (KDF) implementations."""

import pytest
import os
from app.crypto.kdf import derive_key, derive_session_keys, KDFError


def test_hkdf_deterministic():
    """Verify HKDF produces deterministic outputs for identical inputs."""
    secret = b"shared-secret-32-byte-length-01"
    salt = b"salt-12345678901234567890123456"
    info = b"test-context-v1"

    k1 = derive_key(secret, salt=salt, info=info, length=32, algorithm="SHA256")
    k2 = derive_key(secret, salt=salt, info=info, length=32, algorithm="SHA256")
    assert k1 == k2
    assert len(k1) == 32


def test_hkdf_domain_separation():
    """Verify distinct info contexts yield distinct cryptographically independent keys."""
    secret = os.urandom(32)
    salt = os.urandom(32)

    k_enc = derive_key(secret, salt=salt, info=b"encryption-key", length=32)
    k_mac = derive_key(secret, salt=salt, info=b"mac-key", length=32)

    assert k_enc != k_mac


def test_hkdf_salt_variation():
    """Verify different salts produce different keys."""
    secret = os.urandom(32)
    salt1 = b"salt-A"
    salt2 = b"salt-B"

    k1 = derive_key(secret, salt=salt1, length=32)
    k2 = derive_key(secret, salt=salt2, length=32)
    assert k1 != k2


@pytest.mark.parametrize("length", [16, 24, 32, 48, 64])
def test_hkdf_output_lengths(length):
    """Verify HKDF produces exact requested lengths."""
    secret = os.urandom(32)
    k = derive_key(secret, length=length)
    assert len(k) == length


@pytest.mark.parametrize("algo", ["SHA256", "SHA384", "SHA512"])
def test_hkdf_hash_algorithms(algo):
    """Verify support for SHA256, SHA384, and SHA512."""
    secret = os.urandom(32)
    k = derive_key(secret, length=32, algorithm=algo)
    assert len(k) == 32


def test_derive_session_keys():
    """Verify session key derivation extracts encryption key, confirmation tag, and salt."""
    secret = os.urandom(32)
    salt = os.urandom(32)
    session_id = "test-session-12345"

    derived = derive_session_keys(
        shared_secret=secret,
        salt=salt,
        session_id=session_id,
        context="test-ctx",
        key_length=32,
    )

    assert "encryption_key" in derived
    assert "confirmation_tag" in derived
    assert "salt" in derived

    assert len(derived["encryption_key"]) == 32
    assert len(derived["confirmation_tag"]) == 16
    assert derived["salt"] == salt
    assert derived["encryption_key"] != derived["confirmation_tag"]


def test_hkdf_error_empty_secret():
    """Verify empty secret raises KDFError."""
    with pytest.raises(KDFError, match="cannot be empty"):
        derive_key(secret=b"", length=32)


def test_hkdf_error_invalid_length():
    """Verify non-positive length raises KDFError."""
    with pytest.raises(KDFError, match="strictly positive"):
        derive_key(secret=b"some-secret", length=0)


def test_hkdf_error_invalid_hash():
    """Verify unsupported hash algorithm raises KDFError."""
    with pytest.raises(KDFError, match="Unsupported KDF hash algorithm"):
        derive_key(secret=b"some-secret", algorithm="MD5")
