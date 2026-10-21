"""Unit tests for Authenticated Encryption with Associated Data (AEAD)."""

import pytest
import os

from app.crypto.aead import (
    encrypt_aead,
    decrypt_aead,
    AEADError,
    AEADKeyError,
    AEADNonceError,
    AEADDecryptionError,
    list_supported_aead_ciphers,
)


@pytest.mark.parametrize("cipher", ["AES-256-GCM", "ChaCha20-Poly1305"])
def test_aead_roundtrip_with_aad(cipher):
    """Verify encrypt and decrypt roundtrip with Associated Data."""
    key = os.urandom(32)
    plaintext = b"Quantum computer attacks cannot break this symmetric envelope!"
    aad = b"header-v1:sender-alice:recipient-bob"

    res = encrypt_aead(key=key, plaintext=plaintext, associated_data=aad, cipher_name=cipher)
    assert len(res["nonce"]) == 12
    assert len(res["tag"]) == 16
    assert len(res["ciphertext"]) == len(plaintext)

    decrypted = decrypt_aead(
        key=key,
        ciphertext=res["ciphertext"],
        nonce=res["nonce"],
        tag=res["tag"],
        associated_data=aad,
        cipher_name=cipher,
    )
    assert decrypted == plaintext


@pytest.mark.parametrize("cipher", ["AES-256-GCM", "ChaCha20-Poly1305"])
def test_aead_roundtrip_without_aad(cipher):
    """Verify encrypt and decrypt roundtrip without Associated Data."""
    key = os.urandom(32)
    plaintext = b"Payload without unencrypted header"

    res = encrypt_aead(key=key, plaintext=plaintext, cipher_name=cipher)
    decrypted = decrypt_aead(
        key=key,
        ciphertext=res["ciphertext"],
        nonce=res["nonce"],
        tag=res["tag"],
        cipher_name=cipher,
    )
    assert decrypted == plaintext


@pytest.mark.parametrize("cipher", ["AES-256-GCM", "ChaCha20-Poly1305"])
def test_aead_empty_plaintext(cipher):
    """Verify encryption and authentication of zero-length plaintext."""
    key = os.urandom(32)
    plaintext = b""
    aad = b"authenticated-empty-command"

    res = encrypt_aead(key=key, plaintext=plaintext, associated_data=aad, cipher_name=cipher)
    assert len(res["ciphertext"]) == 0
    assert len(res["tag"]) == 16

    decrypted = decrypt_aead(
        key=key,
        ciphertext=res["ciphertext"],
        nonce=res["nonce"],
        tag=res["tag"],
        associated_data=aad,
        cipher_name=cipher,
    )
    assert decrypted == b""


def test_aead_custom_nonce():
    """Verify providing an explicit 12-byte nonce."""
    key = os.urandom(32)
    custom_nonce = b"\x01" * 12
    plaintext = b"Testing custom nonce injection"

    res = encrypt_aead(key=key, plaintext=plaintext, nonce=custom_nonce)
    assert res["nonce"] == custom_nonce


def test_aead_key_length_validation():
    """Verify invalid key lengths raise AEADKeyError."""
    with pytest.raises(AEADKeyError, match="exactly 32 bytes"):
        encrypt_aead(key=b"too-short-16byte", plaintext=b"hello")

    with pytest.raises(AEADKeyError, match="exactly 32 bytes"):
        decrypt_aead(key=b"too-short-16byte", ciphertext=b"abc", nonce=b"1"*12, tag=b"1"*16)


def test_aead_nonce_length_validation():
    """Verify invalid nonce length raises AEADNonceError."""
    key = os.urandom(32)
    with pytest.raises(AEADNonceError, match="exactly 12 bytes"):
        encrypt_aead(key=key, plaintext=b"hello", nonce=b"bad_nonce_len")


def test_aead_tag_length_validation():
    """Verify invalid tag length raises AEADDecryptionError."""
    key = os.urandom(32)
    with pytest.raises(AEADDecryptionError, match="exactly 16 bytes"):
        decrypt_aead(key=key, ciphertext=b"abc", nonce=b"1"*12, tag=b"short_tag")


def test_aead_unsupported_cipher():
    """Verify unsupported cipher names raise AEADError."""
    key = os.urandom(32)
    with pytest.raises(AEADError, match="Unsupported AEAD cipher"):
        encrypt_aead(key=key, plaintext=b"hello", cipher_name="DES-CBC")


def test_list_supported_aead_ciphers():
    """Verify AEAD metadata list."""
    ciphers = list_supported_aead_ciphers()
    assert len(ciphers) >= 2
    names = [c["cipher"] for c in ciphers]
    assert "AES-256-GCM" in names
    assert "ChaCha20-Poly1305" in names
