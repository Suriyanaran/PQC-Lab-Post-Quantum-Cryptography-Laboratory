"""Unit tests for Key Encapsulation Mechanism (KEM) implementations."""

import pytest
from app.crypto.kem import (
    get_kem_provider,
    list_supported_kem_algorithms,
    KEMError,
    KEMKeyError,
    KEMDecapsulationError,
)


@pytest.mark.parametrize(
    "algo,expected_pk_len,expected_sk_len,expected_ct_len,expected_ss_len,is_pqc",
    [
        ("ML-KEM-512", 800, 1632, 768, 32, True),
        ("ML-KEM-768", 1184, 2400, 1088, 32, True),
        ("ML-KEM-1024", 1568, 3168, 1568, 32, True),
        ("X25519", 32, 32, 32, 32, False),
    ],
)
def test_kem_roundtrip_and_lengths(
    algo, expected_pk_len, expected_sk_len, expected_ct_len, expected_ss_len, is_pqc
):
    """Verify keygen, encaps, decaps roundtrip and exact NIST byte lengths."""
    kem = get_kem_provider(algo)

    assert kem.public_key_size == expected_pk_len
    assert kem.private_key_size == expected_sk_len
    assert kem.ciphertext_size == expected_ct_len
    assert kem.shared_secret_size == expected_ss_len
    assert kem.is_quantum_resistant == is_pqc

    # Key generation
    pk, sk = kem.keygen()
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)
    assert len(pk) == expected_pk_len
    assert len(sk) == expected_sk_len

    # Encapsulation
    ss_client, ct = kem.encapsulate(pk)
    assert isinstance(ss_client, bytes)
    assert isinstance(ct, bytes)
    assert len(ss_client) == expected_ss_len
    assert len(ct) == expected_ct_len

    # Decapsulation
    ss_server = kem.decapsulate(sk, ct)
    assert isinstance(ss_server, bytes)
    assert len(ss_server) == expected_ss_len

    # Shared secrets must match exactly
    assert ss_client == ss_server


def test_kem_keygen_randomness():
    """Verify consecutive keygens produce distinct keypairs."""
    kem = get_kem_provider("ML-KEM-768")
    pk1, sk1 = kem.keygen()
    pk2, sk2 = kem.keygen()
    assert pk1 != pk2
    assert sk1 != sk2


def test_kem_algorithm_aliases():
    """Verify alias normalization (case-insensitive and common short names)."""
    p1 = get_kem_provider("ml-kem-768")
    p2 = get_kem_provider("MLKEM768")
    p3 = get_kem_provider("kyber768")
    assert p1.algorithm_name == "ML-KEM-768"
    assert p2.algorithm_name == "ML-KEM-768"
    assert p3.algorithm_name == "ML-KEM-768"

    p_classic = get_kem_provider("curve25519")
    assert p_classic.algorithm_name == "X25519"


def test_kem_unsupported_algorithm():
    """Verify requesting an unsupported algorithm raises KEMError."""
    with pytest.raises(KEMError, match="Unsupported algorithm"):
        get_kem_provider("RSA-2048-NOT-KEM")


def test_kem_list_metadata():
    """Verify algorithm listing metadata schema."""
    algos = list_supported_kem_algorithms()
    assert len(algos) >= 4
    names = [a["algorithm"] for a in algos]
    assert "ML-KEM-512" in names
    assert "ML-KEM-768" in names
    assert "ML-KEM-1024" in names
    assert "X25519" in names
