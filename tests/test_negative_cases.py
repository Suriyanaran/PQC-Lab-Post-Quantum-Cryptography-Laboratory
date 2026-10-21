"""Negative security and adversarial test cases for PQC-Lab."""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.crypto.kem import get_kem_provider, KEMKeyError, KEMDecapsulationError
from app.crypto.aead import encrypt_aead, decrypt_aead, AEADDecryptionError
from app.services.session_service import session_service, SessionNotFoundError, SessionStateError

client = TestClient(app)


def test_tampered_ciphertext_rejection():
    """Verify modifying a single byte in ciphertext causes AEAD decryption failure."""
    init_res = client.post("/api/v1/session/init", json={"algorithm": "ML-KEM-768"})
    sid = init_res.json()["session_id"]
    pk = bytes.fromhex(init_res.json()["public_key_hex"])

    kem = get_kem_provider("ML-KEM-768")
    _, ct = kem.encapsulate(pk)
    client.post(f"/api/v1/session/{sid}/handshake", json={"ciphertext_hex": ct.hex()})

    # Encrypt
    enc_res = client.post(
        f"/api/v1/session/{sid}/encrypt",
        json={"plaintext": "Critical command: Transfer 1,000,000 Credits"},
    )
    enc = enc_res.json()

    # Tamper with ciphertext by flipping last byte
    ct_bytes = bytearray(bytes.fromhex(enc["ciphertext_hex"]))
    ct_bytes[-1] ^= 0x01  # Flip one bit
    tampered_ct_hex = ct_bytes.hex()

    # Attempt decrypt tampered ciphertext
    dec_res = client.post(
        f"/api/v1/session/{sid}/decrypt",
        json={
            "ciphertext_hex": tampered_ct_hex,
            "nonce_hex": enc["nonce_hex"],
            "tag_hex": enc["tag_hex"],
        },
    )
    assert dec_res.status_code == 400
    assert "integrity authentication failed" in dec_res.json()["detail"].lower()


def test_tampered_authentication_tag_rejection():
    """Verify modifying the authentication tag causes decryption failure."""
    init_res = client.post("/api/v1/session/init", json={"algorithm": "ML-KEM-768"})
    sid = init_res.json()["session_id"]
    pk = bytes.fromhex(init_res.json()["public_key_hex"])

    kem = get_kem_provider("ML-KEM-768")
    _, ct = kem.encapsulate(pk)
    client.post(f"/api/v1/session/{sid}/handshake", json={"ciphertext_hex": ct.hex()})

    enc_res = client.post(f"/api/v1/session/{sid}/encrypt", json={"plaintext": "Secret"})
    enc = enc_res.json()

    # Tamper with authentication tag
    tag_bytes = bytearray(bytes.fromhex(enc["tag_hex"]))
    tag_bytes[0] ^= 0xFF
    tampered_tag_hex = tag_bytes.hex()

    dec_res = client.post(
        f"/api/v1/session/{sid}/decrypt",
        json={
            "ciphertext_hex": enc["ciphertext_hex"],
            "nonce_hex": enc["nonce_hex"],
            "tag_hex": tampered_tag_hex,
        },
    )
    assert dec_res.status_code == 400


def test_associated_data_mismatch_rejection():
    """Verify changing or omitting unencrypted associated data breaks authentication."""
    init_res = client.post("/api/v1/session/init", json={"algorithm": "ML-KEM-768"})
    sid = init_res.json()["session_id"]
    pk = bytes.fromhex(init_res.json()["public_key_hex"])

    kem = get_kem_provider("ML-KEM-768")
    _, ct = kem.encapsulate(pk)
    client.post(f"/api/v1/session/{sid}/handshake", json={"ciphertext_hex": ct.hex()})

    # Encrypt with AAD
    enc_res = client.post(
        f"/api/v1/session/{sid}/encrypt",
        json={"plaintext": "Data", "associated_data": "header-valid"},
    )
    enc = enc_res.json()

    # 1. Attempt decrypt with different AAD
    dec_diff_aad = client.post(
        f"/api/v1/session/{sid}/decrypt",
        json={
            "ciphertext_hex": enc["ciphertext_hex"],
            "nonce_hex": enc["nonce_hex"],
            "tag_hex": enc["tag_hex"],
            "associated_data": "header-tampered-by-adversary",
        },
    )
    assert dec_diff_aad.status_code == 400

    # 2. Attempt decrypt without AAD
    dec_no_aad = client.post(
        f"/api/v1/session/{sid}/decrypt",
        json={
            "ciphertext_hex": enc["ciphertext_hex"],
            "nonce_hex": enc["nonce_hex"],
            "tag_hex": enc["tag_hex"],
        },
    )
    assert dec_no_aad.status_code == 400


def test_malformed_or_truncated_kem_keys():
    """Verify truncated public key or ciphertext returns HTTP 400."""
    # Truncated public key (only 16 bytes instead of 1184)
    short_pk_hex = "00" * 16
    enc_res = client.post(
        "/api/v1/kem/encapsulate",
        json={"algorithm": "ML-KEM-768", "public_key_hex": short_pk_hex},
    )
    assert enc_res.status_code == 400
    assert "invalid public key length" in enc_res.json()["detail"].lower()

    # Truncated ciphertext
    short_ct_hex = "ff" * 10
    dummy_sk_hex = "aa" * 2400
    dec_res = client.post(
        "/api/v1/kem/decapsulate",
        json={
            "algorithm": "ML-KEM-768",
            "private_key_hex": dummy_sk_hex,
            "ciphertext_hex": short_ct_hex,
        },
    )
    assert dec_res.status_code == 400


def test_session_state_machine_violations():
    """Verify state machine invariants: cannot double-handshake, encrypt before handshake, etc."""
    # 1. Initialize session
    init_res = client.post("/api/v1/session/init", json={"algorithm": "ML-KEM-768"})
    sid = init_res.json()["session_id"]
    pk = bytes.fromhex(init_res.json()["public_key_hex"])

    # 2. Attempting to encrypt before completing handshake should return HTTP 409
    premature_enc = client.post(
        f"/api/v1/session/{sid}/encrypt",
        json={"plaintext": "Should fail before handshake"},
    )
    assert premature_enc.status_code == 409

    # 3. Complete handshake
    kem = get_kem_provider("ML-KEM-768")
    _, ct = kem.encapsulate(pk)
    hs1 = client.post(f"/api/v1/session/{sid}/handshake", json={"ciphertext_hex": ct.hex()})
    assert hs1.status_code == 200

    # 4. Attempting duplicate handshake on already established session should return HTTP 409
    hs2 = client.post(f"/api/v1/session/{sid}/handshake", json={"ciphertext_hex": ct.hex()})
    assert hs2.status_code == 409
    assert "expected 'initialized'" in hs2.json()["detail"].lower()

    # 5. Terminate session
    term = client.delete(f"/api/v1/session/{sid}")
    assert term.status_code == 200

    # 6. Attempting to encrypt on terminated session should return HTTP 409
    post_term_enc = client.post(
        f"/api/v1/session/{sid}/encrypt",
        json={"plaintext": "Should fail after termination"},
    )
    assert post_term_enc.status_code == 409


def test_nonexistent_session_not_found():
    """Verify 404 is returned when referencing non-existent session UUID."""
    fake_id = "00000000-0000-0000-0000-000000000000"
    res = client.get(f"/api/v1/session/{fake_id}/status")
    assert res.status_code == 404

    res2 = client.post(
        f"/api/v1/session/{fake_id}/handshake",
        json={"ciphertext_hex": "00" * 1088},
    )
    assert res2.status_code == 404


def test_invalid_hex_string_validation():
    """Verify malformed hex strings trigger validation error."""
    res = client.post(
        "/api/v1/kem/encapsulate",
        json={"algorithm": "ML-KEM-768", "public_key_hex": "not-valid-hex-zzz"},
    )
    assert res.status_code == 422
