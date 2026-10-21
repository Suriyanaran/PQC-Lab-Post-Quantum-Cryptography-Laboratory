"""End-to-End integration tests for PQC-Lab cryptographic protocols."""

from fastapi.testclient import TestClient

from app.main import app
from app.crypto.kem import get_kem_provider
from app.crypto.kdf import derive_session_keys
from app.crypto.aead import decrypt_aead

client = TestClient(app)


def test_e2e_full_session_flow_mlkem768_aesgcm():
    """Complete multi-party session handshake and message exchange using ML-KEM-768 + AES-256-GCM."""
    # 1. Initialize session on server
    init_res = client.post(
        "/api/v1/session/init",
        json={"algorithm": "ML-KEM-768", "cipher": "AES-256-GCM", "ttl_seconds": 1800},
    )
    assert init_res.status_code == 200
    init_data = init_res.json()
    session_id = init_data["session_id"]
    server_pk_hex = init_data["public_key_hex"]
    assert init_data["state"] == "INITIALIZED"
    assert init_data["public_key_bytes"] == 1184
    assert init_data["is_quantum_resistant"] is True

    # 2. Client-side: encapsulate against server's public key
    client_kem = get_kem_provider("ML-KEM-768")
    server_pk = bytes.fromhex(server_pk_hex)
    client_shared_secret, ciphertext = client_kem.encapsulate(server_pk)

    # 3. Client transmits ciphertext to server to complete handshake
    handshake_res = client.post(
        f"/api/v1/session/{session_id}/handshake",
        json={"ciphertext_hex": ciphertext.hex()},
    )
    assert handshake_res.status_code == 200
    hs_data = handshake_res.json()
    assert hs_data["state"] == "ESTABLISHED"
    server_conf_tag = bytes.fromhex(hs_data["confirmation_tag_hex"])
    salt = bytes.fromhex(hs_data["salt_hex"])

    # 4. Client verifies mutual key confirmation tag
    client_derived = derive_session_keys(
        shared_secret=client_shared_secret,
        salt=salt,
        session_id=session_id,
        context="pqc-lab-handshake",
        key_length=32,
    )
    assert client_derived["confirmation_tag"] == server_conf_tag
    client_enc_key = client_derived["encryption_key"]

    # 5. Server-side encrypts payload
    secret_message = "Confidential Quantum-Safe Transmission: Mission Successful"
    associated_header = "auth-context:level-5:session-token"
    enc_res = client.post(
        f"/api/v1/session/{session_id}/encrypt",
        json={"plaintext": secret_message, "associated_data": associated_header},
    )
    assert enc_res.status_code == 200
    enc_data = enc_res.json()

    # 6. Verify client can decrypt the server-encrypted message locally
    client_decrypted = decrypt_aead(
        key=client_enc_key,
        ciphertext=bytes.fromhex(enc_data["ciphertext_hex"]),
        nonce=bytes.fromhex(enc_data["nonce_hex"]),
        tag=bytes.fromhex(enc_data["tag_hex"]),
        associated_data=associated_header.encode("utf-8"),
        cipher_name="AES-256-GCM",
    )
    assert client_decrypted.decode("utf-8") == secret_message

    # 7. Server decrypts its own message through endpoint
    dec_res = client.post(
        f"/api/v1/session/{session_id}/decrypt",
        json={
            "ciphertext_hex": enc_data["ciphertext_hex"],
            "nonce_hex": enc_data["nonce_hex"],
            "tag_hex": enc_data["tag_hex"],
            "associated_data": associated_header,
        },
    )
    assert dec_res.status_code == 200
    assert dec_res.json()["plaintext"] == secret_message

    # 8. Check session status
    status_res = client.get(f"/api/v1/session/{session_id}/status")
    assert status_res.status_code == 200
    st_data = status_res.json()
    assert st_data["state"] == "ESTABLISHED"
    assert st_data["messages_encrypted"] == 1
    assert st_data["messages_decrypted"] == 1

    # 9. Terminate session
    del_res = client.delete(f"/api/v1/session/{session_id}")
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "TERMINATED"


def test_e2e_direct_kem_endpoints_flow():
    """Verify stateless /kem/keygen -> /kem/encapsulate -> /kem/decapsulate endpoints."""
    # 1. Keygen
    kg_res = client.post("/api/v1/kem/keygen", json={"algorithm": "ML-KEM-1024"})
    assert kg_res.status_code == 200
    kg_data = kg_res.json()
    pk_hex = kg_data["public_key_hex"]
    sk_hex = kg_data["private_key_hex"]
    assert kg_data["public_key_bytes"] == 1568
    assert kg_data["private_key_bytes"] == 3168

    # 2. Encapsulate
    enc_res = client.post(
        "/api/v1/kem/encapsulate",
        json={"algorithm": "ML-KEM-1024", "public_key_hex": pk_hex},
    )
    assert enc_res.status_code == 200
    enc_data = enc_res.json()
    ss_client_hex = enc_data["shared_secret_hex"]
    ct_hex = enc_data["ciphertext_hex"]
    assert enc_data["ciphertext_bytes"] == 1568

    # 3. Decapsulate
    dec_res = client.post(
        "/api/v1/kem/decapsulate",
        json={
            "algorithm": "ML-KEM-1024",
            "private_key_hex": sk_hex,
            "ciphertext_hex": ct_hex,
        },
    )
    assert dec_res.status_code == 200
    dec_data = dec_res.json()
    ss_server_hex = dec_data["shared_secret_hex"]

    # Shared secrets must match
    assert ss_client_hex == ss_server_hex


def test_e2e_chacha20_flow():
    """Verify end-to-end session with ChaCha20-Poly1305 and ML-KEM-512."""
    init_res = client.post(
        "/api/v1/session/init",
        json={"algorithm": "ML-KEM-512", "cipher": "ChaCha20-Poly1305"},
    )
    assert init_res.status_code == 200
    sid = init_res.json()["session_id"]
    pk = bytes.fromhex(init_res.json()["public_key_hex"])

    kem = get_kem_provider("ML-KEM-512")
    _, ct = kem.encapsulate(pk)

    hs_res = client.post(
        f"/api/v1/session/{sid}/handshake",
        json={"ciphertext_hex": ct.hex()},
    )
    assert hs_res.status_code == 200
    assert hs_res.json()["cipher"] == "ChaCha20-Poly1305"

    enc_res = client.post(
        f"/api/v1/session/{sid}/encrypt",
        json={"plaintext": "ChaCha20 quantum payload"},
    )
    assert enc_res.status_code == 200
    enc = enc_res.json()

    dec_res = client.post(
        f"/api/v1/session/{sid}/decrypt",
        json={
            "ciphertext_hex": enc["ciphertext_hex"],
            "nonce_hex": enc["nonce_hex"],
            "tag_hex": enc["tag_hex"],
        },
    )
    assert dec_res.status_code == 200
    assert dec_res.json()["plaintext"] == "ChaCha20 quantum payload"
