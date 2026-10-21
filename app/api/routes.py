"""REST API routes for PQC-Lab cryptographic operations and session management."""

from typing import Optional
from fastapi import APIRouter, HTTPException, status

from app.api.schemas import (
    AlgorithmsResponse,
    AlgorithmInfo,
    AEADCipherInfo,
    KEMKeygenRequest,
    KEMKeygenResponse,
    KEMEncapsulateRequest,
    KEMEncapsulateResponse,
    KEMDecapsulateRequest,
    KEMDecapsulateResponse,
    SessionInitRequest,
    SessionInitResponse,
    SessionHandshakeRequest,
    SessionHandshakeResponse,
    EncryptMessageRequest,
    EncryptMessageResponse,
    DecryptMessageRequest,
    DecryptMessageResponse,
    SessionStatusResponse,
    MessageResponse,
)
from app.crypto.kem import (
    get_kem_provider,
    list_supported_kem_algorithms,
    KEMError,
)
from app.crypto.aead import list_supported_aead_ciphers, AEADError, AEADDecryptionError
from app.crypto.kdf import KDFError
from app.services.session_service import (
    session_service,
    SessionNotFoundError,
    SessionStateError,
    SessionError,
)

router = APIRouter(prefix="/api/v1", tags=["PQC Cryptography"])


@router.get("/algorithms", response_model=AlgorithmsResponse)
def get_algorithms():
    """Retrieve all supported Post-Quantum KEM algorithms, AEAD ciphers, and KDF options."""
    kem_list = [AlgorithmInfo(**m) for m in list_supported_kem_algorithms()]
    aead_list = [AEADCipherInfo(**m) for m in list_supported_aead_ciphers()]
    kdf_list = ["SHA256", "SHA384", "SHA512"]
    return AlgorithmsResponse(
        kem_algorithms=kem_list,
        aead_ciphers=aead_list,
        kdf_algorithms=kdf_list,
    )


# ---------------------------------------------------------------------------
# Direct KEM Primitives Endpoints
# ---------------------------------------------------------------------------

@router.post("/kem/keygen", response_model=KEMKeygenResponse)
def kem_keygen(req: KEMKeygenRequest):
    """Generate a standalone KEM keypair (public encapsulation key and private decapsulation key)."""
    try:
        kem = get_kem_provider(req.algorithm)
        pk, sk = kem.keygen()
        return KEMKeygenResponse(
            algorithm=kem.algorithm_name,
            public_key_hex=pk.hex(),
            private_key_hex=sk.hex(),
            public_key_bytes=len(pk),
            private_key_bytes=len(sk),
        )
    except KEMError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/kem/encapsulate", response_model=KEMEncapsulateResponse)
def kem_encapsulate(req: KEMEncapsulateRequest):
    """Encapsulate a shared secret against a recipient's public key."""
    try:
        kem = get_kem_provider(req.algorithm)
        pk_bytes = bytes.fromhex(req.public_key_hex)
        shared_secret, ciphertext = kem.encapsulate(pk_bytes)
        return KEMEncapsulateResponse(
            algorithm=kem.algorithm_name,
            shared_secret_hex=shared_secret.hex(),
            ciphertext_hex=ciphertext.hex(),
            shared_secret_bytes=len(shared_secret),
            ciphertext_bytes=len(ciphertext),
        )
    except (KEMError, ValueError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/kem/decapsulate", response_model=KEMDecapsulateResponse)
def kem_decapsulate(req: KEMDecapsulateRequest):
    """Decapsulate a shared secret using a recipient's private key and ciphertext."""
    try:
        kem = get_kem_provider(req.algorithm)
        sk_bytes = bytes.fromhex(req.private_key_hex)
        ct_bytes = bytes.fromhex(req.ciphertext_hex)
        shared_secret = kem.decapsulate(sk_bytes, ct_bytes)
        return KEMDecapsulateResponse(
            algorithm=kem.algorithm_name,
            shared_secret_hex=shared_secret.hex(),
            shared_secret_bytes=len(shared_secret),
        )
    except (KEMError, ValueError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# ---------------------------------------------------------------------------
# Stateful End-to-End Cryptographic Sessions
# ---------------------------------------------------------------------------

@router.post("/session/init", response_model=SessionInitResponse)
def session_init(req: SessionInitRequest):
    """Initialize a new cryptographic session and receive server encapsulation public key."""
    try:
        res = session_service.init_session(
            algorithm=req.algorithm,
            cipher=req.cipher,
            ttl_seconds=req.ttl_seconds,
        )
        return SessionInitResponse(
            session_id=res["session_id"],
            algorithm=res["algorithm"],
            cipher=res["cipher"],
            public_key_hex=res["public_key"].hex(),
            public_key_bytes=res["public_key_bytes"],
            state=res["state"],
            created_at=res["created_at"],
            expires_at=res["expires_at"],
            ttl_seconds=res["ttl_seconds"],
            is_quantum_resistant=res["is_quantum_resistant"],
        )
    except (KEMError, SessionError, ValueError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/session/{session_id}/handshake", response_model=SessionHandshakeResponse)
def session_handshake(session_id: str, req: SessionHandshakeRequest):
    """Complete session handshake by providing encapsulated ciphertext."""
    try:
        ct_bytes = bytes.fromhex(req.ciphertext_hex)
        salt_bytes = bytes.fromhex(req.salt_hex) if req.salt_hex else None
        res = session_service.complete_handshake(
            session_id=session_id,
            ciphertext=ct_bytes,
            salt=salt_bytes,
        )
        return SessionHandshakeResponse(
            session_id=res["session_id"],
            state=res["state"],
            algorithm=res["algorithm"],
            cipher=res["cipher"],
            confirmation_tag_hex=res["confirmation_tag"].hex(),
            salt_hex=res["salt"].hex(),
            established_at=res["established_at"],
        )
    except SessionNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except SessionStateError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except (KEMError, KDFError, ValueError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/session/{session_id}/encrypt", response_model=EncryptMessageResponse)
def session_encrypt(session_id: str, req: EncryptMessageRequest):
    """Encrypt message with established session key using authenticated AEAD."""
    try:
        if req.plaintext is not None:
            pt_bytes = req.plaintext.encode("utf-8")
        elif req.plaintext_hex is not None:
            pt_bytes = bytes.fromhex(req.plaintext_hex)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either 'plaintext' or 'plaintext_hex' must be provided",
            )

        aad_bytes = req.associated_data.encode("utf-8") if req.associated_data else None

        res = session_service.encrypt_message(
            session_id=session_id,
            plaintext=pt_bytes,
            associated_data=aad_bytes,
        )

        return EncryptMessageResponse(
            session_id=res["session_id"],
            ciphertext_hex=res["ciphertext"].hex(),
            nonce_hex=res["nonce"].hex(),
            tag_hex=res["tag"].hex(),
            cipher=res["cipher"],
            sequence_number=res["sequence_number"],
        )
    except SessionNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except SessionStateError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except (AEADError, ValueError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/session/{session_id}/decrypt", response_model=DecryptMessageResponse)
def session_decrypt(session_id: str, req: DecryptMessageRequest):
    """Decrypt message with established session key and verify integrity authentication tag."""
    try:
        ct_bytes = bytes.fromhex(req.ciphertext_hex)
        nonce_bytes = bytes.fromhex(req.nonce_hex)
        tag_bytes = bytes.fromhex(req.tag_hex)
        aad_bytes = req.associated_data.encode("utf-8") if req.associated_data else None

        pt_bytes = session_service.decrypt_message(
            session_id=session_id,
            ciphertext=ct_bytes,
            nonce=nonce_bytes,
            tag=tag_bytes,
            associated_data=aad_bytes,
        )

        # Attempt UTF-8 decoding, fallback to repr if binary
        try:
            pt_str = pt_bytes.decode("utf-8")
        except UnicodeDecodeError:
            pt_str = f"<binary:{len(pt_bytes)} bytes>"

        return DecryptMessageResponse(
            session_id=session_id,
            plaintext=pt_str,
            plaintext_hex=pt_bytes.hex(),
        )
    except SessionNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except SessionStateError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except AEADDecryptionError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except (AEADError, ValueError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/session/{session_id}/status", response_model=SessionStatusResponse)
def session_status(session_id: str):
    """Inspect status, state, and telemetry metrics for a given session."""
    try:
        res = session_service.get_session_status(session_id)
        return SessionStatusResponse(**res)
    except SessionNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.delete("/session/{session_id}", response_model=MessageResponse)
def session_terminate(session_id: str):
    """Explicitly terminate session and zeroize all cryptographic key material."""
    success = session_service.terminate_session(session_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Session '{session_id}' not found")
    return MessageResponse(
        message=f"Session '{session_id}' terminated successfully. All key material zeroized.",
        status="TERMINATED",
    )
