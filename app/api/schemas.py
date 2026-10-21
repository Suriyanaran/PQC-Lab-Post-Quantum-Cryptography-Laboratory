"""Pydantic schemas and serialization models for the REST API."""

from typing import List, Optional
from pydantic import BaseModel, Field, field_validator


class AlgorithmInfo(BaseModel):
    """Metadata describing a cryptographic algorithm."""
    algorithm: str
    standard: str
    security_level: int
    is_quantum_resistant: bool
    public_key_bytes: int
    private_key_bytes: int
    ciphertext_bytes: int
    shared_secret_bytes: int


class AEADCipherInfo(BaseModel):
    """Metadata describing a symmetric AEAD cipher."""
    cipher: str
    standard: str
    key_bytes: int
    nonce_bytes: int
    tag_bytes: int
    description: str


class AlgorithmsResponse(BaseModel):
    """List of all cryptographic primitives supported by the laboratory."""
    kem_algorithms: List[AlgorithmInfo]
    aead_ciphers: List[AEADCipherInfo]
    kdf_algorithms: List[str]


# ---------------------------------------------------------------------------
# Direct KEM Primitives Schemas (Keygen, Encapsulate, Decapsulate)
# ---------------------------------------------------------------------------

class KEMKeygenRequest(BaseModel):
    """Request to generate standalone KEM keypair."""
    algorithm: str = Field(default="ML-KEM-768", description="KEM Algorithm: ML-KEM-512, ML-KEM-768, ML-KEM-1024, or X25519")


class KEMKeygenResponse(BaseModel):
    """Generated standalone KEM keypair."""
    algorithm: str
    public_key_hex: str
    private_key_hex: str
    public_key_bytes: int
    private_key_bytes: int


class KEMEncapsulateRequest(BaseModel):
    """Request to encapsulate a shared secret against recipient's public key."""
    algorithm: str = Field(default="ML-KEM-768", description="Target KEM algorithm")
    public_key_hex: str = Field(..., description="Recipient encapsulation key (hex-encoded)")

    @field_validator("public_key_hex")
    @classmethod
    def validate_hex(cls, v: str) -> str:
        clean = v.strip()
        try:
            bytes.fromhex(clean)
        except ValueError:
            raise ValueError("public_key_hex must be a valid hex-encoded string")
        return clean


class KEMEncapsulateResponse(BaseModel):
    """Encapsulation result containing shared secret and ciphertext."""
    algorithm: str
    shared_secret_hex: str
    ciphertext_hex: str
    shared_secret_bytes: int
    ciphertext_bytes: int


class KEMDecapsulateRequest(BaseModel):
    """Request to decapsulate shared secret using recipient's private key."""
    algorithm: str = Field(default="ML-KEM-768", description="Target KEM algorithm")
    private_key_hex: str = Field(..., description="Recipient decapsulation key (hex-encoded)")
    ciphertext_hex: str = Field(..., description="Encapsulated ciphertext (hex-encoded)")

    @field_validator("private_key_hex", "ciphertext_hex")
    @classmethod
    def validate_hex(cls, v: str) -> str:
        clean = v.strip()
        try:
            bytes.fromhex(clean)
        except ValueError:
            raise ValueError("Field must be a valid hex-encoded string")
        return clean


class KEMDecapsulateResponse(BaseModel):
    """Decapsulation result containing recovered shared secret."""
    algorithm: str
    shared_secret_hex: str
    shared_secret_bytes: int


# ---------------------------------------------------------------------------
# Session & Message Schemas
# ---------------------------------------------------------------------------

class SessionInitRequest(BaseModel):
    """Request to start an active end-to-end cryptographic session."""
    algorithm: Optional[str] = Field(default="ML-KEM-768", description="KEM Algorithm")
    cipher: Optional[str] = Field(default="AES-256-GCM", description="Symmetric AEAD cipher")
    ttl_seconds: Optional[int] = Field(default=3600, ge=60, le=86400, description="Session TTL in seconds")


class SessionInitResponse(BaseModel):
    """Server keypair and session initialization response."""
    session_id: str
    algorithm: str
    cipher: str
    public_key_hex: str
    public_key_bytes: int
    state: str
    created_at: float
    expires_at: float
    ttl_seconds: int
    is_quantum_resistant: bool


class SessionHandshakeRequest(BaseModel):
    """Handshake request with client encapsulated ciphertext."""
    ciphertext_hex: str = Field(..., description="Client-generated ciphertext (hex-encoded)")
    salt_hex: Optional[str] = Field(default=None, description="Optional hex-encoded salt for KDF")

    @field_validator("ciphertext_hex")
    @classmethod
    def validate_ct(cls, v: str) -> str:
        clean = v.strip()
        try:
            bytes.fromhex(clean)
        except ValueError:
            raise ValueError("ciphertext_hex must be valid hex")
        return clean

    @field_validator("salt_hex")
    @classmethod
    def validate_salt(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        clean = v.strip()
        try:
            bytes.fromhex(clean)
        except ValueError:
            raise ValueError("salt_hex must be valid hex")
        return clean


class SessionHandshakeResponse(BaseModel):
    """Handshake response confirming session key establishment."""
    session_id: str
    state: str
    algorithm: str
    cipher: str
    confirmation_tag_hex: str
    salt_hex: str
    established_at: float


class EncryptMessageRequest(BaseModel):
    """Request to encrypt message using active session key."""
    plaintext: Optional[str] = Field(default=None, description="UTF-8 plaintext string to encrypt")
    plaintext_hex: Optional[str] = Field(default=None, description="Optional raw plaintext bytes (hex-encoded)")
    associated_data: Optional[str] = Field(default=None, description="Optional unencrypted authenticated header string")

    @field_validator("plaintext_hex")
    @classmethod
    def validate_pt_hex(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        clean = v.strip()
        try:
            bytes.fromhex(clean)
        except ValueError:
            raise ValueError("plaintext_hex must be valid hex")
        return clean


class EncryptMessageResponse(BaseModel):
    """Result of AEAD encryption."""
    session_id: str
    ciphertext_hex: str
    nonce_hex: str
    tag_hex: str
    cipher: str
    sequence_number: int


class DecryptMessageRequest(BaseModel):
    """Request to decrypt ciphertext using active session key."""
    ciphertext_hex: str = Field(..., description="Ciphertext bytes (hex-encoded)")
    nonce_hex: str = Field(..., description="12-byte Nonce (hex-encoded)")
    tag_hex: str = Field(..., description="16-byte Authentication Tag (hex-encoded)")
    associated_data: Optional[str] = Field(default=None, description="Associated data matching encryption")

    @field_validator("ciphertext_hex", "nonce_hex", "tag_hex")
    @classmethod
    def validate_hex_fields(cls, v: str) -> str:
        clean = v.strip()
        try:
            bytes.fromhex(clean)
        except ValueError:
            raise ValueError("Field must be valid hex")
        return clean


class DecryptMessageResponse(BaseModel):
    """Result of AEAD decryption and authentication."""
    session_id: str
    plaintext: str
    plaintext_hex: str


class SessionStatusResponse(BaseModel):
    """Public telemetry and status of an active or expired session."""
    session_id: str
    state: str
    algorithm: str
    cipher: str
    created_at: float
    expires_at: float
    is_expired: bool
    messages_encrypted: int
    messages_decrypted: int
    public_key_bytes: int


class MessageResponse(BaseModel):
    """Generic status or notification message."""
    message: str
    status: str
