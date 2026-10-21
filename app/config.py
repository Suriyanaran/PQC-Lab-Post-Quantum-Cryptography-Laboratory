"""Configuration settings for PQC-Lab."""

from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration settings."""

    # Application Metadata
    APP_TITLE: str = "PQC-Lab: Post-Quantum Cryptography Laboratory"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = (
        "Enterprise-grade Post-Quantum Cryptography experimentation suite featuring "
        "NIST FIPS 203 ML-KEM, HKDF key derivation, and authenticated AEAD ciphers."
    )
    DEBUG: bool = False

    # Server Settings
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # Cryptography Defaults
    DEFAULT_KEM_ALGORITHM: str = "ML-KEM-768"
    SUPPORTED_KEM_ALGORITHMS: List[str] = [
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
        "X25519",  # Classical baseline
    ]

    DEFAULT_AEAD_CIPHER: str = "AES-256-GCM"
    SUPPORTED_AEAD_CIPHERS: List[str] = [
        "AES-256-GCM",
        "ChaCha20-Poly1305",
    ]

    # Key Derivation Parameters
    KDF_SALT_LENGTH: int = 32
    KDF_DEFAULT_INFO: bytes = b"pqc-lab-session-key-derivation-v1"
    KDF_HASH_ALGORITHM: str = "SHA256"

    # Session Management
    SESSION_TTL_SECONDS: int = 3600  # 1 hour default
    MAX_ACTIVE_SESSIONS: int = 5000

    model_config = SettingsConfigDict(
        env_prefix="PQC_",
        env_file=".env",
        extra="ignore",
    )


settings = Settings()
