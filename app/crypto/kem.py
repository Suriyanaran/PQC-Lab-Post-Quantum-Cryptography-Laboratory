"""Key Encapsulation Mechanism (KEM) implementations.

Supports:
- NIST FIPS 203 ML-KEM (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
- Classical baseline: X25519 (ECDH-based KEM)
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, Type
import os

from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization


class KEMError(Exception):
    """Base exception for KEM operations."""
    pass


class KEMKeyError(KEMError):
    """Raised when keys are malformed or invalid length."""
    pass


class KEMDecapsulationError(KEMError):
    """Raised when decapsulation fails or ciphertext is malformed."""
    pass


class KEMProvider(ABC):
    """Abstract base class for Key Encapsulation Mechanism providers."""

    @property
    @abstractmethod
    def algorithm_name(self) -> str:
        """Standardized algorithm identifier."""
        pass

    @property
    @abstractmethod
    def standard(self) -> str:
        """Standardization authority/reference (e.g., NIST FIPS 203, RFC 7748)."""
        pass

    @property
    @abstractmethod
    def security_level(self) -> int:
        """NIST Security Category (1, 3, 5) or equivalent bits of classical security."""
        pass

    @property
    @abstractmethod
    def is_quantum_resistant(self) -> bool:
        """True if algorithm is resistant to cryptanalytic quantum attacks."""
        pass

    @property
    @abstractmethod
    def public_key_size(self) -> int:
        """Encapsulation key byte size."""
        pass

    @property
    @abstractmethod
    def private_key_size(self) -> int:
        """Decapsulation key byte size."""
        pass

    @property
    @abstractmethod
    def ciphertext_size(self) -> int:
        """Ciphertext byte size."""
        pass

    @property
    @abstractmethod
    def shared_secret_size(self) -> int:
        """Shared secret byte size."""
        pass

    @abstractmethod
    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate an encapsulation key (public key) and decapsulation key (private key).

        Returns:
            Tuple of (public_key_bytes, private_key_bytes)
        """
        pass

    @abstractmethod
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret against recipient's public key.

        Args:
            public_key: Recipient's encapsulation key.

        Returns:
            Tuple of (shared_secret_bytes, ciphertext_bytes)
        """
        pass

    @abstractmethod
    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate the shared secret using recipient's private key.

        Args:
            private_key: Recipient's decapsulation key.
            ciphertext: Encapsulated ciphertext from sender.

        Returns:
            Shared secret bytes.
        """
        pass

    def metadata(self) -> dict:
        """Return standardized algorithm metadata dictionary."""
        return {
            "algorithm": self.algorithm_name,
            "standard": self.standard,
            "security_level": self.security_level,
            "is_quantum_resistant": self.is_quantum_resistant,
            "public_key_bytes": self.public_key_size,
            "private_key_bytes": self.private_key_size,
            "ciphertext_bytes": self.ciphertext_size,
            "shared_secret_bytes": self.shared_secret_size,
        }


class BaseMLKEMProvider(KEMProvider):
    """Generic provider for NIST FIPS 203 ML-KEM algorithms."""

    def __init__(
        self,
        name: str,
        security_level: int,
        pk_size: int,
        sk_size: int,
        ct_size: int,
        ml_kem_backend,
    ):
        self._name = name
        self._security_level = security_level
        self._pk_size = pk_size
        self._sk_size = sk_size
        self._ct_size = ct_size
        self._backend = ml_kem_backend

    @property
    def algorithm_name(self) -> str:
        return self._name

    @property
    def standard(self) -> str:
        return "NIST FIPS 203"

    @property
    def security_level(self) -> int:
        return self._security_level

    @property
    def is_quantum_resistant(self) -> bool:
        return True

    @property
    def public_key_size(self) -> int:
        return self._pk_size

    @property
    def private_key_size(self) -> int:
        return self._sk_size

    @property
    def ciphertext_size(self) -> int:
        return self._ct_size

    @property
    def shared_secret_size(self) -> int:
        return 32

    def keygen(self) -> Tuple[bytes, bytes]:
        try:
            ek, dk = self._backend.keygen()
            return ek, dk
        except Exception as e:
            raise KEMKeyError(f"Key generation failed for {self._name}: {str(e)}") from e

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        if not isinstance(public_key, (bytes, bytearray)):
            raise KEMKeyError("Public key must be bytes")
        if len(public_key) != self._pk_size:
            raise KEMKeyError(
                f"Invalid public key length for {self._name}: "
                f"expected {self._pk_size} bytes, got {len(public_key)}"
            )
        try:
            shared_secret, ciphertext = self._backend.encaps(bytes(public_key))
            return shared_secret, ciphertext
        except Exception as e:
            raise KEMError(f"Encapsulation failed for {self._name}: {str(e)}") from e

    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        if not isinstance(private_key, (bytes, bytearray)):
            raise KEMKeyError("Private key must be bytes")
        if len(private_key) != self._sk_size:
            raise KEMKeyError(
                f"Invalid private key length for {self._name}: "
                f"expected {self._sk_size} bytes, got {len(private_key)}"
            )
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise KEMDecapsulationError("Ciphertext must be bytes")
        if len(ciphertext) != self._ct_size:
            raise KEMDecapsulationError(
                f"Invalid ciphertext length for {self._name}: "
                f"expected {self._ct_size} bytes, got {len(ciphertext)}"
            )
        try:
            shared_secret = self._backend.decaps(bytes(private_key), bytes(ciphertext))
            return shared_secret
        except Exception as e:
            raise KEMDecapsulationError(
                f"Decapsulation failed for {self._name}: {str(e)}"
            ) from e


class MLKEM512Provider(BaseMLKEMProvider):
    """NIST FIPS 203 ML-KEM-512 (Category 1, AES-128 equivalent)."""

    def __init__(self):
        super().__init__(
            name="ML-KEM-512",
            security_level=1,
            pk_size=800,
            sk_size=1632,
            ct_size=768,
            ml_kem_backend=ML_KEM_512,
        )


class MLKEM768Provider(BaseMLKEMProvider):
    """NIST FIPS 203 ML-KEM-768 (Category 3, AES-192 equivalent - Recommended Default)."""

    def __init__(self):
        super().__init__(
            name="ML-KEM-768",
            security_level=3,
            pk_size=1184,
            sk_size=2400,
            ct_size=1088,
            ml_kem_backend=ML_KEM_768,
        )


class MLKEM1024Provider(BaseMLKEMProvider):
    """NIST FIPS 203 ML-KEM-1024 (Category 5, AES-256 equivalent)."""

    def __init__(self):
        super().__init__(
            name="ML-KEM-1024",
            security_level=5,
            pk_size=1568,
            sk_size=3168,
            ct_size=1568,
            ml_kem_backend=ML_KEM_1024,
        )


class X25519KEMProvider(KEMProvider):
    """Classical baseline: Ephemeral-Static Diffie-Hellman KEM using Curve25519 (RFC 7748)."""

    @property
    def algorithm_name(self) -> str:
        return "X25519"

    @property
    def standard(self) -> str:
        return "RFC 7748 (Classical Baseline)"

    @property
    def security_level(self) -> int:
        return 128  # ~128 bits classical security

    @property
    def is_quantum_resistant(self) -> bool:
        return False

    @property
    def public_key_size(self) -> int:
        return 32

    @property
    def private_key_size(self) -> int:
        return 32

    @property
    def ciphertext_size(self) -> int:
        return 32

    @property
    def shared_secret_size(self) -> int:
        return 32

    def keygen(self) -> Tuple[bytes, bytes]:
        sk = x25519.X25519PrivateKey.generate()
        pk = sk.public_key()
        raw_pk = pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        raw_sk = sk.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        return raw_pk, raw_sk

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        if not isinstance(public_key, (bytes, bytearray)):
            raise KEMKeyError("Public key must be bytes")
        if len(public_key) != 32:
            raise KEMKeyError(f"Invalid public key length for X25519: expected 32 bytes, got {len(public_key)}")

        try:
            peer_pubkey = x25519.X25519PublicKey.from_public_bytes(bytes(public_key))
            ephemeral_sk = x25519.X25519PrivateKey.generate()
            ephemeral_pk = ephemeral_sk.public_key()
            ciphertext = ephemeral_pk.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            shared_secret = ephemeral_sk.exchange(peer_pubkey)
            return shared_secret, ciphertext
        except Exception as e:
            raise KEMError(f"Encapsulation failed for X25519: {str(e)}") from e

    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        if not isinstance(private_key, (bytes, bytearray)):
            raise KEMKeyError("Private key must be bytes")
        if len(private_key) != 32:
            raise KEMKeyError(f"Invalid private key length for X25519: expected 32 bytes, got {len(private_key)}")
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise KEMDecapsulationError("Ciphertext must be bytes")
        if len(ciphertext) != 32:
            raise KEMDecapsulationError(f"Invalid ciphertext length for X25519: expected 32 bytes, got {len(ciphertext)}")

        try:
            recipient_sk = x25519.X25519PrivateKey.from_private_bytes(bytes(private_key))
            ephemeral_pk = x25519.X25519PublicKey.from_public_bytes(bytes(ciphertext))
            shared_secret = recipient_sk.exchange(ephemeral_pk)
            return shared_secret
        except Exception as e:
            raise KEMDecapsulationError(f"Decapsulation failed for X25519: {str(e)}") from e


_PROVIDERS: Dict[str, Type[KEMProvider]] = {
    "ML-KEM-512": MLKEM512Provider,
    "ML-KEM-768": MLKEM768Provider,
    "ML-KEM-1024": MLKEM1024Provider,
    "X25519": X25519KEMProvider,
}


def get_kem_provider(algorithm_name: str) -> KEMProvider:
    """Retrieve an instantiated KEM provider by algorithm name.

    Args:
        algorithm_name: Name of algorithm (e.g., 'ML-KEM-768', 'X25519'). Case-insensitive.

    Raises:
        KEMError: If algorithm is unsupported.
    """
    normalized = algorithm_name.strip().upper()
    # Normalize variations like 'MLKEM768' -> 'ML-KEM-768'
    alias_map = {
        "MLKEM512": "ML-KEM-512",
        "MLKEM768": "ML-KEM-768",
        "MLKEM1024": "ML-KEM-1024",
        "KYBER512": "ML-KEM-512",
        "KYBER768": "ML-KEM-768",
        "KYBER1024": "ML-KEM-1024",
        "CURVE25519": "X25519",
    }
    normalized = alias_map.get(normalized, normalized)

    provider_cls = _PROVIDERS.get(normalized)
    if not provider_cls:
        valid_options = ", ".join(_PROVIDERS.keys())
        raise KEMError(f"Unsupported algorithm '{algorithm_name}'. Supported: {valid_options}")
    return provider_cls()


def list_supported_kem_algorithms() -> List[dict]:
    """List metadata for all supported KEM algorithms."""
    return [get_kem_provider(name).metadata() for name in _PROVIDERS.keys()]
