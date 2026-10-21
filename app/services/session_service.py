"""Session management service for Post-Quantum cryptographic sessions."""

from enum import Enum
from typing import Dict, Optional, Set
import os
import time
import uuid
import threading

from app.config import settings
from app.crypto.kem import get_kem_provider, KEMError
from app.crypto.kdf import derive_session_keys, KDFError
from app.crypto.aead import encrypt_aead, decrypt_aead, AEADError, _normalize_cipher_name


class SessionState(str, Enum):
    """Lifecycle states for a PQC session."""
    INITIALIZED = "INITIALIZED"      # Keypair generated, awaiting client encapsulation
    ESTABLISHED = "ESTABLISHED"      # Shared secret established and keys derived
    TERMINATED = "TERMINATED"        # Explicitly terminated by either party
    EXPIRED = "EXPIRED"              # Inactive past TTL


class SessionError(Exception):
    """Base session exception."""
    pass


class SessionNotFoundError(SessionError):
    """Raised when session ID does not exist."""
    pass


class SessionStateError(SessionError):
    """Raised when operation is invalid for current session state."""
    pass


def _zeroize(b: Optional[bytearray]):
    """Overwrite memory buffer with zeros."""
    if b is not None and isinstance(b, bytearray):
        for i in range(len(b)):
            b[i] = 0


class SessionRecord:
    """Internal session state and key storage container."""

    def __init__(
        self,
        session_id: str,
        algorithm: str,
        cipher: str,
        ttl_seconds: int,
        public_key: bytes,
        private_key: bytes,
    ):
        self.session_id: str = session_id
        self.algorithm: str = algorithm
        self.cipher: str = _normalize_cipher_name(cipher)
        self.created_at: float = time.time()
        self.ttl_seconds: int = ttl_seconds
        self.expires_at: float = self.created_at + ttl_seconds
        self.state: SessionState = SessionState.INITIALIZED

        # Keys (stored as mutable bytearrays to permit secure zeroization)
        self.public_key: bytes = bytes(public_key)
        self._private_key: Optional[bytearray] = bytearray(private_key)
        self._encryption_key: Optional[bytearray] = None
        self.confirmation_tag: Optional[bytes] = None
        self.salt: Optional[bytes] = None

        # Metrics and replay protection
        self.messages_encrypted: int = 0
        self.messages_decrypted: int = 0
        self.seen_nonces: Set[bytes] = set()

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def zeroize_private_key(self):
        """Zero out private decapsulation key immediately after handshake."""
        if self._private_key is not None:
            _zeroize(self._private_key)
            self._private_key = None

    def zeroize_all(self):
        """Zero out all sensitive symmetric and asymmetric key material."""
        self.zeroize_private_key()
        if self._encryption_key is not None:
            _zeroize(self._encryption_key)
            self._encryption_key = None
        self.confirmation_tag = None
        self.state = SessionState.TERMINATED

    @property
    def private_key_bytes(self) -> bytes:
        if self._private_key is None:
            raise SessionStateError("Private key has already been wiped for forward secrecy")
        return bytes(self._private_key)

    @property
    def encryption_key_bytes(self) -> bytes:
        if self._encryption_key is None:
            raise SessionStateError("Session is not yet established or encryption key has been wiped")
        return bytes(self._encryption_key)

    def set_established(self, encryption_key: bytes, confirmation_tag: bytes, salt: bytes):
        self._encryption_key = bytearray(encryption_key)
        self.confirmation_tag = bytes(confirmation_tag)
        self.salt = bytes(salt)
        self.state = SessionState.ESTABLISHED
        # Enforce forward secrecy by discarding server private decapsulation key
        self.zeroize_private_key()


class SessionService:
    """Thread-safe cryptographic session lifecycle manager."""

    def __init__(self):
        self._sessions: Dict[str, SessionRecord] = {}
        self._lock = threading.RLock()

    def init_session(
        self,
        algorithm: Optional[str] = None,
        cipher: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
    ) -> Dict:
        """Initialize a new cryptographic session and generate KEM keypair.

        Args:
            algorithm: KEM algorithm name (defaults to settings.DEFAULT_KEM_ALGORITHM).
            cipher: Symmetric AEAD cipher name (defaults to settings.DEFAULT_AEAD_CIPHER).
            ttl_seconds: Lifetime in seconds (defaults to settings.SESSION_TTL_SECONDS).

        Returns:
            Dictionary containing session_id, public_key, algorithm, cipher, and expiry metadata.
        """
        algo_name = algorithm or settings.DEFAULT_KEM_ALGORITHM
        cipher_name = cipher or settings.DEFAULT_AEAD_CIPHER
        ttl = ttl_seconds or settings.SESSION_TTL_SECONDS

        kem = get_kem_provider(algo_name)
        public_key, private_key = kem.keygen()
        session_id = str(uuid.uuid4())

        with self._lock:
            # Self-cleanup if session count gets high
            if len(self._sessions) >= settings.MAX_ACTIVE_SESSIONS:
                self.cleanup_expired_sessions()
                if len(self._sessions) >= settings.MAX_ACTIVE_SESSIONS:
                    raise SessionError("Maximum active session capacity reached")

            record = SessionRecord(
                session_id=session_id,
                algorithm=kem.algorithm_name,
                cipher=cipher_name,
                ttl_seconds=ttl,
                public_key=public_key,
                private_key=private_key,
            )
            self._sessions[session_id] = record

        return {
            "session_id": session_id,
            "algorithm": kem.algorithm_name,
            "cipher": record.cipher,
            "public_key": public_key,
            "public_key_bytes": len(public_key),
            "state": record.state.value,
            "created_at": record.created_at,
            "expires_at": record.expires_at,
            "ttl_seconds": ttl,
            "is_quantum_resistant": kem.is_quantum_resistant,
        }

    def complete_handshake(
        self,
        session_id: str,
        ciphertext: bytes,
        salt: Optional[bytes] = None,
    ) -> Dict:
        """Process client encapsulation ciphertext to establish session key via HKDF.

        Args:
            session_id: Target session identifier.
            ciphertext: KEM ciphertext encapsulated by client.
            salt: Optional KDF salt. If None, service derives with a fresh 32-byte salt.

        Returns:
            Handshake confirmation dictionary with session state and confirmation tag.
        """
        with self._lock:
            record = self._get_active_record(session_id)
            if record.state != SessionState.INITIALIZED:
                raise SessionStateError(
                    f"Session {session_id} is in state '{record.state.value}', expected 'INITIALIZED'"
                )

            kem = get_kem_provider(record.algorithm)
            sk = record.private_key_bytes
            shared_secret = kem.decapsulate(sk, ciphertext)

            derived = derive_session_keys(
                shared_secret=shared_secret,
                salt=salt,
                session_id=session_id,
                context="pqc-lab-handshake",
                key_length=32,
            )

            record.set_established(
                encryption_key=derived["encryption_key"],
                confirmation_tag=derived["confirmation_tag"],
                salt=derived["salt"],
            )

            return {
                "session_id": session_id,
                "state": record.state.value,
                "algorithm": record.algorithm,
                "cipher": record.cipher,
                "confirmation_tag": record.confirmation_tag,
                "salt": record.salt,
                "established_at": time.time(),
            }

    def encrypt_message(
        self,
        session_id: str,
        plaintext: bytes,
        associated_data: Optional[bytes] = None,
    ) -> Dict:
        """Encrypt message with established session symmetric key.

        Args:
            session_id: Active established session ID.
            plaintext: Plaintext bytes.
            associated_data: Optional associated data for authentication.

        Returns:
            Dictionary with ciphertext, nonce, tag, sequence_number.
        """
        with self._lock:
            record = self._get_active_record(session_id)
            if record.state != SessionState.ESTABLISHED:
                raise SessionStateError(
                    f"Session {session_id} is in state '{record.state.value}', expected 'ESTABLISHED'"
                )

            key = record.encryption_key_bytes
            res = encrypt_aead(
                key=key,
                plaintext=plaintext,
                associated_data=associated_data,
                cipher_name=record.cipher,
            )

            record.messages_encrypted += 1
            record.seen_nonces.add(res["nonce"])

            return {
                "session_id": session_id,
                "ciphertext": res["ciphertext"],
                "nonce": res["nonce"],
                "tag": res["tag"],
                "cipher": record.cipher,
                "sequence_number": record.messages_encrypted,
            }

    def decrypt_message(
        self,
        session_id: str,
        ciphertext: bytes,
        nonce: bytes,
        tag: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """Decrypt message using established session symmetric key.

        Args:
            session_id: Active established session ID.
            ciphertext: Encrypted payload bytes.
            nonce: 12-byte nonce.
            tag: 16-byte authentication tag.
            associated_data: Optional associated data.

        Returns:
            Plaintext bytes.
        """
        with self._lock:
            record = self._get_active_record(session_id)
            if record.state != SessionState.ESTABLISHED:
                raise SessionStateError(
                    f"Session {session_id} is in state '{record.state.value}', expected 'ESTABLISHED'"
                )

            key = record.encryption_key_bytes
            plaintext = decrypt_aead(
                key=key,
                ciphertext=ciphertext,
                nonce=nonce,
                tag=tag,
                associated_data=associated_data,
                cipher_name=record.cipher,
            )

            record.messages_decrypted += 1
            record.seen_nonces.add(nonce)

            return plaintext

    def get_session_status(self, session_id: str) -> Dict:
        """Get public status metadata for a session."""
        with self._lock:
            record = self._get_record(session_id)
            if record.is_expired() and record.state != SessionState.TERMINATED:
                record.zeroize_all()
                record.state = SessionState.EXPIRED

            return {
                "session_id": record.session_id,
                "state": record.state.value,
                "algorithm": record.algorithm,
                "cipher": record.cipher,
                "created_at": record.created_at,
                "expires_at": record.expires_at,
                "is_expired": record.is_expired(),
                "messages_encrypted": record.messages_encrypted,
                "messages_decrypted": record.messages_decrypted,
                "public_key_bytes": len(record.public_key),
            }

    def terminate_session(self, session_id: str) -> bool:
        """Explicitly terminate and securely wipe all session key material."""
        with self._lock:
            record = self._sessions.get(session_id)
            if not record:
                return False
            record.zeroize_all()
            return True

    def cleanup_expired_sessions(self) -> int:
        """Sweep and zero out expired sessions."""
        cleaned = 0
        now = time.time()
        with self._lock:
            expired_ids = [
                sid for sid, rec in self._sessions.items()
                if rec.expires_at < now or rec.state == SessionState.TERMINATED
            ]
            for sid in expired_ids:
                self._sessions[sid].zeroize_all()
                del self._sessions[sid]
                cleaned += 1
        return cleaned

    def _get_record(self, session_id: str) -> SessionRecord:
        record = self._sessions.get(session_id)
        if not record:
            raise SessionNotFoundError(f"Session '{session_id}' not found")
        return record

    def _get_active_record(self, session_id: str) -> SessionRecord:
        record = self._get_record(session_id)
        if record.is_expired():
            record.zeroize_all()
            record.state = SessionState.EXPIRED
            raise SessionStateError(f"Session '{session_id}' has expired")
        if record.state == SessionState.TERMINATED:
            raise SessionStateError(f"Session '{session_id}' has been terminated")
        return record


# Global singleton instance
session_service = SessionService()
