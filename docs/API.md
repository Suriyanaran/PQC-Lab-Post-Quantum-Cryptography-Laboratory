# PQC-Lab REST API Specification

## 1. Overview

PQC-Lab provides a standardized REST API for Post-Quantum Cryptography experimentation, benchmarking, and application integration.

- **Base URL**: `http://127.0.0.1:8000`
- **Interactive OpenAPI Documentation**: `http://127.0.0.1:8000/docs`
- **ReDoc Technical Specification**: `http://127.0.0.1:8000/redoc`
- **Encoding Standard**: All cryptographic keys, nonces, tags, and ciphertexts are transmitted as **hexadecimal strings**.

---

## 2. Core Endpoints

### 2.1 Service Health
`GET /health`

**Response (200 OK):**
```json
{
  "status": "healthy",
  "service": "PQC-Lab: Post-Quantum Cryptography Laboratory",
  "version": "1.0.0",
  "timestamp": 1729520000.0,
  "default_kem": "ML-KEM-768",
  "default_aead": "AES-256-GCM"
}
```

---

### 2.2 List Supported Algorithms
`GET /api/v1/algorithms`

Returns metadata for all available KEM algorithms, AEAD ciphers, and KDF options.

**Example Request:**
```bash
curl -X GET http://127.0.0.1:8000/api/v1/algorithms
```

**Response (200 OK):**
```json
{
  "kem_algorithms": [
    {
      "algorithm": "ML-KEM-512",
      "standard": "NIST FIPS 203",
      "security_level": 1,
      "is_quantum_resistant": true,
      "public_key_bytes": 800,
      "private_key_bytes": 1632,
      "ciphertext_bytes": 768,
      "shared_secret_bytes": 32
    },
    {
      "algorithm": "ML-KEM-768",
      "standard": "NIST FIPS 203",
      "security_level": 3,
      "is_quantum_resistant": true,
      "public_key_bytes": 1184,
      "private_key_bytes": 2400,
      "ciphertext_bytes": 1088,
      "shared_secret_bytes": 32
    },
    {
      "algorithm": "ML-KEM-1024",
      "standard": "NIST FIPS 203",
      "security_level": 5,
      "is_quantum_resistant": true,
      "public_key_bytes": 1568,
      "private_key_bytes": 3168,
      "ciphertext_bytes": 1568,
      "shared_secret_bytes": 32
    },
    {
      "algorithm": "X25519",
      "standard": "RFC 7748 (Classical Baseline)",
      "security_level": 128,
      "is_quantum_resistant": false,
      "public_key_bytes": 32,
      "private_key_bytes": 32,
      "ciphertext_bytes": 32,
      "shared_secret_bytes": 32
    }
  ],
  "aead_ciphers": [
    {
      "cipher": "AES-256-GCM",
      "standard": "NIST SP 800-38D",
      "key_bytes": 32,
      "nonce_bytes": 12,
      "tag_bytes": 16,
      "description": "Galois/Counter Mode with 256-bit AES key"
    },
    {
      "cipher": "ChaCha20-Poly1305",
      "standard": "RFC 8439",
      "key_bytes": 32,
      "nonce_bytes": 12,
      "tag_bytes": 16,
      "description": "ChaCha20 stream cipher with Poly1305 authenticator"
    }
  ],
  "kdf_algorithms": ["SHA256", "SHA384", "SHA512"]
}
```

---

## 3. Direct Stateless KEM Primitives

### 3.1 Generate KEM Keypair
`POST /api/v1/kem/keygen`

**Request Body:**
```json
{
  "algorithm": "ML-KEM-768"
}
```

**Response (200 OK):**
```json
{
  "algorithm": "ML-KEM-768",
  "public_key_hex": "4a2b91...",
  "private_key_hex": "e1f98c...",
  "public_key_bytes": 1184,
  "private_key_bytes": 2400
}
```

---

### 3.2 Encapsulate Shared Secret
`POST /api/v1/kem/encapsulate`

**Request Body:**
```json
{
  "algorithm": "ML-KEM-768",
  "public_key_hex": "<1184-byte hex public key>"
}
```

**Response (200 OK):**
```json
{
  "algorithm": "ML-KEM-768",
  "shared_secret_hex": "d8e34a...32bytes...",
  "ciphertext_hex": "91a2fc...1088bytes...",
  "shared_secret_bytes": 32,
  "ciphertext_bytes": 1088
}
```

---

### 3.3 Decapsulate Shared Secret
`POST /api/v1/kem/decapsulate`

**Request Body:**
```json
{
  "algorithm": "ML-KEM-768",
  "private_key_hex": "<2400-byte hex private key>",
  "ciphertext_hex": "<1088-byte hex ciphertext>"
}
```

**Response (200 OK):**
```json
{
  "algorithm": "ML-KEM-768",
  "shared_secret_hex": "d8e34a...32bytes...",
  "shared_secret_bytes": 32
}
```

---

## 4. End-to-End Cryptographic Sessions

### 4.1 Initialize Session
`POST /api/v1/session/init`

Generates server KEM keypair and assigns an active session identifier.

**Request Body:**
```json
{
  "algorithm": "ML-KEM-768",
  "cipher": "AES-256-GCM",
  "ttl_seconds": 3600
}
```

**Response (200 OK):**
```json
{
  "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "algorithm": "ML-KEM-768",
  "cipher": "AES-256-GCM",
  "public_key_hex": "<1184-byte hex>",
  "public_key_bytes": 1184,
  "state": "INITIALIZED",
  "created_at": 1729521000.0,
  "expires_at": 1729524600.0,
  "ttl_seconds": 3600,
  "is_quantum_resistant": true
}
```

---

### 4.2 Complete Handshake
`POST /api/v1/session/{session_id}/handshake`

Client sends encapsulated ciphertext. Server decapsulates, derives symmetric session key, and wipes private key.

**Request Body:**
```json
{
  "ciphertext_hex": "<1088-byte hex ciphertext>",
  "salt_hex": null
}
```

**Response (200 OK):**
```json
{
  "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "state": "ESTABLISHED",
  "algorithm": "ML-KEM-768",
  "cipher": "AES-256-GCM",
  "confirmation_tag_hex": "<16-byte hex tag>",
  "salt_hex": "<32-byte hex salt>",
  "established_at": 1729521010.0
}
```

---

### 4.3 Encrypt Message
`POST /api/v1/session/{session_id}/encrypt`

**Request Body:**
```json
{
  "plaintext": "Top Secret Quantum Transmission",
  "associated_data": "header-v1:channel-alpha"
}
```

**Response (200 OK):**
```json
{
  "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "ciphertext_hex": "4a9e81...",
  "nonce_hex": "0102030405060708090a0b0c",
  "tag_hex": "9f1e8a23...",
  "cipher": "AES-256-GCM",
  "sequence_number": 1
}
```

---

### 4.4 Decrypt Message
`POST /api/v1/session/{session_id}/decrypt`

**Request Body:**
```json
{
  "ciphertext_hex": "4a9e81...",
  "nonce_hex": "0102030405060708090a0b0c",
  "tag_hex": "9f1e8a23...",
  "associated_data": "header-v1:channel-alpha"
}
```

**Response (200 OK):**
```json
{
  "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "plaintext": "Top Secret Quantum Transmission",
  "plaintext_hex": "546f7020536563726574205175616e74756d205472616e736d697373696f6e"
}
```

---

### 4.5 Inspect Session Status
`GET /api/v1/session/{session_id}/status`

**Response (200 OK):**
```json
{
  "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "state": "ESTABLISHED",
  "algorithm": "ML-KEM-768",
  "cipher": "AES-256-GCM",
  "created_at": 1729521000.0,
  "expires_at": 1729524600.0,
  "is_expired": false,
  "messages_encrypted": 1,
  "messages_decrypted": 1,
  "public_key_bytes": 1184
}
```

---

### 4.6 Terminate Session
`DELETE /api/v1/session/{session_id}`

**Response (200 OK):**
```json
{
  "message": "Session '3fa85f64-5717-4562-b3fc-2c963f66afa6' terminated successfully. All key material zeroized.",
  "status": "TERMINATED"
}
```
