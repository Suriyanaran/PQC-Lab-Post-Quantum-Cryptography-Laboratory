
# PQC-Lab: Post-Quantum Cryptography Integration & Testing Laboratory

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![NIST FIPS 203](https://img.shields.io/badge/NIST-FIPS%20203%20ML--KEM-blueviolet)](https://csrc.nist.gov/pubs/fips/203/final)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**PQC-Lab** is a developer-focused reference laboratory for integrating,
testing, and benchmarking Post-Quantum Cryptography in modern applications.

It demonstrates a practical cryptographic stack using **ML-KEM** as defined in
NIST FIPS 203, **HKDF** key derivation per RFC 5869, and authenticated
encryption using **AES-256-GCM** or **ChaCha20-Poly1305**.

> **Scope:** This is an engineering prototype and integration/testing toolkit.
> It is not a certified cryptographic module, formal security audit, or
> production-ready security guarantee.

## 🌟 Key Features

- **NIST FIPS 203 Compliant**: Full implementation of `ML-KEM-512` (Cat 1), `ML-KEM-768` (Cat 3 - Recommended), and `ML-KEM-1024` (Cat 5).
- **Classical Baseline Comparison**: Integrated `X25519` (RFC 7748) ECDH-as-KEM provider for empirical benchmarking.
- **Robust Key Derivation**: RFC 5869 HKDF Extract-and-Expand with strict domain separation between encryption keys and confirmation tags.
- **High-Throughput Authenticated Ciphers**: `AES-256-GCM` (NIST SP 800-38D) and `ChaCha20-Poly1305` (RFC 8439) with Authenticated Associated Data (AAD).
- **Stateful Cryptographic Sessions**: Thread-safe session management with automated memory zeroization to enforce **Forward Secrecy**.
- **Interactive Web Dashboard**: Sleek, glassmorphic UI served on `GET /` to run live key exchanges, inspect wire overhead, and visualize cryptographic envelopes.
- **Automated Benchmarking Suite**: Measures keygen, encapsulation, and decapsulation latency, operations per second, and AEAD throughput across payload sizes.
- **Extensive Test Coverage**: 45 unit, end-to-end integration, and adversarial negative tests covering bit-flip tampering, key truncations, and replay attacks.

---

## 📁 Project Structure

```text
pqc-lab/
├── app/
│   ├── __init__.py                  # Application package initialization
│   ├── main.py                      # FastAPI application entry & interactive dashboard
│   ├── config.py                    # Environment and cryptographic settings
│   ├── crypto/
│   │   ├── __init__.py              # Cryptographic primitives exports
│   │   ├── kem.py                   # NIST FIPS 203 ML-KEM & X25519 KEM providers
│   │   ├── kdf.py                   # RFC 5869 HKDF extract/expand & session derivation
│   │   └── aead.py                  # AES-256-GCM & ChaCha20-Poly1305 AEAD engines
│   ├── api/
│   │   ├── __init__.py              # REST API package initialization
│   │   ├── routes.py                # REST endpoints for KEM and session operations
│   │   └── schemas.py               # Pydantic schemas and hex validation models
│   └── services/
│       ├── __init__.py              # Service package initialization
│       └── session_service.py       # Thread-safe session lifecycle & memory zeroization
├── tests/
│   ├── __init__.py                  # Test package initialization
│   ├── test_kem.py                  # Unit tests for ML-KEM and X25519 algorithms
│   ├── test_kdf.py                  # Unit tests for HKDF key expansion and domain separation
│   ├── test_aead.py                 # Unit tests for AEAD encryption and AAD verification
│   ├── test_end_to_end.py           # Multi-party integration tests for full handshake
│   └── test_negative_cases.py       # Adversarial tests (tampering, replay, truncations)
├── benchmarks/
│   └── run_benchmarks.py            # High-precision benchmark runner
├── docs/
│   ├── ARCHITECTURE.md              # Technical design, modules, and sequence diagrams
│   ├── SECURITY.md                  # Threat model, Shor/Grover analysis, and memory safety
│   ├── API.md                       # Comprehensive REST API specifications and curl examples
│   └── BENCHMARK_REPORT.md          # Empirical benchmark numbers and transition guidance
├── requirements.txt                 # Project dependencies
├── .gitignore                       # Git ignore configuration
└── README.md                        # Project documentation
```

---

## 🚀 Quick Start

### 1. Installation

Ensure you have Python 3.12+ installed.

```bash
# Clone the repository
git clone https://github.com/your-org/pqc-lab.git
cd pqc-lab

# Install dependencies
pip install -r requirements.txt
```

### 2. Run the Application Server

```bash
python -m app.main
```

The server starts locally at `http://127.0.0.1:8000`:
- **Interactive Web Dashboard**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Interactive Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc Technical Specification**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
- **Health Check**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

---

## 🧪 Running Tests

Execute the complete test suite with pytest:

```bash
pytest -v
```

All **45 tests** run and pass in under 1 second:
- `test_kem.py`: Algorithm parameter sizes, keygen randomness, alias normalizations.
- `test_kdf.py`: Determinism, domain separation, hash algorithms (SHA256, SHA384, SHA512).
- `test_aead.py`: AES-256-GCM and ChaCha20-Poly1305 roundtrips, custom nonces, empty plaintexts.
- `test_end_to_end.py`: Multi-party handshake, key confirmation verification, local client-side decryption.
- `test_negative_cases.py`: Bit-flip ciphertext tampering, tag modification, AAD mismatches, truncated keys, and state machine violations.

---

## 📊 Running Benchmarks

Measure latency, operations per second, and AEAD throughput:

```bash
python benchmarks/run_benchmarks.py --iterations 30
```

### Empirical Summary:

```text
=================================================================================================
 POST-QUANTUM & CLASSICAL KEM BENCHMARK RESULTS
=================================================================================================
Algorithm      | PQC?  | PK (B)  | CT (B)  | Keygen (ms) | Encaps (ms) | Decaps (ms) | Total (ms)
-------------------------------------------------------------------------------------------------
ML-KEM-512     | YES   | 800     | 768     | 1.472       | 2.217       | 3.265       | 6.954     
ML-KEM-768     | YES   | 1184    | 1088    | 2.657       | 3.404       | 4.639       | 10.700    
ML-KEM-1024    | YES   | 1568    | 1568    | 3.904       | 4.994       | 6.506       | 15.405    
X25519         | NO    | 32      | 32      | 0.032       | 0.062       | 0.073       | 0.166     
-------------------------------------------------------------------------------------------------
```

Detailed analysis and transition recommendations are available in [docs/BENCHMARK_REPORT.md](docs/BENCHMARK_REPORT.md).

---

## 📡 REST API Examples

### 1. Initialize a Quantum-Safe Session
```bash
curl -X POST http://127.0.0.1:8000/api/v1/session/init \
  -H "Content-Type: application/json" \
  -d '{"algorithm": "ML-KEM-768", "cipher": "AES-256-GCM"}'
```

### 2. Complete Handshake
```bash
curl -X POST http://127.0.0.1:8000/api/v1/session/<SESSION_ID>/handshake \
  -H "Content-Type: application/json" \
  -d '{"ciphertext_hex": "<CIPHERTEXT_HEX>"}'
```

### 3. Encrypt Payload
```bash
curl -X POST http://127.0.0.1:8000/api/v1/session/<SESSION_ID>/encrypt \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "Top Secret Quantum Transmission", "associated_data": "header-v1"}'
```

### 4. Decrypt Payload
```bash
curl -X POST http://127.0.0.1:8000/api/v1/session/<SESSION_ID>/decrypt \
  -H "Content-Type: application/json" \
  -d '{"ciphertext_hex": "<CT_HEX>", "nonce_hex": "<NONCE_HEX>", "tag_hex": "<TAG_HEX>", "associated_data": "header-v1"}'
```

Full API specifications are available in [docs/API.md](docs/API.md).

---

## 📚 Technical Documentation

- [Architecture & Design Details](docs/ARCHITECTURE.md)
- [Security Threat Model & Cryptanalysis](docs/SECURITY.md)
- [REST API Specifications](docs/API.md)
- [Benchmark & Transition Report](docs/BENCHMARK_REPORT.md)

## Commercial Use

PQC-Lab can be used as:

- A developer integration starter kit.
- A PQC evaluation and benchmarking environment.
- A reference implementation for quantum-safe session establishment.
- A foundation for custom PQC integration pilots.

Available offerings:

| Offering | Description |
|---|---|
| Developer Kit | Source code, tests, benchmark suite, and integration documentation |
| Integration Pilot | Time-boxed PQC proof-of-concept for an existing application |
| Technical Consultation | Architecture review and PQC migration guidance |

For pilot or integration enquiries, contact: [suriyanarayananpalani@gmail.com]---

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
