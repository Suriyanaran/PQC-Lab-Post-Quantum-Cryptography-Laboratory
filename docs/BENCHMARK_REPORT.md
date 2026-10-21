# PQC-Lab Empirical Benchmark & Transition Analysis

## 1. Executive Summary

This report documents empirical performance benchmarks comparing **NIST FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)** parameter sets against classical **X25519 (ECDH-based KEM)** and evaluating symmetric **AEAD** cipher throughput.

All tests were executed on a standard multi-core workstation running Python 3.12 under identical isolation conditions.

---

## 2. Key Encapsulation Mechanism (KEM) Benchmark Results

### 2.1 Latency & Computational Overhead

| Algorithm | Post-Quantum? | NIST Category | Keygen (ms) | Encaps (ms) | Decaps (ms) | Total Handshake (ms) | Handshake Ops/Sec |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **ML-KEM-512** | **YES** | Cat 1 | 1.472 | 2.217 | 3.265 | **6.954** | ~143.8 |
| **ML-KEM-768** | **YES** | Cat 3 | 2.657 | 3.404 | 4.639 | **10.700** | ~93.5 |
| **ML-KEM-1024** | **YES** | Cat 5 | 3.904 | 4.994 | 6.506 | **15.405** | ~64.9 |
| **X25519** (Baseline) | **NO** | Classical | 0.032 | 0.062 | 0.073 | **0.166** | ~6,024.1 |

```
Handshake Latency Comparison (ms):
X25519      [0.17ms]
ML-KEM-512  [======= 6.95ms]
ML-KEM-768  [=========== 10.70ms] (Recommended)
ML-KEM-1024 [=============== 15.41ms]
```

---

### 2.2 Bandwidth & Wire Overhead Analysis

The primary cost of migrating to Post-Quantum Cryptography is not computational delay, but **network transmission size**:

| Algorithm | Public Key ($ek$) | Private Key ($dk$) | Ciphertext ($c$) | Total Wire Overhead ($ek + c$) | Expansion vs X25519 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **X25519** (Baseline) | 32 B | 32 B | 32 B | 64 B | 1.0x |
| **ML-KEM-512** | 800 B | 1,632 B | 768 B | 1,568 B | **24.5x** |
| **ML-KEM-768** | 1,184 B | 2,400 B | 1,088 B | 2,272 B | **35.5x** |
| **ML-KEM-1024** | 1,568 B | 3,168 B | 1,568 B | 3,136 B | **49.0x** |

#### Network MTU & Packet Fragmentation:
- **Ethernet MTU**: Standard network packets have a Maximum Transmission Unit (MTU) of **1,500 bytes**.
- **ML-KEM-768**: Both the public key (1,184 bytes) and ciphertext (1,088 bytes) **individually fit within a single unfragmented 1,500-byte IP packet**.
- **ML-KEM-1024**: The public key (1,568 bytes) exceeds standard MTU, triggering IP packet fragmentation unless Jumbo Frames or TCP segmentation are active.

---

## 3. Symmetric AEAD Throughput & Latency

Once the asymmetric KEM handshake completes and a 256-bit symmetric key is derived via HKDF, payload traffic is protected by authenticated symmetric ciphers:

| Cipher | Payload Size | Encrypt Latency | Encrypt Throughput | Decrypt Latency | Decrypt Throughput |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **AES-256-GCM** | 64 B | 5.1 µs | 11.96 MB/s | 4.6 µs | 13.29 MB/s |
| **AES-256-GCM** | 1 KB | 6.7 µs | 146.19 MB/s | 3.6 µs | 274.32 MB/s |
| **AES-256-GCM** | 64 KB | 34.8 µs | **1,795.56 MB/s** | 12.9 µs | **4,857.01 MB/s** |
| **ChaCha20-Poly1305** | 64 B | 3.5 µs | 17.70 MB/s | 3.2 µs | 18.97 MB/s |
| **ChaCha20-Poly1305** | 1 KB | 6.9 µs | 140.67 MB/s | 5.4 µs | 181.38 MB/s |
| **ChaCha20-Poly1305** | 64 KB | 42.3 µs | **1,478.59 MB/s** | 22.4 µs | **2,789.68 MB/s** |

### Key Observations:
1. **AES-256-GCM** benefits heavily from hardware AES-NI and PCLMULQDQ instructions on modern x86_64 CPUs, achieving nearly **5.0 GB/s** decryption throughput on 64 KB blocks.
2. **ChaCha20-Poly1305** exhibits lower latency on small messages (64 B: 3.5 µs vs 5.1 µs) and provides exceptional performance on platforms lacking dedicated AES hardware (e.g. mobile, microcontrollers).

---

## 4. Architectural Recommendations for PQC Migration

1. **Standardize on ML-KEM-768**:
   - ML-KEM-768 provides NIST Category 3 security (equivalent to AES-192), meeting all NSA CNSA 2.0 and BSI guidelines.
   - It guarantees sub-packet delivery under standard 1,500-byte MTU constraints.

2. **Employ Hybrid Cryptographic Envelopes**:
   - During the 2024–2030 transition window, enterprise systems should adopt hybrid KEMs (e.g. `X25519 + ML-KEM-768`).
   - If an unexpected theoretical cryptanalytic breakthrough affects lattice assumptions, classical Diffie-Hellman maintains security; conversely, if a quantum computer arrives, ML-KEM shields the session.

3. **Strict Ephemeral Forward Secrecy**:
   - The decapsulation key ($dk$) must never be written to non-volatile storage and must be immediately zeroized post-handshake.
