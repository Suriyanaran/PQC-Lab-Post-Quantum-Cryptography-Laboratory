"""High-precision benchmarking suite for Post-Quantum Cryptography primitives."""

import argparse
import json
import os
import sys
import time
from typing import Dict, List, Tuple

# Add parent directory to path so imports work when running directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.crypto.kem import get_kem_provider, list_supported_kem_algorithms
from app.crypto.kdf import derive_session_keys
from app.crypto.aead import encrypt_aead, decrypt_aead


def benchmark_kem_algorithm(algo_name: str, iterations: int = 50, warmup: int = 5) -> Dict:
    """Benchmark keygen, encapsulation, and decapsulation for a given KEM."""
    kem = get_kem_provider(algo_name)

    # Warmup
    for _ in range(warmup):
        pk, sk = kem.keygen()
        ss, ct = kem.encapsulate(pk)
        _ = kem.decapsulate(sk, ct)

    # 1. Benchmark Keygen
    keygen_times: List[float] = []
    keys: List[Tuple[bytes, bytes]] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        pk, sk = kem.keygen()
        t1 = time.perf_counter()
        keygen_times.append((t1 - t0) * 1000)  # ms
        keys.append((pk, sk))

    # 2. Benchmark Encapsulation
    encaps_times: List[float] = []
    ciphertexts: List[Tuple[bytes, bytes]] = []
    for i in range(iterations):
        pk = keys[i][0]
        t0 = time.perf_counter()
        ss, ct = kem.encapsulate(pk)
        t1 = time.perf_counter()
        encaps_times.append((t1 - t0) * 1000)
        ciphertexts.append((ss, ct))

    # 3. Benchmark Decapsulation
    decaps_times: List[float] = []
    for i in range(iterations):
        sk = keys[i][1]
        ct = ciphertexts[i][1]
        t0 = time.perf_counter()
        _ = kem.decapsulate(sk, ct)
        t1 = time.perf_counter()
        decaps_times.append((t1 - t0) * 1000)

    avg_keygen = sum(keygen_times) / len(keygen_times)
    avg_encaps = sum(encaps_times) / len(encaps_times)
    avg_decaps = sum(decaps_times) / len(decaps_times)
    total_handshake_ms = avg_keygen + avg_encaps + avg_decaps

    return {
        "algorithm": algo_name,
        "is_pqc": kem.is_quantum_resistant,
        "security_level": kem.security_level,
        "public_key_bytes": kem.public_key_size,
        "private_key_bytes": kem.private_key_size,
        "ciphertext_bytes": kem.ciphertext_size,
        "shared_secret_bytes": kem.shared_secret_size,
        "iterations": iterations,
        "keygen_avg_ms": round(avg_keygen, 3),
        "keygen_ops_sec": round(1000.0 / avg_keygen, 1) if avg_keygen > 0 else 0,
        "encaps_avg_ms": round(avg_encaps, 3),
        "encaps_ops_sec": round(1000.0 / avg_encaps, 1) if avg_encaps > 0 else 0,
        "decaps_avg_ms": round(avg_decaps, 3),
        "decaps_ops_sec": round(1000.0 / avg_decaps, 1) if avg_decaps > 0 else 0,
        "total_handshake_ms": round(total_handshake_ms, 3),
    }


def benchmark_aead_cipher(cipher_name: str, payload_size_bytes: int, iterations: int = 100) -> Dict:
    """Benchmark encryption and decryption throughput for an AEAD cipher."""
    key = os.urandom(32)
    plaintext = os.urandom(payload_size_bytes)
    aad = b"benchmark-aad-metadata-v1"

    # Warmup
    for _ in range(5):
        enc = encrypt_aead(key=key, plaintext=plaintext, associated_data=aad, cipher_name=cipher_name)
        _ = decrypt_aead(
            key=key,
            ciphertext=enc["ciphertext"],
            nonce=enc["nonce"],
            tag=enc["tag"],
            associated_data=aad,
            cipher_name=cipher_name,
        )

    # Benchmark Encrypt
    enc_times = []
    enc_results = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        enc = encrypt_aead(key=key, plaintext=plaintext, associated_data=aad, cipher_name=cipher_name)
        t1 = time.perf_counter()
        enc_times.append(t1 - t0)
        enc_results.append(enc)

    # Benchmark Decrypt
    dec_times = []
    for i in range(iterations):
        enc = enc_results[i]
        t0 = time.perf_counter()
        _ = decrypt_aead(
            key=key,
            ciphertext=enc["ciphertext"],
            nonce=enc["nonce"],
            tag=enc["tag"],
            associated_data=aad,
            cipher_name=cipher_name,
        )
        t1 = time.perf_counter()
        dec_times.append(t1 - t0)

    avg_enc_sec = sum(enc_times) / len(enc_times)
    avg_dec_sec = sum(dec_times) / len(dec_times)

    enc_throughput_mb_s = (payload_size_bytes / (1024 * 1024)) / avg_enc_sec if avg_enc_sec > 0 else 0
    dec_throughput_mb_s = (payload_size_bytes / (1024 * 1024)) / avg_dec_sec if avg_dec_sec > 0 else 0

    return {
        "cipher": cipher_name,
        "payload_bytes": payload_size_bytes,
        "iterations": iterations,
        "enc_latency_us": round(avg_enc_sec * 1_000_000, 2),
        "enc_throughput_mb_s": round(enc_throughput_mb_s, 2),
        "dec_latency_us": round(avg_dec_sec * 1_000_000, 2),
        "dec_throughput_mb_s": round(dec_throughput_mb_s, 2),
    }


def print_kem_summary_table(results: List[Dict]):
    """Print formatted summary table for KEM benchmarks."""
    header = (
        f"{'Algorithm':<14} | {'PQC?':<5} | {'PK (B)':<7} | {'CT (B)':<7} | "
        f"{'Keygen (ms)':<11} | {'Encaps (ms)':<11} | {'Decaps (ms)':<11} | {'Total (ms)':<10}"
    )
    separator = "-" * len(header)
    print("\n" + "=" * len(header))
    print(" POST-QUANTUM & CLASSICAL KEM BENCHMARK RESULTS")
    print("=" * len(header))
    print(header)
    print(separator)
    for r in results:
        pqc_str = "YES" if r["is_pqc"] else "NO"
        line = (
            f"{r['algorithm']:<14} | {pqc_str:<5} | {r['public_key_bytes']:<7} | {r['ciphertext_bytes']:<7} | "
            f"{r['keygen_avg_ms']:<11.3f} | {r['encaps_avg_ms']:<11.3f} | {r['decaps_avg_ms']:<11.3f} | "
            f"{r['total_handshake_ms']:<10.3f}"
        )
        print(line)
    print(separator)


def print_aead_summary_table(results: List[Dict]):
    """Print formatted summary table for AEAD benchmarks."""
    header = (
        f"{'Cipher':<18} | {'Payload':<9} | {'Enc Latency':<12} | {'Enc MB/s':<10} | "
        f"{'Dec Latency':<12} | {'Dec MB/s':<10}"
    )
    separator = "-" * len(header)
    print("\n" + "=" * len(header))
    print(" SYMMETRIC AEAD THROUGHPUT & LATENCY BENCHMARK RESULTS")
    print("=" * len(header))
    print(header)
    print(separator)
    for r in results:
        payload_str = f"{r['payload_bytes'] // 1024} KB" if r['payload_bytes'] >= 1024 else f"{r['payload_bytes']} B"
        line = (
            f"{r['cipher']:<18} | {payload_str:<9} | {r['enc_latency_us']:>8.1f} us  | "
            f"{r['enc_throughput_mb_s']:>8.2f}   | {r['dec_latency_us']:>8.1f} us  | "
            f"{r['dec_throughput_mb_s']:>8.2f}"
        )
        print(line)
    print(separator + "\n")


def main():
    parser = argparse.ArgumentParser(description="PQC-Lab Benchmark Suite")
    parser.add_argument("--iterations", type=int, default=30, help="Number of benchmark iterations (default: 30)")
    parser.add_argument("--save-json", type=str, default=None, help="Save raw benchmark results to JSON file")
    args = parser.parse_args()

    print(f"\n[+] Starting PQC-Lab Benchmark Suite ({args.iterations} iterations per algorithm)...")

    kem_algos = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "X25519"]
    kem_results = []
    for algo in kem_algos:
        print(f"  • Benchmarking {algo}...", end="", flush=True)
        res = benchmark_kem_algorithm(algo, iterations=args.iterations)
        kem_results.append(res)
        print(f" done ({res['total_handshake_ms']} ms/handshake)")

    print_kem_summary_table(kem_results)

    aead_sizes = [64, 1024, 65536]  # 64B, 1KB, 64KB
    aead_ciphers = ["AES-256-GCM", "ChaCha20-Poly1305"]
    aead_results = []
    for cipher in aead_ciphers:
        for size in aead_sizes:
            print(f"  • Benchmarking {cipher} ({size} B)...", end="", flush=True)
            res = benchmark_aead_cipher(cipher, payload_size_bytes=size, iterations=50)
            aead_results.append(res)
            print(f" done ({res['enc_throughput_mb_s']} MB/s)")

    print_aead_summary_table(aead_results)

    if args.save_json:
        payload = {
            "timestamp": time.time(),
            "kem_benchmarks": kem_results,
            "aead_benchmarks": aead_results,
        }
        with open(args.save_json, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"[✔] Benchmark data exported to {args.save_json}")


if __name__ == "__main__":
    main()
