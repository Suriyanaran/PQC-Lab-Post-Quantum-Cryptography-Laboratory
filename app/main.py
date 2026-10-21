"""Main FastAPI application entry point for PQC-Lab."""

from contextlib import asynccontextmanager
import time
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from app.config import settings
from app.api.routes import router as api_router
from app.services.session_service import session_service


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle management."""
    # Startup actions
    yield
    # Shutdown actions: securely wipe all session keys
    session_service.cleanup_expired_sessions()


app = FastAPI(
    title=settings.APP_TITLE,
    version=settings.APP_VERSION,
    description=settings.APP_DESCRIPTION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Enable CORS for web clients and cross-origin experimentation
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount REST API
app.include_router(api_router)


@app.get("/health", tags=["Health"])
def health_check():
    """Health check endpoint providing service status."""
    return {
        "status": "healthy",
        "service": settings.APP_TITLE,
        "version": settings.APP_VERSION,
        "timestamp": time.time(),
        "default_kem": settings.DEFAULT_KEM_ALGORITHM,
        "default_aead": settings.DEFAULT_AEAD_CIPHER,
    }


@app.get("/", response_class=HTMLResponse, tags=["Dashboard"])
def interactive_dashboard():
    """Interactive Post-Quantum Cryptography Laboratory Web Dashboard."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PQC-Lab | Post-Quantum Cryptography Laboratory</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Outfit:wght@300;400;600;700;900&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #070913;
            --bg-card: rgba(18, 24, 43, 0.7);
            --bg-card-hover: rgba(28, 38, 68, 0.85);
            --border-subtle: rgba(99, 102, 241, 0.2);
            --border-glow: rgba(168, 85, 247, 0.4);
            --accent-cyan: #06b6d4;
            --accent-indigo: #6366f1;
            --accent-purple: #a855f7;
            --accent-emerald: #10b981;
            --accent-rose: #f43f5e;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --font-display: 'Outfit', sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-base);
            background-image: 
                radial-gradient(circle at 15% 20%, rgba(99, 102, 241, 0.15) 0%, transparent 40%),
                radial-gradient(circle at 85% 80%, rgba(168, 85, 247, 0.15) 0%, transparent 40%),
                radial-gradient(circle at 50% 50%, rgba(6, 182, 212, 0.08) 0%, transparent 60%);
            color: var(--text-main);
            font-family: var(--font-display);
            min-height: 100vh;
            padding: 2rem 1.5rem;
            line-height: 1.5;
        }

        .container {
            max-width: 1280px;
            margin: 0 auto;
        }

        header {
            text-align: center;
            margin-bottom: 3rem;
            position: relative;
        }

        .badge-quantum {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            background: linear-gradient(135deg, rgba(99,102,241,0.2), rgba(168,85,247,0.2));
            border: 1px solid var(--border-glow);
            padding: 0.4rem 1rem;
            border-radius: 9999px;
            font-size: 0.85rem;
            font-weight: 600;
            color: #c084fc;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 1rem;
            backdrop-filter: blur(10px);
        }

        h1 {
            font-size: clamp(2.2rem, 5vw, 3.6rem);
            font-weight: 900;
            letter-spacing: -0.03em;
            background: linear-gradient(135deg, #ffffff 30%, #a5b4fc 70%, #06b6d4 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.75rem;
        }

        p.lead {
            color: var(--text-muted);
            font-size: 1.15rem;
            max-width: 720px;
            margin: 0 auto 1.5rem auto;
        }

        .nav-links {
            display: flex;
            justify-content: center;
            gap: 1rem;
            flex-wrap: wrap;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.7rem 1.4rem;
            border-radius: 10px;
            font-weight: 600;
            font-size: 0.95rem;
            text-decoration: none;
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
            cursor: pointer;
            border: 1px solid transparent;
        }

        .btn-primary {
            background: linear-gradient(135deg, var(--accent-indigo), var(--accent-purple));
            color: #ffffff;
            box-shadow: 0 4px 20px rgba(99, 102, 241, 0.35);
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 25px rgba(99, 102, 241, 0.5);
        }

        .btn-outline {
            background: rgba(255, 255, 255, 0.04);
            border-color: var(--border-subtle);
            color: var(--text-main);
            backdrop-filter: blur(8px);
        }

        .btn-outline:hover {
            background: rgba(255, 255, 255, 0.08);
            border-color: var(--accent-indigo);
            transform: translateY(-2px);
        }

        .grid-2 {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .card {
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 16px;
            padding: 1.75rem;
            backdrop-filter: blur(12px);
            transition: border-color 0.25s, transform 0.25s;
        }

        .card:hover {
            border-color: var(--border-glow);
        }

        .card-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1.25rem;
        }

        .card-title {
            font-size: 1.25rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 0.6rem;
        }

        .pill {
            font-size: 0.75rem;
            font-weight: 700;
            padding: 0.25rem 0.6rem;
            border-radius: 6px;
            text-transform: uppercase;
        }

        .pill-pqc {
            background: rgba(16, 185, 129, 0.15);
            color: var(--accent-emerald);
            border: 1px solid rgba(16, 185, 129, 0.3);
        }

        .pill-classic {
            background: rgba(244, 63, 94, 0.15);
            color: var(--accent-rose);
            border: 1px solid rgba(244, 63, 94, 0.3);
        }

        .param-table {
            width: 100%;
            border-collapse: collapse;
            font-family: var(--font-mono);
            font-size: 0.85rem;
            margin-bottom: 1rem;
        }

        .param-table th, .param-table td {
            padding: 0.65rem 0.75rem;
            text-align: left;
            border-bottom: 1px solid rgba(255, 255, 255, 0.06);
        }

        .param-table th {
            color: var(--text-muted);
            font-weight: 500;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }

        .param-table td {
            color: #cbd5e1;
        }

        .interactive-section {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .form-group {
            display: flex;
            flex-direction: column;
            gap: 0.4rem;
        }

        label {
            font-size: 0.85rem;
            color: var(--text-muted);
            font-weight: 600;
        }

        select, input, textarea {
            background: rgba(10, 15, 30, 0.8);
            border: 1px solid var(--border-subtle);
            border-radius: 8px;
            padding: 0.65rem 0.85rem;
            color: var(--text-main);
            font-family: var(--font-mono);
            font-size: 0.9rem;
            outline: none;
            transition: border-color 0.2s;
        }

        select:focus, input:focus, textarea:focus {
            border-color: var(--accent-indigo);
            box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
        }

        .output-box {
            background: #050711;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 8px;
            padding: 0.85rem;
            font-family: var(--font-mono);
            font-size: 0.8rem;
            color: #38bdf8;
            max-height: 180px;
            overflow-y: auto;
            word-break: break-all;
            white-space: pre-wrap;
        }

        .flow-step {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 0.9rem;
            color: var(--text-muted);
            margin-bottom: 0.5rem;
        }

        .step-num {
            width: 24px;
            height: 24px;
            border-radius: 50%;
            background: rgba(99, 102, 241, 0.2);
            color: #818cf8;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.75rem;
            font-weight: bold;
        }

        footer {
            text-align: center;
            margin-top: 4rem;
            padding-top: 2rem;
            border-top: 1px solid rgba(255, 255, 255, 0.05);
            color: var(--text-muted);
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="badge-quantum">✨ NIST Post-Quantum Cryptography Suite</div>
            <h1>PQC-Lab Architecture</h1>
            <p class="lead">
                Experimentation environment for NIST FIPS 203 ML-KEM, RFC 5869 HKDF key derivation,
                and authenticated AEAD encryption envelopes (AES-256-GCM & ChaCha20-Poly1305).
            </p>
            <div class="nav-links">
                <a href="/docs" class="btn btn-primary" id="btn-swagger">⚡ Swagger API Docs</a>
                <a href="/redoc" class="btn btn-outline" id="btn-redoc">📖 ReDoc Specifications</a>
                <a href="/health" class="btn btn-outline" id="btn-health">🩺 Health Check</a>
            </div>
        </header>

        <div class="grid-2">
            <!-- Algorithm Comparison Matrix -->
            <div class="card">
                <div class="card-header">
                    <span class="card-title">🔬 Cryptographic Specification Matrix</span>
                    <span class="pill pill-pqc">FIPS 203 Validated</span>
                </div>
                <table class="param-table">
                    <thead>
                        <tr>
                            <th>Algorithm</th>
                            <th>NIST Cat</th>
                            <th>Public Key</th>
                            <th>Ciphertext</th>
                            <th>Quantum Safe</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong>ML-KEM-512</strong></td>
                            <td>Cat 1</td>
                            <td>800 B</td>
                            <td>768 B</td>
                            <td><span class="pill pill-pqc">Yes</span></td>
                        </tr>
                        <tr>
                            <td><strong>ML-KEM-768</strong></td>
                            <td>Cat 3</td>
                            <td>1,184 B</td>
                            <td>1,088 B</td>
                            <td><span class="pill pill-pqc">Yes (Default)</span></td>
                        </tr>
                        <tr>
                            <td><strong>ML-KEM-1024</strong></td>
                            <td>Cat 5</td>
                            <td>1,568 B</td>
                            <td>1,568 B</td>
                            <td><span class="pill pill-pqc">Yes</span></td>
                        </tr>
                        <tr>
                            <td><strong>X25519</strong></td>
                            <td>Classical</td>
                            <td>32 B</td>
                            <td>32 B</td>
                            <td><span class="pill pill-classic">No (Baseline)</span></td>
                        </tr>
                    </tbody>
                </table>
                <p style="font-size: 0.85rem; color: var(--text-muted);">
                    ML-KEM algorithms provide Module-Lattice based post-quantum hardness against Shor's algorithm,
                    yielding 32-byte shared secrets ready for HKDF session key expansion.
                </p>
            </div>

            <!-- Live Interactive Playground -->
            <div class="card">
                <div class="card-header">
                    <span class="card-title">🧪 Live KEM Demonstration</span>
                    <span id="pqc-status" class="pill pill-pqc">Ready</span>
                </div>
                <div class="interactive-section">
                    <div class="form-group">
                        <label for="algo-select">Select KEM Algorithm:</label>
                        <select id="algo-select">
                            <option value="ML-KEM-768" selected>ML-KEM-768 (NIST Category 3 - Standard)</option>
                            <option value="ML-KEM-512">ML-KEM-512 (NIST Category 1)</option>
                            <option value="ML-KEM-1024">ML-KEM-1024 (NIST Category 5)</option>
                            <option value="X25519">X25519 (Classical Baseline)</option>
                        </select>
                    </div>

                    <div style="display: flex; gap: 0.75rem; flex-wrap: wrap;">
                        <button class="btn btn-primary" id="btn-run-keygen" onclick="runKeygenDemo()">1. Keygen</button>
                        <button class="btn btn-outline" id="btn-run-encaps" onclick="runEncapsDemo()">2. Encapsulate</button>
                        <button class="btn btn-outline" id="btn-run-decaps" onclick="runDecapsDemo()">3. Decapsulate</button>
                    </div>

                    <div class="form-group">
                        <label>Console Output:</label>
                        <div class="output-box" id="demo-output">// Click "1. Keygen" to start generating quantum-resistant keys...</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- End-to-End Session Protocol Architecture -->
        <div class="card">
            <div class="card-header">
                <span class="card-title">🔐 Hybrid Cryptographic Envelope Protocol</span>
                <span class="pill pill-pqc">End-to-End Encrypted</span>
            </div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5rem;">
                <div>
                    <div class="flow-step">
                        <div class="step-num">1</div>
                        <div><strong>KEM Public Key Exchange</strong></div>
                    </div>
                    <p style="font-size: 0.85rem; color: var(--text-muted); margin-left: 2.2rem;">
                        Server generates ML-KEM-768 keypair and sends encapsulation key (1,184 B) to initiator.
                    </p>
                </div>
                <div>
                    <div class="flow-step">
                        <div class="step-num">2</div>
                        <div><strong>Encapsulation & Decapsulation</strong></div>
                    </div>
                    <p style="font-size: 0.85rem; color: var(--text-muted); margin-left: 2.2rem;">
                        Client encapsulates 32-byte shared secret, transmits 1,088-byte ciphertext. Server decapsulates.
                    </p>
                </div>
                <div>
                    <div class="flow-step">
                        <div class="step-num">3</div>
                        <div><strong>HKDF Key Expansion</strong></div>
                    </div>
                    <p style="font-size: 0.85rem; color: var(--text-muted); margin-left: 2.2rem;">
                        Both parties derive 256-bit symmetric AEAD key and handshake confirmation tag via RFC 5869.
                    </p>
                </div>
                <div>
                    <div class="flow-step">
                        <div class="step-num">4</div>
                        <div><strong>AEAD Payload Protection</strong></div>
                    </div>
                    <p style="font-size: 0.85rem; color: var(--text-muted); margin-left: 2.2rem;">
                        High-throughput message encryption with AES-256-GCM or ChaCha20-Poly1305 with authenticated AAD.
                    </p>
                </div>
            </div>
        </div>

        <footer>
            <p>PQC-Lab • Post-Quantum Cryptography Enterprise Suite • NIST FIPS 203 Compliant</p>
        </footer>
    </div>

    <script>
        let currentKeys = null;
        let currentEncaps = null;

        function logOutput(msg) {
            const box = document.getElementById('demo-output');
            box.textContent = msg;
        }

        async function runKeygenDemo() {
            const algo = document.getElementById('algo-select').value;
            logOutput(`[+] Generating ${algo} keypair...`);
            try {
                const res = await fetch('/api/v1/kem/keygen', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({algorithm: algo})
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Keygen failed');
                currentKeys = data;
                logOutput(`[✔] ${algo} Keypair Generated Successfully!\n` +
                          `• Public Key (${data.public_key_bytes} bytes): ${data.public_key_hex.substring(0, 48)}...\n` +
                          `• Private Key (${data.private_key_bytes} bytes): ${data.private_key_hex.substring(0, 48)}...\n\n` +
                          `Ready for Step 2: Encapsulate!`);
            } catch (err) {
                logOutput(`[✘] Error: ${err.message}`);
            }
        }

        async function runEncapsDemo() {
            if (!currentKeys) {
                logOutput('[!] Please run Step 1 (Keygen) first.');
                return;
            }
            logOutput(`[+] Encapsulating shared secret against public key...`);
            try {
                const res = await fetch('/api/v1/kem/encapsulate', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        algorithm: currentKeys.algorithm,
                        public_key_hex: currentKeys.public_key_hex
                    })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Encapsulation failed');
                currentEncaps = data;
                logOutput(`[✔] Encapsulation Completed!\n` +
                          `• Ciphertext (${data.ciphertext_bytes} bytes): ${data.ciphertext_hex.substring(0, 48)}...\n` +
                          `• Client Shared Secret (${data.shared_secret_bytes} bytes): ${data.shared_secret_hex}\n\n` +
                          `Ready for Step 3: Decapsulate!`);
            } catch (err) {
                logOutput(`[✘] Error: ${err.message}`);
            }
        }

        async function runDecapsDemo() {
            if (!currentKeys || !currentEncaps) {
                logOutput('[!] Please complete Step 1 (Keygen) and Step 2 (Encapsulate) first.');
                return;
            }
            logOutput(`[+] Decapsulating ciphertext using private key...`);
            try {
                const res = await fetch('/api/v1/kem/decapsulate', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        algorithm: currentKeys.algorithm,
                        private_key_hex: currentKeys.private_key_hex,
                        ciphertext_hex: currentEncaps.ciphertext_hex
                    })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Decapsulation failed');

                const matches = data.shared_secret_hex === currentEncaps.shared_secret_hex;
                logOutput(`[✔] Decapsulation Succeeded!\n` +
                          `• Recovered Shared Secret: ${data.shared_secret_hex}\n` +
                          `• Client/Server Secret Match: ${matches ? '✅ EXACT MATCH' : '❌ MISMATCH'}\n` +
                          `• Status: Quantum-safe channel established! Ready for HKDF key expansion.`);
            } catch (err) {
                logOutput(`[✘] Error: ${err.message}`);
            }
        }
    </script>
</body>
</html>
"""


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
