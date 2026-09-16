import os
import re
import json
from typing import Dict, Any, List

class CBOMParser:
    """Multi-language Cryptographic Bill of Materials (CBOM) AST Parser (CycloneDX 1.6+)."""

    CRYPTO_PATTERNS = [
        # Asymmetric / Legacy Public Key Cryptography (Quantum-Vulnerable)
        {"name": "RSA (1024/2048/4096-bit)", "category": "asymmetric", "pqc_status": "VULNERABLE (Shor's Algorithm)", "regex": r"\b(RSA|RSASSA|RSA_PKCS1|generate_rsa_key|RSACryptoServiceProvider|RSASignature|RSAEncryptionPadding)\b"},
        {"name": "ECDHE / ECDSA (NIST P-256/P-384)", "category": "asymmetric", "pqc_status": "VULNERABLE (Shor's Algorithm)", "regex": r"\b(ECDHE|ECDSA|secp256r1|secp384r1|curve25519|ed25519|ECParameters|ECDsaCng)\b"},
        {"name": "Diffie-Hellman (DH/DHE)", "category": "asymmetric", "pqc_status": "VULNERABLE (Shor's Algorithm)", "regex": r"\b(DiffieHellman|DHE-RSA|DHE-DSS|DHParameters)\b"},

        # Symmetric Ciphers (Grover Impact Assessment)
        {"name": "AES-256-GCM / CBC", "category": "symmetric", "pqc_status": "SAFE (128-bit Grover Resilience)", "regex": r"\b(AES_256|AES256|AES-256-GCM|AES-256-CBC|AesGcm|RijndaelManaged)\b"},
        {"name": "AES-128-GCM / CBC", "category": "symmetric", "pqc_status": "UPGRADE RECOMMENDED (64-bit Grover Weakness)", "regex": r"\b(AES_128|AES128|AES-128-GCM|AES-128-CBC)\b"},
        {"name": "ChaCha20-Poly1305", "category": "symmetric", "pqc_status": "SAFE (Quantum Resilient)", "regex": r"\b(ChaCha20|Poly1305|ChaCha20Poly1305)\b"},

        # Post-Quantum Cryptography (NIST FIPS 203 / 204 / 205 Standards)
        {"name": "ML-KEM-768 (Kyber)", "category": "pqc-kem", "pqc_status": "QUANTUM SAFE (NIST FIPS 203 Standard)", "regex": r"\b(ML_KEM|MLKEM768|Kyber768|X25519MLKEM768|SecP256r1MLKEM768)\b"},
        {"name": "ML-DSA-65 (Dilithium)", "category": "pqc-sign", "pqc_status": "QUANTUM SAFE (NIST FIPS 204 Standard)", "regex": r"\b(ML_DSA|MLDSA65|Dilithium3|Dilithium)\b"},
        {"name": "SLH-DSA (SPHINCS+)", "category": "pqc-sign", "pqc_status": "QUANTUM SAFE (NIST FIPS 205 Standard)", "regex": r"\b(SLH_DSA|SPHINCS|SPHINCSPlus)\b"}
    ]

    SUPPORTED_EXTENSIONS = ('.py', '.java', '.go', '.js', '.ts', '.c', '.cpp', '.cs', '.kt', '.rs')

    def scan_directory(self, repo_path: str) -> Dict[str, Any]:
        findings = []
        files_scanned = 0
        for root, _, files in os.walk(repo_path):
            if any(ign in root for ign in ['.git', 'node_modules', '__pycache__', '.venv', 'dist', 'build']):
                continue
            for file in files:
                if file.endswith(self.SUPPORTED_EXTENSIONS):
                    files_scanned += 1
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r', errors='ignore') as f:
                            content = f.read()
                            for pat in self.CRYPTO_PATTERNS:
                                matches = re.findall(pat["regex"], content, re.IGNORECASE)
                                if matches:
                                    findings.append({
                                        "algorithm": pat["name"],
                                        "category": pat["category"],
                                        "pqc_status": pat["pqc_status"],
                                        "file": os.path.relpath(filepath, repo_path),
                                        "occurrences": len(matches)
                                    })
                    except Exception:
                        continue

        vulnerable_count = sum(1 for f in findings if "VULNERABLE" in f["pqc_status"])
        quantum_safe_count = sum(1 for f in findings if "QUANTUM SAFE" in f["pqc_status"])

        cbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "component": {"name": os.path.basename(os.path.abspath(repo_path)), "type": "application"},
                "files_scanned": files_scanned,
                "total_cryptographic_findings": len(findings),
                "vulnerable_assets_count": vulnerable_count,
                "quantum_safe_assets_count": quantum_safe_count
            },
            "cryptographicAssets": findings
        }
        return cbom
