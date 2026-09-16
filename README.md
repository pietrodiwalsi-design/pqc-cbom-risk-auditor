# PQC & CBOM Risk Auditor 🛡️📦

> **Automated Cryptographic Bill of Materials (CBOM) Extraction, Post-Quantum TLS Probing & DORA Compliance Risk Assessment Platform.**

---

## 🌟 Executive Overview

The **PQC & CBOM Risk Auditor** is an enterprise-grade cybersecurity and IT risk governance engine designed to assess, quantify, and remediate cryptographic obsolescence in the advent of quantum computing. 

It provides financial institutions, critical infrastructure operators, and enterprise software vendors with:
1. **Automated TLS & Network Endpoint Probing** for Post-Quantum Cryptography (PQC) hybrid key encapsulation (NIST FIPS 203 ML-KEM / Kyber) vs. legacy RSA/ECC.
2. **Multi-Language Static Codebase Scanning** generating standardized **CycloneDX v1.6+ Cryptographic Bill of Materials (CBOM)** across Python, Java, Go, C#, C++, Rust, and Kotlin.
3. **Quantified HNDL (Harvest Now, Decrypt Later) Risk Indexing** matching data retention policies with quantum decryption horizons.
4. **Automated Regulatory Compliance Mapping** against **EU DORA** (Articles 9 & 13), **NIST FIPS 203/204/205**, **BSI TR-02102**, and **NCSC guidelines**.
5. **FastMCP Server:** Anthropic Model Context Protocol interface for Claude Desktop and Cursor.

---

## 🏛️ Strategic Role in the IT Risk Suite

The **PQC & CBOM Risk Auditor** is the dedicated Cryptographic Resilience pillar within Peter Van Walsem's enterprise IT Risk portfolio:

| Suite Tool | Focus Area | Core Standard / Framework |
| :--- | :--- | :--- |
| **STRIDE Threat Modeler** | Architecture & Threat Design | STRIDE / MITRE ATT&CK / OWASP ASI |
| **EU AI Act Compliance Checker** | AI Governance & Regulatory Classification | EU AI Act (Regulation EU 2024/1689) |
| **AI Risk Auditor** | AI Model Risk & Adversarial Robustness | NIST AI RMF 1.0 / MITRE ATLAS |
| **Vendor SOC / ISAE Auditor** | Privacy-First Third-Party Risk Management | EU DORA (Art. 28) / SOC 2 Type II |
| **⭐ PQC & CBOM Risk Auditor** | **Crypto Inventory, PQC & Resilience** | **EU DORA / NIST FIPS 203/204 / BSI** |

---

## 🚀 Key Capabilities

- **🔍 Dual-Engine Scanning:**
  - **Endpoint Probe:** Evaluates live TLS 1.3/1.2 handshakes, supported cipher suites, PQC KEM groups (`X25519MLKEM768`, `SecP256r1MLKEM768`), and X.509 certificate chains.
  - **Multi-Language CBOM Parser:** Static AST extraction across Python, Java (JCE/BouncyCastle), Go (`crypto/*`), C# (.NET BCL), C/C++, Rust, and Kotlin.
- **📦 Standardized CBOM Generation:** Native export to CycloneDX 1.6+ JSON format.
- **⏳ HNDL Risk Engine:** Computes risk exposure using Mosca's Theorem:
  $$\text{HNDL Risk Score} = f(\text{Data Retention Years}, \text{Algorithm Vulnerability}, \text{Quantum Horizon})$$
- **⚡ Multiple Execution Modes:**
  - **Standalone Mode:** Interactive CLI tool and self-contained HTML audit dashboard.
  - **FastMCP Mode:** Anthropic MCP server for live execution in Claude Desktop & Cursor IDE.
  - **CI/CD Quality Gate:** Automated GitHub Actions workflow (`.github/workflows/cbom-scan.yml`).

---

## 🛠️ Quickstart (CLI)

```bash
# Clone the repository
git clone https://github.com/pietrodiwalsi-design/pqc-cbom-risk-auditor.git
cd pqc-cbom-risk-auditor

# Install dependencies
pip install -r requirements.txt

# Run an external TLS Endpoint PQC audit
python3 -m pqc_auditor.cli probe --host mijn.nn.nl --port 443

# Scan a repository for Cryptographic Bill of Materials (CBOM)
python3 -m pqc_auditor.cli scan-repo --path ./core-banking-service

# Calculate HNDL Risk Score & Generate DORA Compliance Summary
python3 -m pqc_auditor.cli audit --retention-years 30

# Start FastMCP Server for Claude Desktop & Cursor
python3 -m pqc_auditor.mcp_server
```

---

## 📋 Compliance & Framework Coverage

| Framework | Coverage Scope | Implementation Status |
| :--- | :--- | :--- |
| **EU DORA (Art. 9)** | Cryptographic Protection & Prevention Measures | ✅ **Implemented** |
| **EU DORA (Art. 13)** | Advanced ICT Capabilities & Cryptographic Inventory (CBOM) | ✅ **Implemented** |
| **NIST FIPS 203** | ML-KEM-768 Post-Quantum Key Encapsulation Probing | ✅ **Implemented** |
| **NIST FIPS 204** | ML-DSA-65 Digital Signature Detection | ✅ **Implemented** |
| **CycloneDX 1.6+** | Standardized Cryptographic Bill of Materials (CBOM) Export | ✅ **Implemented** |
| **FastMCP Protocol** | Anthropic Model Context Protocol Server Interface | ✅ **Implemented** |

---

## 📄 License & Authors

- **Author & Project Lead:** [Peter Van Walsem](https://github.com/pietrodiwalsi-design) (`pietrodiwalsi-design`)
- **License:** Apache License 2.0 (see `LICENSE` and `AUTHORS.md`).
