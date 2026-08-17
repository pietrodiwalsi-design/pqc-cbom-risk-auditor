# PQC & CBOM Risk Auditor 🛡️📦

> **Automated Cryptographic Bill of Materials (CBOM) Extraction, Post-Quantum TLS Probing & DORA Compliance Risk Assessment Platform.**

---

## 🌟 Executive Overview

The **PQC & CBOM Risk Auditor** is an enterprise-grade cybersecurity and IT risk governance engine designed to assess, quantify, and remediate cryptographic obsolescence in the advent of quantum computing. 

It provides financial institutions, critical infrastructure operators, and enterprise software vendors with:
1. **Automated TLS & Network Endpoint Probing** for Post-Quantum Cryptography (PQC) hybrid key encapsulation (NIST FIPS 203 ML-KEM / Kyber) vs. legacy RSA/ECC.
2. **Multi-Language Static Codebase Scanning** generating standardized **CycloneDX v1.6+ Cryptographic Bill of Materials (CBOM)**.
3. **Quantified HNDL (Harvest Now, Decrypt Later) Risk Indexing** matching data retention policies with quantum decryption horizons.
4. **Automated Regulatory Compliance Mapping** against **EU DORA** (Articles 9 & 13), **NIST FIPS 203/204/205**, **BSI TR-02102**, and **NCSC guidelines**.

---

## 🏛️ Strategic Role in the IT Risk Suite

The **PQC & CBOM Risk Auditor** is the dedicated Cryptographic Resilience pillar within Peter Van Walsem's enterprise IT Risk portfolio:

| Suite Tool | Focus Area | Core Standard / Framework |
| :--- | :--- | :--- |
| **STRIDE Threat Modeler** | Architecture & Threat Design | STRIDE / MITRE ATT&CK |
| **EU AI Act Compliance Checker** | AI Governance & Regulatory Classification | EU AI Act (Regulation EU 2024/1689) |
| **AI Bias Checker** | Machine Learning Fairness & Parity | Statistical Parity & Equalized Odds |
| **IT Risk Quantification Tool** | Financial Risk & Loss Modeling | Open FAIR™ Standard |
| **⭐ PQC & CBOM Risk Auditor** | **Crypto Inventory, PQC & Resilience** | **EU DORA / NIST FIPS 203/204 / BSI** |

---

## 🚀 Key Capabilities

- **🔍 Dual-Engine Scanning:**
  - **Endpoint Probe:** Evaluates live TLS 1.3/1.2 handshakes, supported cipher suites, PQC KEM groups (`X25519MLKEM768`, `SecP256r1MLKEM768`), and X.509 certificate chains.
  - **CBOM Codebase Parser:** Static AST extraction across Python, Java (JCE/BouncyCastle), Go (`crypto/*`), C# (.NET BCL), and C/C++ (OpenSSL).
- **📦 Standardized CBOM Generation:** Native export to CycloneDX 1.6+ JSON/XML format for ingestion into GRC, SIEM, and vulnerability management platforms.
- **⏳ HNDL Risk Engine:** Computes risk exposure using data confidentiality lifespans:
  $$\text{HNDL Risk Score} = f(\text{Data Retention Years}, \text{Algorithm Vulnerability}, \text{Perimeter Exposure})$$
- **⚡ Dual Execution Modes:**
  - **Standalone Mode:** Interactive CLI tool and self-contained HTML audit dashboard for auditors and consultants.
  - **Integrated Mode:** Headless REST API and OCI Docker container for seamless CI/CD quality gates and back-office GRC orchestration (e.g. ServiceNow, RSA Archer).

---

## 📂 Documentation Index

Detailed architectural and planning documents are available in the [`docs/`](docs/) directory:

- 📋 [**Requirements Specification** (`docs/REQUIREMENTS.md`)](docs/REQUIREMENTS.md): Detailed breakdown of the 10 Functional and 10 Non-Functional Requirements.
- 🏗️ [**System Architecture & Data Flow** (`docs/ARCHITECTURE.md`)](docs/ARCHITECTURE.md): Multi-layer architecture, trust boundaries, CBOM pipeline, and component design.
- 🗺️ [**Development Plan & MVP Roadmap** (`docs/DEVELOPMENT_PLAN.md`)](docs/DEVELOPMENT_PLAN.md): 4-phase agile implementation plan from MVP to Enterprise Cloud-Native Suite.
- 🧭 [**Architecture Diagram** (`docs/architecture-diagram.svg`)](docs/architecture-diagram.svg): Visual system topology and component interactions.

---

## 🛠️ Quickstart (MVP Standalone)

```bash
# Clone the repository
git clone git@github.com:pietrodiwalsi-design/pqc-cbom-risk-auditor.git
cd pqc-cbom-risk-auditor

# Install dependencies
pip install -r requirements.txt

# Run an external TLS Endpoint PQC audit
python3 -m pqc_auditor probe --host api.insurance-group.eu --port 443 --output report.json

# Scan a repository for Cryptographic Bill of Materials (CBOM)
python3 -m pqc_auditor scan-repo --path ./core-banking-service --format cyclonedx --output cbom.json

# Calculate HNDL Risk Score & Generate DORA Compliance Summary
python3 -m pqc_auditor audit --retention-years 30 --dora-report
```

---

## 📄 License & Ownership

Developed by **Peter Van Walsem** / `pietrodiwalsi-design`.  
Licensed under the Apache License 2.0.
