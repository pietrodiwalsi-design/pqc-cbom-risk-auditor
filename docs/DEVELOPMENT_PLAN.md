# High-Level Development Plan & Roadmap

## 🎯 Project Objective
Deliver a market-ready, enterprise-grade **PQC & CBOM Risk Auditor** platform that discovers cryptographic assets across network endpoints and codebases, generates standardized CycloneDX CBOM manifests, quantifies HNDL risks, and generates audit reports aligned with EU DORA and NIST standards.

---

## 🗓️ Phased Implementation Roadmap

```
+-----------------------------------------------------------------------------------------+
| Phase 1: MVP Core (Weeks 1 - 3)                                                         |
| - CLI Interface & Baseline Data Models                                                  |
| - TLS 1.3 / ML-KEM-768 Network Handshake Prober                                        |
| - Python & Java AST CBOM Extractor (CycloneDX 1.6+)                                     |
| - HNDL Risk Index Algorithm & Basic DORA Art. 9/13 Mapper                               |
| - Markdown & JSON Audit Reporting                                                       |
+-----------------------------------------------------------------------------------------+
                                           |
                                           v
+-----------------------------------------------------------------------------------------+
| Phase 2: Multi-Language & Reporting Engine (Weeks 4 - 6)                                |
| - Expanded AST Parsers: Go, C# (.NET), C/C++ (OpenSSL)                                  |
| - X.509 PKI Chain Analyzer & Shor Factorization Risk Index                              |
| - Interactive HTML Audit Dashboard & Excel Workpapers                                   |
| - CI/CD Quality Gate (GitHub Action & GitLab CI Runner)                                 |
+-----------------------------------------------------------------------------------------+
                                           |
                                           v
+-----------------------------------------------------------------------------------------+
| Phase 3: Back-Office REST API & Orchestration (Weeks 7 - 9)                            |
| - Containerized REST Microservice (OpenAPI 3.0 / FastAPI)                               |
| - Asynchronous Batch Scanning & Webhook Event Notifications                             |
| - Deterministic SHA-256 Audit Integrity Hashes & Signed Reports                        |
| - GRC Connectors (ServiceNow / Jira / RSA Archer Export)                                |
+-----------------------------------------------------------------------------------------+
                                           |
                                           v
+-----------------------------------------------------------------------------------------+
| Phase 4: Enterprise Scale & Continuous Monitoring (Weeks 10 - 12)                       |
| - Multi-tenant Cloud/VPC Deployment Helm Charts                                         |
| - Continuous Perimeter Re-Scanning & Cryptographic Drift Alerts                         |
| - Live Performance Benchmark: Latency & Packet Fragmentation Overhead under PQC         |
| - Automated Remediation PR Generator (Automated code upgrades to PQC primitives)        |
+-----------------------------------------------------------------------------------------+
```

---

## 📦 Phase 1: MVP Scope & Deliverables (In Progress)

### Milestone 1.1: Core Architecture & Data Models
* [x] Project repository initialized and requirements documented.
* [ ] Pydantic / dataclass schemas for Cryptographic Assets, CBOM elements, Endpoint profiles, and Audit findings.
* [ ] CLI entry point (`pqc_auditor.cli`) with subcommands: `probe`, `scan-repo`, `audit`, and `export-cbom`.

### Milestone 1.2: Endpoint Handshake Prober
* [ ] TLS 1.2 and TLS 1.3 probe supporting standard and hybrid PQC key encapsulation groups (`X25519MLKEM768`, `SecP256r1MLKEM768`, `Kyber768`).
* [ ] Cipher suite classification (PQC Hybrid, Classical Strong, Deprecated/Weak).
* [ ] X.509 leaf certificate signature and key size extraction.

### Milestone 1.3: Static AST CBOM Parser (Python & Java)
* [ ] Python parser inspecting `cryptography`, `hashlib`, `ssl`, and `pycryptodome`.
* [ ] Java parser inspecting `javax.crypto.*`, `java.security.*`, and BouncyCastle providers.
* [ ] CycloneDX v1.6+ JSON CBOM serializer.

### Milestone 1.4: HNDL Risk Engine & DORA Compliance Mapping
* [ ] Mathematical HNDL scoring engine based on data retention windows ($T_r$) and quantum transition estimates ($Z_q$).
* [ ] Rule-based compliance matrix mapping findings to DORA Articles 9 and 13.
* [ ] Self-contained Markdown and JSON report generator.

---

## 📊 Work Breakdown Structure (WBS) & Resource Allocation

| Component | Lead Responsibilities | Key Dependencies | Deliverable Format |
| :--- | :--- | :--- | :--- |
| **Network Probing Engine** | TLS 1.3 socket probes, KEM group enumeration, handshake timing | `ssl`, `cryptography`, socket | Python module (`prober.py`) |
| **Static CBOM Extractor** | Multi-language AST parsing, dependency manifest inspection | `ast`, tree-sitter | Python module (`cbom.py`) |
| **HNDL Risk Engine** | Mathematical risk modeling, Mosca's theorem calculations | NumPy / standard math | Python module (`risk.py`) |
| **DORA Compliance Engine**| Regulatory ruleset, gap scoring, recommendation generator | JSON rulesets | Python module (`dora.py`) |
| **Reporting & Export** | CycloneDX 1.6 serialization, HTML/PDF rendering, Excel output | `jinja2`, `openpyxl` | Python module (`reporting.py`)|
| **API & Headless Service**| FastAPI REST server, OpenAPI docs, Docker containerization | FastAPI, Uvicorn, Docker | Service container (`api/`) |

---

## 🛡️ Quality Assurance & Validation Strategy
1. **Unit Testing:** $> 85\%$ test coverage across all AST extraction patterns and mathematical risk calculations.
2. **Benchmark Verification:** Validation against known test endpoints (e.g. Cloudflare PQC test servers, Google Chrome PQC endpoints).
3. **Synthetic Vulnerability Codebase:** Dedicated test repositories containing deliberate legacy crypto (e.g. RSA-1024, MD5, DES) to verify 100% detection recall with $< 3\%$ false positive rate.
