# Requirements Specification: PQC & CBOM Risk Auditor

This document specifies the **10 Functional Requirements (FR)** and **10 Non-Functional Requirements (NFR)** for the **PQC & CBOM Risk Auditor** Minimum Viable Product (MVP) and enterprise baseline.

---

## 1. Functional Requirements (FR)

### FR-01: Automated TLS & Cipher Suite Handshake Probing
* **Description:** The system must actively probe network endpoints (HTTPS, mTLS, API gateways) across TLS 1.2 and TLS 1.3 to detect supported cipher suites and key encapsulation mechanisms.
* **Acceptance Criteria:**
  * Detects post-quantum hybrid KEM groups (e.g., `X25519MLKEM768`, `SecP256r1MLKEM768`, `Kyber768`) vs. classical groups (`ECDHE-X25519`, `P-256`, `RSA`).
  * Flags obsolete and insecure cipher suites (e.g., 3DES, RC4, CBC-mode ciphers).
  * Records ALPN protocols (HTTP/2, HTTP/3, gRPC).

### FR-02: X.509 Certificate Chain Quantum Vulnerability Inspection
* **Description:** The engine must parse the entire certificate hierarchy (Leaf, Intermediates, Root CA) retrieved from endpoints or provided locally.
* **Acceptance Criteria:**
  * Evaluates signature algorithms (e.g., `sha256WithRSAEncryption`, `ecdsa-with-SHA384`, `ML-DSA-65 / Dilithium`).
  * Calculates Shor's algorithm vulnerability index per certificate tier.
  * Checks certificate validity windows and flags certificates expiring past estimated CRQC (Cryptographically Relevant Quantum Computer) timelines.

### FR-03: Multi-Language Static Codebase & Dependency Scanner
* **Description:** Static code analysis engine parsing source code trees and dependency manifests to identify cryptographic primitives and library calls.
* **Acceptance Criteria:**
  * Supports AST / pattern parsing for Python (`cryptography`, `pycryptodome`, `hashlib`), Java (`javax.crypto`, BouncyCastle, JCE), Go (`crypto/*`), C#/.NET (`System.Security.Cryptography`), and C/C++ (OpenSSL, libsodium).
  * Detects hardcoded keys, weak hashing (`MD5`, `SHA-1`), symmetric algorithms (`AES-128` vs `AES-256`), and asymmetric key exchanges (`RSA-2048`, `ECC Secp256r1`).

### FR-04: Standardized CBOM (Cryptographic Bill of Materials) Generation
* **Description:** Automatically constructs and exports a structured, machine-readable Cryptographic Bill of Materials.
* **Acceptance Criteria:**
  * Outputs in **CycloneDX v1.6+ JSON/XML** (CBOM extension) and **SPDX 3.0** formats.
  * Catalogs asset identity, algorithm OID / name, key length, classical security level (bits), quantum security level (bits), crypto primitive type (KEM, Digital Signature, Hash, AEAD), and file/line provenance.

### FR-05: HNDL (Harvest Now, Decrypt Later) Risk Index Scoring
* **Description:** Calculates asset-specific risk scores based on data confidentiality lifespan against quantum progress estimates.
* **Acceptance Criteria:**
  * Inputs: Data retention period (years: $T_r$), Migration timeline ($T_m$), Quantum collapse horizon ($Z_q$).
  * Applies Mosca's Theorem ($T_m + T_r > Z_q \implies \text{Critical Risk}$).
  * Emits normalized HNDL Risk Index from $0$ (Quantum-Safe / Hybrid) to $100$ (Critical Imminent Vulnerability).

### FR-06: DORA & Regulatory Compliance Mapping Engine
* **Description:** Automatically correlates audit findings to specific regulatory articles and cryptographic guidance.
* **Acceptance Criteria:**
  * Maps findings to **EU DORA** (Regulation EU 2022/2554, Art. 9 "Protection and Prevention", Art. 13 "ICT Security").
  * Cross-references **NIST FIPS 203 (ML-KEM)**, **FIPS 204 (ML-DSA)**, **FIPS 205 (SLH-DSA)**, and **BSI TR-02102**.
  * Generates compliance pass/fail/gap matrices for supervisory reporting (DNB, AFM, ECB).

### FR-07: Dual Execution Modes (CLI & Back-Office REST API)
* **Description:** The system must operate both as an autonomous command-line tool and as a decoupled microservice API.
* **Acceptance Criteria:**
  * Standalone CLI mode executes one-off audits without external server dependencies.
  * REST API (OpenAPI 3.0) exposes endpoints for `/api/v1/scan/endpoint`, `/api/v1/scan/codebase`, and `/api/v1/reports/cbom` with webhook callback support for asynchronous batch scans.

### FR-08: CI/CD Quality Gate & Pull Request Blocker
* **Description:** Integrates into development workflows (GitHub Actions, GitLab CI) to detect cryptographic regressions.
* **Acceptance Criteria:**
  * Provides configurable threshold triggers (e.g., fail build if new RSA-2048 or deprecated hash is introduced).
  * Emits Markdown PR summaries detailing newly detected cryptographic components and suggested PQC alternatives.

### FR-09: Automated Executive & Technical Reporting
* **Description:** Multi-tier reporting engine generating stakeholder-specific outputs.
* **Acceptance Criteria:**
  * **Executive Summary:** High-level PDF/HTML dashboard with KPI risk dials, DORA status, and exposure heatmaps.
  * **Technical Audit Workpapers:** Comprehensive JSON, CSV, and interactive Excel spreadsheets with full CBOM details for security engineers and external auditors.

### FR-10: Prioritized Remediation Roadmap & Playbook
* **Description:** Recommends concrete mitigation paths and drop-in PQC algorithm replacements.
* **Acceptance Criteria:**
  * Categorizes findings into Quick Wins (e.g. TLS cipher configuration), Medium Term (hybrid KEM integration), and Strategic (PKI / Root CA migration).
  * Provides code-level migration snippets (e.g. migrating Python `cryptography` or Java BouncyCastle to ML-KEM-768).

---

## 2. Non-Functional Requirements (NFR)

### NFR-01: Zero Data Retention & Privacy by Design (Security)
* **Specification:** The scanner must operate strictly in-memory during AST and network analysis.
* **Target:** Zero customer source code, private keys, payload content, or unmasked credentials persisted to disk or transmitted to external third-party services.

### NFR-02: High-Performance Scan Throughput (Performance)
* **Specification:** Rapid execution to minimize developer friction and enable large-scale infrastructure scanning.
* **Target:**
  * Endpoint TLS probe: $< 3$ seconds per host.
  * Codebase CBOM scan: $< 30$ seconds for a 100,000 LOC repository on standard dual-core hardware.

### NFR-03: Modular & Extensible Architecture (Maintainability)
* **Specification:** Decoupled engine design using provider/strategy patterns.
* **Target:** Adding a new programming language AST parser or new NIST/ISO cryptographic standard requires $< 200$ lines of plugin code without altering core evaluation pipeline.

### NFR-04: Deterministic & Reproducible Audit Integrity (Reliability)
* **Specification:** Auditing the exact same target state (endpoint snapshot or commit SHA) must produce identical CBOM outputs and risk scores.
* **Target:** Every generated report embeds a deterministic SHA-256 integrity digest of inputs and audit rulesets.

### NFR-05: Lightweight Footprint & Cloud-Native Packaging (Portability)
* **Specification:** The software must deploy seamlessly across varied operating environments.
* **Target:**
  * Docker image size $< 150\text{MB}$.
  * Runs with $< 256\text{MB}$ RAM in CLI mode and $< 512\text{MB}$ in API server mode.
  * Compatible with Linux (x86_64, aarch64), macOS (Apple Silicon / Intel), and Windows.

### NFR-06: Low False-Positive Tolerance (Accuracy)
* **Specification:** High-precision AST parsing distinguishing between active production cryptography and test fixtures/mock data.
* **Target:** False positive rate $< 3\%$ on standard enterprise codebases.

### NFR-07: Resilient & Non-Intrusive Network Probing (Operational Safety)
* **Specification:** Network probing must never degrade target service availability or trigger security denial-of-service locks.
* **Target:** Passive TLS ClientHello negotiation only; graceful socket timeouts (configurable, default 5s); strict concurrency controls.

### NFR-08: Standardized Enterprise Interoperability (Integration)
* **Specification:** Open standards compliance for back-office enterprise architectures.
* **Target:** Full compliance with OpenAPI 3.0 specifications, CycloneDX v1.6 CBOM schema, and RFC 9110 HTTP standards for REST integration with ServiceNow, RSA Archer, and SIEM platforms.

### NFR-09: Least Privilege & Hardened Execution (Security)
* **Specification:** Core binary and container images must adhere to strict security hardening.
* **Target:** Runs as non-root user (`UID 10001`), signed container images via Cosign, zero high/critical CVEs in base dependencies.

### NFR-10: Executive & Ergonomic UI/UX Consistency (Usability)
* **Specification:** Clear, intuitive data representation tailored to both technical security specialists and non-technical risk executives.
* **Target:** Single-glance status indicators (Red/Amber/Green), clear mathematical formulas for risk scoring, and zero cryptic error messages.
