class DORAComplianceExporter:
    """Maps PQC & CBOM findings against EU DORA (Articles 9 & 13)."""

    def generate_dora_matrix(self, cbom: dict, prober_results: list) -> dict:
        crypto_assets = cbom.get("cryptographicAssets", [])
        vulnerable_count = sum(1 for a in crypto_assets if "VULNERABLE" in a.get("pqc_status", ""))
        pqc_ready_endpoints = sum(1 for p in prober_results if p.get("pqc_supported"))

        return {
            "dora_regulation": "Regulation (EU) 2022/2554 (DORA)",
            "article_9_protection": {
                "requirement": "Protection and Prevention (Strong cryptographic measures & crypto-agility)",
                "status": "COMPLIANT" if vulnerable_count == 0 else "PARTIALLY_COMPLIANT",
                "legacy_vulnerabilities_found": vulnerable_count
            },
            "article_13_quantum_readiness": {
                "requirement": "Advanced ICT Risk Capabilities & Cryptographic Inventory (CBOM)",
                "cbom_generated": True,
                "pqc_endpoints_tested": len(prober_results),
                "pqc_active_endpoints": pqc_ready_endpoints
            }
        }
