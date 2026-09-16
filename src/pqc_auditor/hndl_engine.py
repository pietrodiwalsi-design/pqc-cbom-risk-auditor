class HNDLEngine:
    """Calculates Harvest Now, Decrypt Later (HNDL) risk exposure using Mosca Theorem."""

    def calculate_hndl_score(self, retention_years: int, y2q_horizon_years: int = 7) -> dict:
        """
        Mosca's Theorem: If Data Shelf Life (X) + Migration Time (Y) > Quantum Horizon (Z),
        then system is immediately vulnerable to retrospective decryption.
        """
        shelf_life_vulnerability = retention_years > y2q_horizon_years
        
        if retention_years >= 20:
            risk_level = "CRITICAL"
            score = 9.5
        elif retention_years >= 10:
            risk_level = "HIGH"
            score = 8.0
        elif retention_years >= 5:
            risk_level = "MEDIUM"
            score = 5.5
        else:
            risk_level = "LOW"
            score = 2.0

        return {
            "retention_years": retention_years,
            "y2q_horizon_years": y2q_horizon_years,
            "hndl_vulnerable": shelf_life_vulnerability,
            "risk_level": risk_level,
            "risk_score_10": score,
            "recommendation": "Migrate to NIST FIPS 203 ML-KEM-768 hybrid key exchange immediately" if shelf_life_vulnerability else "Monitor standard PQC transition timelines"
        }
