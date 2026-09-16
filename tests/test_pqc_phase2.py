import unittest
import sys
sys.path.insert(0, '/root/repos/pqc-cbom-risk-auditor/src')

from pqc_auditor.cbom_parser import CBOMParser
from pqc_auditor.dashboard_generator import DashboardGenerator
from pqc_auditor.hndl_engine import HNDLEngine
from pqc_auditor.dora_compliance import DORAComplianceExporter

class TestPQCPhase2(unittest.TestCase):
    def test_multi_language_cbom(self):
        parser = CBOMParser()
        cbom = parser.scan_directory('/root/repos/pqc-cbom-risk-auditor')
        self.assertIn("metadata", cbom)
        self.assertGreaterEqual(cbom["metadata"]["files_scanned"], 1)

    def test_dashboard_generator(self):
        gen = DashboardGenerator()
        html = gen.generate_html_dashboard(
            cbom={"metadata": {"vulnerable_assets_count": 0, "files_scanned": 10}, "cryptographicAssets": []},
            prober_results=[{"host": "pq.cloudflareresearch.com", "pqc_supported": True, "negotiated_group": "X25519MLKEM768"}],
            hndl_score={"risk_score_10": 2.0, "risk_level": "LOW"},
            dora_matrix={"article_9_protection": {"status": "COMPLIANT"}, "article_13_quantum_readiness": {"pqc_active_endpoints": 1}}
        )
        self.assertIn("PQC & CBOM Risk Audit Dashboard", html)
        self.assertIn("X25519MLKEM768", html)

if __name__ == '__main__':
    unittest.main()
