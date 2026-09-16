import unittest
import sys
sys.path.insert(0, '/root/repos/pqc-cbom-risk-auditor/src')

from pqc_auditor.prober import TLSProber
from pqc_auditor.cbom_parser import CBOMParser
from pqc_auditor.hndl_engine import HNDLEngine
from pqc_auditor.dora_compliance import DORAComplianceExporter

class TestPQCAuditor(unittest.TestCase):
    def test_hndl_engine(self):
        engine = HNDLEngine()
        res = engine.calculate_hndl_score(25)
        self.assertEqual(res["risk_level"], "CRITICAL")
        self.assertTrue(res["hndl_vulnerable"])

    def test_cbom_parser(self):
        parser = CBOMParser()
        cbom = parser.scan_directory('/root/repos/pqc-cbom-risk-auditor')
        self.assertEqual(cbom["bomFormat"], "CycloneDX")
        self.assertEqual(cbom["specVersion"], "1.6")

    def test_dora_compliance(self):
        exporter = DORAComplianceExporter()
        matrix = exporter.generate_dora_matrix({"cryptographicAssets": []}, [])
        self.assertEqual(matrix["article_9_protection"]["status"], "COMPLIANT")

if __name__ == '__main__':
    unittest.main()
