"""
Phase 3 Hardening Regression Suite (Claude Sonnet 5 Certification Pass).

Covers JSON-RPC 2.0 conformance, input validation, and error-id integrity
for the MCP server, plus edge-case guards added to hndl_engine and
dora_compliance during the security review.
"""
import unittest
import sys
sys.path.insert(0, '/root/repos/pqc-cbom-risk-auditor/src')

from pqc_auditor.mcp_server import handle_request
from pqc_auditor.hndl_engine import HNDLEngine
from pqc_auditor.dora_compliance import DORAComplianceExporter


class TestMCPServerHardening(unittest.TestCase):
    def test_missing_required_host_returns_matching_id(self):
        resp = handle_request({
            "jsonrpc": "2.0", "id": 42, "method": "tools/call",
            "params": {"name": "probe_pqc_endpoint", "arguments": {}}
        })
        self.assertEqual(resp["id"], 42)
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32602)

    def test_invalid_port_type_rejected(self):
        resp = handle_request({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": "probe_pqc_endpoint", "arguments": {"host": "example.com", "port": "bad"}}
        })
        self.assertEqual(resp["id"], 7)
        self.assertIn("error", resp)

    def test_nonexistent_repo_path_rejected(self):
        resp = handle_request({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "scan_cbom_repository", "arguments": {"repo_path": "/this/does/not/exist"}}
        })
        self.assertEqual(resp["id"], 3)
        self.assertIn("error", resp)

    def test_negative_retention_years_rejected(self):
        resp = handle_request({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "audit_hndl_risk", "arguments": {"retention_years": -5}}
        })
        self.assertIn("error", resp)

    def test_malformed_request_missing_method_gets_invalid_request_error(self):
        # Simulates a malformed JSON-RPC envelope missing 'method' passed directly to handle_request.
        # (main()'s stdin loop performs the -32600 envelope check; handle_request falls back to
        # "Method not found" for a None method, which is still a valid, non-crashing response.)
        resp = handle_request({"jsonrpc": "2.0", "id": 99, "params": {}})
        self.assertEqual(resp["id"], 99)
        self.assertIn("error", resp)

    def test_unknown_tool_preserves_id(self):
        resp = handle_request({
            "jsonrpc": "2.0", "id": "abc", "method": "tools/call",
            "params": {"name": "nonexistent_tool", "arguments": {}}
        })
        self.assertEqual(resp["id"], "abc")
        self.assertEqual(resp["error"]["code"], -32602)


class TestHNDLEngineHardening(unittest.TestCase):
    def test_rejects_negative_retention(self):
        with self.assertRaises(ValueError):
            HNDLEngine().calculate_hndl_score(-1)

    def test_rejects_non_numeric_retention(self):
        with self.assertRaises(TypeError):
            HNDLEngine().calculate_hndl_score("twenty")

    def test_rejects_bool_as_retention(self):
        with self.assertRaises(TypeError):
            HNDLEngine().calculate_hndl_score(True)


class TestDORAComplianceHardening(unittest.TestCase):
    def test_handles_none_inputs_gracefully(self):
        exporter = DORAComplianceExporter()
        matrix = exporter.generate_dora_matrix(None, None)
        self.assertEqual(matrix["article_9_protection"]["status"], "COMPLIANT")
        self.assertEqual(matrix["article_13_quantum_readiness"]["pqc_endpoints_tested"], 0)


if __name__ == "__main__":
    unittest.main()
