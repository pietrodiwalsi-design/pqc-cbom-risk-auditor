"""
Regression suite for the 2026-09-18 probe evidence-quality review
(fix/probe-evidence-quality branch).

Covers:
  TASK 1 - negotiated_group always reflects the real negotiated group
           (never a discarded "None (Classical fallback)"), with
           pqc_supported kept as a separate boolean, and a psk_only edge case.
  TASK 2 - explicit status taxonomy (ok/dns_error/connect_timeout/tls_alert/
           protocol_error); no risk verdict on any non-ok status; no
           exception ever falls through into a fabricated result.
  TASK 3 - client_offered_groups / probe_client_pqc_capable are always
           present; hndl_risk is fully removed from probe_pqc_endpoint
           output (risk scoring stays in audit_hndl_risk only).
  EVIDENCE ENVELOPE - schema_version, tool_version, timestamp_utc,
           resolved_ip, tls_library_version present on every response.

Unit tests build synthetic raw TLS records by hand so they do not depend
on network access or on any specific server's live configuration (which
can change). A small number of live-network tests are also included,
using example.com / cloudflare.com as the repeat targets per the working
rules; these are skipped automatically if there is no network access in
the test environment (e.g. air-gapped CI).
"""
import socket
import struct
import unittest
import sys

sys.path.insert(0, '/root/repos/pqc-cbom-risk-auditor/src')

from pqc_auditor.prober import (
    TLSProber,
    GROUP_X25519,
    GROUP_X25519_MLKEM768,
    GROUP_SECP256R1,
)


def _server_hello_record(group_id=None, include_psk_ext=False, cipher_suite=0x1301):
    """Builds a minimal, syntactically valid raw TLS record containing a
    ServerHello handshake message with an optional key_share extension
    (given group_id) and/or an optional (empty-body) pre_shared_key
    extension marker. Used to drive TLSProber's ServerHello parser without
    touching the network."""
    extensions = b""
    if group_id is not None:
        # key_share server extension body: just the negotiated group id
        # (server's key_share entry omits the actual key bytes for our
        # parser's purposes - real servers include the key, but the parser
        # only reads the first 2 bytes as the group id).
        ks_body = struct.pack('>H', group_id)
        extensions += struct.pack('>HH', 0x0033, len(ks_body)) + ks_body
    if include_psk_ext:
        extensions += struct.pack('>HH', 0x0029, 0)  # pre_shared_key, empty body

    session_id = b""
    sh_body = (
        struct.pack('>H', 0x0303)            # legacy_version
        + (b'\x77' * 32)                      # random
        + struct.pack('>B', len(session_id)) + session_id
        + struct.pack('>H', cipher_suite)
        + b'\x00'                              # legacy compression method
        + struct.pack('>H', len(extensions)) + extensions
    )
    hs_msg = struct.pack('>B', 2) + struct.pack('>I', len(sh_body))[1:] + sh_body  # type=2 ServerHello
    record = struct.pack('>BHH', 22, 0x0303, len(hs_msg)) + hs_msg  # content_type=22 Handshake
    return record


def _alert_record(level=2, description=40):
    # content_type=21 Alert, body = level(1) + description(1)
    body = struct.pack('>BB', level, description)
    return struct.pack('>BHH', 21, 0x0303, len(body)) + body


class TestTask1NegotiatedGroup(unittest.TestCase):
    """Task 1: always report the real negotiated group; pqc_supported stays
    a separate boolean; psk_only is a distinct explicit value, never None."""

    def setUp(self):
        self.prober = TLSProber()

    def test_classical_x25519_group_reported_by_name_not_none(self):
        record = _server_hello_record(group_id=GROUP_X25519)
        parsed = self.prober._parse_server_hello_or_alert(record)
        self.assertEqual(parsed["status"], "ok")
        self.assertEqual(parsed["group_id"], GROUP_X25519)
        self.assertFalse(parsed["is_psk_only"])

    def test_classical_secp256r1_group_reported_by_name(self):
        record = _server_hello_record(group_id=GROUP_SECP256R1)
        parsed = self.prober._parse_server_hello_or_alert(record)
        self.assertEqual(parsed["status"], "ok")
        self.assertEqual(parsed["group_id"], GROUP_SECP256R1)

    def test_pqc_group_still_recognised(self):
        record = _server_hello_record(group_id=GROUP_X25519_MLKEM768)
        parsed = self.prober._parse_server_hello_or_alert(record)
        self.assertEqual(parsed["status"], "ok")
        self.assertEqual(parsed["group_id"], GROUP_X25519_MLKEM768)

    def test_psk_only_resumption_returns_psk_only_not_none(self):
        # No key_share extension at all, only pre_shared_key -> pure PSK
        # resumption, no key exchange to name.
        record = _server_hello_record(group_id=None, include_psk_ext=True)
        parsed = self.prober._parse_server_hello_or_alert(record)
        self.assertEqual(parsed["status"], "ok")
        self.assertTrue(parsed["is_psk_only"])
        self.assertIsNone(parsed["group_id"])

    def test_full_probe_result_never_uses_the_literal_string_none(self):
        """End-to-end guard: build_result's negotiated_group must never be
        the discarded literal 'None (Classical fallback)' string that
        prompted this fix."""
        result = self.prober._build_result(
            "example.com", 443, "ok", None, "93.184.216.34", ["x25519"], True, 0.0,
            negotiated_group="x25519", pqc_supported=False,
        )
        self.assertEqual(result["negotiated_group"], "x25519")
        self.assertNotEqual(result["negotiated_group"], "None (Classical fallback)")
        self.assertIs(result["pqc_supported"], False)  # separate boolean field, not overloaded


class TestTask2ErrorTaxonomy(unittest.TestCase):
    """Task 2: exactly 5 status values; no risk verdict except on status=ok;
    error_detail always populated on failure; exceptions never produce a
    fabricated negative PQC result."""

    VALID_STATUSES = {"ok", "dns_error", "connect_timeout", "tls_alert", "protocol_error"}

    def setUp(self):
        self.prober = TLSProber()

    def test_dns_failure_yields_dns_error_with_no_verdict(self):
        result = self.prober.probe_endpoint("this-host-does-not-exist-abcxyz123.invalid", timeout=3.0)
        self.assertEqual(result["status"], "dns_error")
        self.assertIsInstance(result["error_detail"], str)
        self.assertIsNone(result["negotiated_group"])
        self.assertIsNone(result["pqc_supported"])

    def test_connect_refused_yields_connect_timeout_with_no_verdict(self):
        # Port 1 on loopback: nothing listens there in this sandbox, so the
        # kernel replies with an immediate RST (ConnectionRefusedError),
        # which the working rules' "a closed port -> connect_timeout"
        # acceptance criterion maps to this status bucket.
        result = self.prober.probe_endpoint("127.0.0.1", port=1, timeout=3.0)
        self.assertEqual(result["status"], "connect_timeout")
        self.assertIsNone(result["negotiated_group"])
        self.assertIsNone(result["pqc_supported"])

    def test_alert_response_yields_tls_alert_status_no_verdict(self):
        record = _alert_record(level=2, description=40)
        parsed = self.prober._parse_server_hello_or_alert(record)
        self.assertEqual(parsed["status"], "tls_alert")
        self.assertIsInstance(parsed["error_detail"], str)
        self.assertIsNone(parsed["group_id"])

    def test_garbage_response_yields_protocol_error_not_a_verdict(self):
        parsed = self.prober._parse_server_hello_or_alert(b"\x00\x01\x02garbage-not-tls")
        self.assertEqual(parsed["status"], "protocol_error")
        self.assertIsNone(parsed["group_id"])

    def test_empty_response_yields_protocol_error(self):
        parsed = self.prober._parse_server_hello_or_alert(b"")
        self.assertEqual(parsed["status"], "protocol_error")

    def test_all_result_statuses_are_within_the_fixed_taxonomy(self):
        cases = [
            self.prober.probe_endpoint("this-host-does-not-exist-abcxyz123.invalid", timeout=3.0),
            self.prober.probe_endpoint("127.0.0.1", port=1, timeout=3.0),
        ]
        for res in cases:
            self.assertIn(res["status"], self.VALID_STATUSES)

    def test_non_ok_status_never_carries_a_risk_verdict(self):
        for res in [
            self.prober.probe_endpoint("this-host-does-not-exist-abcxyz123.invalid", timeout=3.0),
            self.prober.probe_endpoint("127.0.0.1", port=1, timeout=3.0),
        ]:
            if res["status"] != "ok":
                self.assertIsNone(res["negotiated_group"], f"status={res['status']} leaked a verdict")
                self.assertIsNone(res["pqc_supported"], f"status={res['status']} leaked a verdict")


class TestTask3SelfValidatingMeasurement(unittest.TestCase):
    """Task 3: client_offered_groups / probe_client_pqc_capable present on
    every response; hndl_risk fully removed from probe output."""

    def setUp(self):
        self.prober = TLSProber()

    def test_client_offered_groups_present_even_on_failure(self):
        result = self.prober.probe_endpoint("this-host-does-not-exist-abcxyz123.invalid", timeout=3.0)
        self.assertIn("client_offered_groups", result)
        self.assertIsInstance(result["client_offered_groups"], list)
        self.assertGreater(len(result["client_offered_groups"]), 0)
        self.assertIn("probe_client_pqc_capable", result)

    def test_offered_groups_include_at_least_one_pqc_group(self):
        result = self.prober.probe_endpoint("this-host-does-not-exist-abcxyz123.invalid", timeout=3.0)
        self.assertTrue(result["probe_client_pqc_capable"])
        self.assertTrue(any("MLKEM" in g or "Kyber" in g for g in result["client_offered_groups"]))

    def test_hndl_risk_field_is_fully_removed_from_probe_output(self):
        result = self.prober.probe_endpoint("this-host-does-not-exist-abcxyz123.invalid", timeout=3.0)
        self.assertNotIn("hndl_risk", result)

    def test_hndl_risk_removed_via_mcp_server_probe_tool_too(self):
        from pqc_auditor.mcp_server import handle_request
        import json
        resp = handle_request({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "probe_pqc_endpoint", "arguments": {"host": "this-host-does-not-exist-abcxyz123.invalid"}}
        })
        out = json.loads(resp["result"]["content"][0]["text"])
        self.assertNotIn("hndl_risk", out)


class TestEvidenceEnvelope(unittest.TestCase):
    """Every probe response must carry schema_version, tool_version,
    timestamp_utc (ISO 8601), resolved_ip, tls_library_version — including
    on failure paths, where resolved_ip may legitimately be None (e.g. a
    DNS failure never resolves an IP) but the other 4 fields must still be
    present and correctly typed."""

    def setUp(self):
        self.prober = TLSProber()

    def test_envelope_fields_present_on_success_and_failure(self):
        results = [
            self.prober.probe_endpoint("this-host-does-not-exist-abcxyz123.invalid", timeout=3.0),
            self.prober.probe_endpoint("127.0.0.1", port=1, timeout=3.0),
        ]
        for res in results:
            self.assertEqual(res["schema_version"], TLSProber.SCHEMA_VERSION)
            self.assertIsInstance(res["tool_version"], str)
            self.assertIsInstance(res["timestamp_utc"], str)
            # Must parse as ISO 8601.
            import datetime
            datetime.datetime.fromisoformat(res["timestamp_utc"])
            self.assertIsInstance(res["tls_library_version"], str)
            self.assertIn("resolved_ip", res)

    def test_dns_failure_never_resolves_an_ip(self):
        res = self.prober.probe_endpoint("this-host-does-not-exist-abcxyz123.invalid", timeout=3.0)
        self.assertIsNone(res["resolved_ip"])


class TestDashboardFailedProbeRendering(unittest.TestCase):
    """The dashboard's `.get('negotiated_group', 'Classical')` fallback only
    applied when the key was MISSING, not when its value was explicitly
    None (which now happens on any failed probe per Task 2). Verifies the
    dashboard renders an explicit no-verdict state instead of the literal
    text "None"."""

    def test_failed_probe_does_not_render_the_word_none(self):
        from pqc_auditor.dashboard_generator import DashboardGenerator
        gen = DashboardGenerator()
        html = gen.generate_html_dashboard(
            cbom={"metadata": {"vulnerable_assets_count": 0, "files_scanned": 1}, "cryptographicAssets": []},
            prober_results=[{
                "host": "broken.example.invalid", "status": "dns_error",
                "error_detail": "[Errno -2] Name or service not known",
                "negotiated_group": None, "pqc_supported": None, "latency_ms": 1.2,
            }],
            hndl_score={"risk_score_10": 0, "risk_level": "N/A"},
            dora_matrix={"article_9_protection": {"status": "COMPLIANT"}, "article_13_quantum_readiness": {"pqc_active_endpoints": 0}},
        )
        # The row must not contain a bare "None" as the rendered group value.
        self.assertNotIn(">None<", html)
        self.assertIn("NO VERDICT", html)
        self.assertIn("dns_error", html)


class TestLiveNetworkRepeatTargets(unittest.TestCase):
    """Live confirmation against the two repeat test targets specified in
    the working rules (example.com, cloudflare.com). Skips gracefully if
    the sandbox has no outbound network access, rather than failing the
    whole suite in an offline CI environment."""

    def setUp(self):
        self.prober = TLSProber()

    def _require_network(self):
        try:
            socket.create_connection(("example.com", 443), timeout=3.0).close()
        except OSError:
            self.skipTest("no outbound network access in this environment")

    def test_example_com_reports_ok_with_full_envelope(self):
        self._require_network()
        res = self.prober.probe_endpoint("example.com")
        self.assertEqual(res["status"], "ok")
        self.assertIsNotNone(res["negotiated_group"])
        self.assertIn(res["negotiated_group"], ("x25519", "secp256r1", "X25519MLKEM768", "X25519Kyber768Draft00", "SecP256r1MLKEM768", "psk_only"))
        self.assertIsInstance(res["pqc_supported"], bool)
        self.assertIsNotNone(res["resolved_ip"])

    def test_cloudflare_com_reports_ok_with_full_envelope(self):
        self._require_network()
        res = self.prober.probe_endpoint("cloudflare.com")
        self.assertEqual(res["status"], "ok")
        self.assertIsNotNone(res["negotiated_group"])
        self.assertIsInstance(res["pqc_supported"], bool)


if __name__ == '__main__':
    unittest.main()
