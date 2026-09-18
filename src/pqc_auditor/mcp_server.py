#!/usr/bin/env python3
"""
PQC & CBOM Risk Auditor — Model Context Protocol (MCP) Server.
Enables Claude Desktop, Cursor, and OpenClaw to execute live PQC TLS and CBOM audits.
"""

import sys
import os
import json
from pqc_auditor.prober import TLSProber
from pqc_auditor.cbom_parser import CBOMParser
from pqc_auditor.hndl_engine import HNDLEngine
from pqc_auditor.dora_compliance import DORAComplianceExporter

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {
    "name": "pqc-cbom-risk-auditor-mcp",
    "version": "1.0.0"
}

TOOLS = [
    {
        "name": "probe_pqc_endpoint",
        "description": (
            "Performs a live TLS 1.3 Handshake probe to test for NIST FIPS 203 ML-KEM-768 quantum resilience. "
            "Response always includes a 'status' field (ok | dns_error | connect_timeout | tls_alert | protocol_error); "
            "'negotiated_group' and 'pqc_supported' are null unless status='ok' — a failed measurement never yields "
            "a risk verdict. 'negotiated_group' reports the real negotiated TLS group (e.g. x25519, secp256r1, "
            "X25519MLKEM768, or psk_only for PSK-only resumption), never a discarded classical placeholder. "
            "HNDL/Harvest-Now-Decrypt-Later risk scoring is NOT computed here — use the separate 'audit_hndl_risk' tool."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Target domain hostname (e.g. mijn.nn.nl)"},
                "port": {"type": "integer", "default": 443, "description": "Port number"}
            },
            "required": ["host"]
        }
    },
    {
        "name": "scan_cbom_repository",
        "description": "Scans a software repository to extract a CycloneDX 1.6+ Cryptographic Bill of Materials (CBOM).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {"type": "string", "description": "Local path to repository"}
            },
            "required": ["repo_path"]
        }
    },
    {
        "name": "audit_hndl_risk",
        "description": "Calculates Harvest Now, Decrypt Later (HNDL) risk score under EU DORA based on data retention years.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "retention_years": {"type": "integer", "description": "Data shelf-life retention period in years"}
            },
            "required": ["retention_years"]
        }
    }
]

def handle_request(req):
    req_id = req.get("id")
    method = req.get("method")
    params = req.get("params", {})

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO
            }
        }
    elif method == "notifications/initialized":
        return None
    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": TOOLS}
        }
    elif method == "tools/call":
        if not isinstance(params, dict):
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Invalid params: expected object"}}
        tool_name = params.get("name")
        args = params.get("arguments", {}) or {}
        if not isinstance(args, dict):
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Invalid params: 'arguments' must be an object"}}

        try:
            if tool_name == "probe_pqc_endpoint":
                host = args.get("host")
                if not isinstance(host, str) or not host.strip():
                    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Invalid params: 'host' is required and must be a non-empty string"}}
                port = args.get("port", 443)
                if not isinstance(port, int) or isinstance(port, bool) or not (0 < port < 65536):
                    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Invalid params: 'port' must be an integer between 1 and 65535"}}
                prober = TLSProber()
                res = prober.probe_endpoint(host, port)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(res, indent=2)}], "isError": False}
                }
            elif tool_name == "scan_cbom_repository":
                repo_path = args.get("repo_path")
                if not isinstance(repo_path, str) or not repo_path.strip():
                    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Invalid params: 'repo_path' is required and must be a non-empty string"}}
                resolved = os.path.realpath(repo_path)
                if not os.path.isdir(resolved):
                    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": f"Invalid params: 'repo_path' does not exist or is not a directory: {repo_path}"}}
                parser = CBOMParser()
                res = parser.scan_directory(resolved)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(res, indent=2)}], "isError": False}
                }
            elif tool_name == "audit_hndl_risk":
                retention_years = args.get("retention_years", 15)
                if not isinstance(retention_years, int) or isinstance(retention_years, bool) or retention_years < 0:
                    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Invalid params: 'retention_years' must be a non-negative integer"}}
                hndl = HNDLEngine()
                res = hndl.calculate_hndl_score(retention_years)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(res, indent=2)}], "isError": False}
                }
            else:
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": f"Unknown tool: {tool_name}"}}
        except Exception as e:
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32603, "message": f"Internal error executing tool '{tool_name}': {str(e)}"}}
    else:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req_id = None
        try:
            req = json.loads(line)
            if isinstance(req, dict):
                req_id = req.get("id")
            if not isinstance(req, dict) or req.get("jsonrpc") != "2.0" or "method" not in req:
                err = {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32600, "message": "Invalid Request: not a valid JSON-RPC 2.0 request object"}}
                sys.stdout.write(json.dumps(err) + "\n")
                sys.stdout.flush()
                continue
            resp = handle_request(req)
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
        except json.JSONDecodeError as e:
            err = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"Parse error: {str(e)}"}}
            sys.stdout.write(json.dumps(err) + "\n")
            sys.stdout.flush()
        except Exception as e:
            err = {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32603, "message": f"Internal error: {str(e)}"}}
            sys.stdout.write(json.dumps(err) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
