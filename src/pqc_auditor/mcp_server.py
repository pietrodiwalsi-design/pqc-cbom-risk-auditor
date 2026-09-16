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
        "description": "Performs a live TLS 1.3 Handshake probe to test for NIST FIPS 203 ML-KEM-768 quantum resilience.",
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
        tool_name = params.get("name")
        args = params.get("arguments", {})

        if tool_name == "probe_pqc_endpoint":
            prober = TLSProber()
            res = prober.probe_endpoint(args.get("host"), args.get("port", 443))
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": json.dumps(res, indent=2)}], "isError": False}
            }
        elif tool_name == "scan_cbom_repository":
            parser = CBOMParser()
            res = parser.scan_directory(args.get("repo_path"))
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": json.dumps(res, indent=2)}], "isError": False}
            }
        elif tool_name == "audit_hndl_risk":
            hndl = HNDLEngine()
            res = hndl.calculate_hndl_score(args.get("retention_years", 15))
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": json.dumps(res, indent=2)}], "isError": False}
            }
        else:
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": f"Unknown tool: {tool_name}"}}
    else:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            resp = handle_request(req)
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
        except Exception as e:
            err = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(e)}}
            sys.stdout.write(json.dumps(err) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
