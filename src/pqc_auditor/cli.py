import sys
import json
import argparse
from pqc_auditor.prober import TLSProber
from pqc_auditor.cbom_parser import CBOMParser
from pqc_auditor.hndl_engine import HNDLEngine
from pqc_auditor.dora_compliance import DORAComplianceExporter

def main():
    parser = argparse.ArgumentParser(description="PQC & CBOM Risk Auditor CLI")
    subparsers = parser.add_subparsers(dest="command")

    # Probe
    probe_p = subparsers.add_parser("probe", help="Probe TLS endpoint for PQC ML-KEM support")
    probe_p.add_argument("--host", required=True, help="Target hostname")
    probe_p.add_argument("--port", type=int, default=443, help="Port")

    # Scan Repo
    scan_p = subparsers.add_parser("scan-repo", help="Scan repository for Cryptographic Bill of Materials (CBOM)")
    scan_p.add_argument("--path", required=True, help="Repository directory path")

    # Audit
    audit_p = subparsers.add_parser("audit", help="Run full HNDL and DORA compliance audit")
    audit_p.add_argument("--retention-years", type=int, default=15, help="Data retention shelf-life")

    args = parser.parse_args()

    if args.command == "probe":
        prober = TLSProber()
        res = prober.probe_endpoint(args.host, args.port)
        print(json.dumps(res, indent=2))
    elif args.command == "scan-repo":
        parser_cbom = CBOMParser()
        cbom = parser_cbom.scan_directory(args.path)
        print(json.dumps(cbom, indent=2))
    elif args.command == "audit":
        hndl = HNDLEngine()
        score = hndl.calculate_hndl_score(args.retention_years)
        print(json.dumps(score, indent=2))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
