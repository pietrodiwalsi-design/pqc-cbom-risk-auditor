import json

class DashboardGenerator:
    """Generates an interactive standalone HTML Audit Dashboard for PQC & DORA compliance."""

    def generate_html_dashboard(self, cbom: dict, prober_results: list, hndl_score: dict, dora_matrix: dict) -> str:
        crypto_assets = cbom.get("cryptographicAssets", [])
        assets_rows = ""
        for a in crypto_assets:
            status_color = "#ef4444" if "VULNERABLE" in a['pqc_status'] else "#10b981" if "QUANTUM SAFE" in a['pqc_status'] else "#f59e0b"
            assets_rows += f"""
            <tr style="border-bottom: 1px solid #334155;">
              <td style="padding: 10px; color: #f8fafc; font-weight: 600;">{a['algorithm']}</td>
              <td style="padding: 10px; color: #94a3b8;">{a['category']}</td>
              <td style="padding: 10px; color: {status_color}; font-weight: 600;">{a['pqc_status']}</td>
              <td style="padding: 10px; color: #cbd5e1; font-family: monospace;">{a['file']}</td>
              <td style="padding: 10px; color: #f8fafc; text-align: center;">{a['occurrences']}</td>
            </tr>"""

        endpoints_rows = ""
        for p in prober_results:
            # FIX (2026-09-18 review, prober evidence-quality follow-through):
            # a failed probe now reports status != "ok" with
            # negotiated_group/pqc_supported explicitly None. The previous
            # `.get('negotiated_group', 'Classical')` fallback only applied
            # when the KEY was missing, not when its VALUE was None, so a
            # failed probe would have rendered the literal text "None" in
            # this dashboard — the same "silent failure looks like a result"
            # problem the prober fix addresses. Failed probes now render an
            # explicit "No verdict (status)" badge instead of a PQC/NO PQC
            # claim or the word "None".
            status = p.get('status', 'ok')
            if status != 'ok':
                pqc_badge = f"<span style='background: rgba(148,163,184,0.2); color: #94a3b8; padding: 4px 8px; border-radius: 6px; font-weight:700;'>NO VERDICT ({status})</span>"
                group_display = p.get('error_detail') or 'measurement failed'
            else:
                pqc_badge = "<span style='background: rgba(16,185,129,0.2); color: #10b981; padding: 4px 8px; border-radius: 6px; font-weight:700;'>PQC ACTIVE</span>" if p.get('pqc_supported') else "<span style='background: rgba(239,68,68,0.2); color: #ef4444; padding: 4px 8px; border-radius: 6px; font-weight:700;'>NO PQC</span>"
                group_display = p.get('negotiated_group') or 'Classical'
            endpoints_rows += f"""
            <tr style="border-bottom: 1px solid #334155;">
              <td style="padding: 10px; color: #f8fafc; font-weight: 600;">{p.get('host')}</td>
              <td style="padding: 10px;">{pqc_badge}</td>
              <td style="padding: 10px; color: #38bdf8;">{group_display}</td>
              <td style="padding: 10px; color: #94a3b8;">{p.get('latency_ms', 0)} ms</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>PQC & CBOM Risk Auditor — Executive Dashboard</title>
  <style>
    body {{ background: #0b132b; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 30px; margin: 0; }}
    .card {{ background: #1c2541; border: 1px solid #3a506b; border-radius: 12px; padding: 24px; margin-bottom: 24px; box-shadow: 0 4px 16px rgba(0,0,0,0.3); }}
    .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
    .metric-card {{ background: #1e293b; border-radius: 10px; padding: 18px; border-left: 4px solid #38bdf8; }}
    .metric-val {{ font-size: 26px; font-weight: 800; color: #f8fafc; margin-top: 6px; }}
    .metric-lbl {{ font-size: 12px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; }}
    table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 13px; }}
    th {{ background: #0f172a; padding: 12px 10px; color: #38bdf8; font-weight: 700; border-bottom: 2px solid #3a506b; }}
  </style>
</head>
<body>
  <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
    <div>
      <h1 style="margin: 0; font-size: 26px; color: #38bdf8;">🛡️ PQC & CBOM Risk Audit Dashboard</h1>
      <p style="margin: 4px 0 0 0; color: #94a3b8; font-size: 14px;">Compliance Standard: EU DORA (Articles 9 & 13) • NIST FIPS 203/204</p>
    </div>
    <div style="background: #1e293b; padding: 8px 16px; border-radius: 8px; border: 1px solid #38bdf8; font-size: 13px; font-weight: 600; color: #38bdf8;">
      Status: Ready for Regulatory Inspection
    </div>
  </div>

  <div class="grid">
    <div class="metric-card">
      <div class="metric-lbl">HNDL Risk Score</div>
      <div class="metric-val" style="color: {'#ef4444' if hndl_score.get('risk_score_10',0) >= 7 else '#10b981'};">{hndl_score.get('risk_score_10', 0)} / 10</div>
      <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">Tier: {hndl_score.get('risk_level', 'N/A')}</div>
    </div>
    <div class="metric-card" style="border-left-color: #10b981;">
      <div class="metric-lbl">DORA Art. 9 Status</div>
      <div class="metric-val" style="color: #10b981; font-size: 20px; margin-top: 10px;">{dora_matrix.get('article_9_protection',{}).get('status','N/A')}</div>
    </div>
    <div class="metric-card" style="border-left-color: #f59e0b;">
      <div class="metric-lbl">Vulnerable Assets (CBOM)</div>
      <div class="metric-val" style="color: #f59e0b;">{cbom.get('metadata',{}).get('vulnerable_assets_count', 0)}</div>
      <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">Files Scanned: {cbom.get('metadata',{}).get('files_scanned', 0)}</div>
    </div>
    <div class="metric-card" style="border-left-color: #a855f7;">
      <div class="metric-lbl">PQC Hybrid Endpoints</div>
      <div class="metric-val" style="color: #a855f7;">{dora_matrix.get('article_13_quantum_readiness',{}).get('pqc_active_endpoints', 0)} / {len(prober_results)}</div>
    </div>
  </div>

  <div class="card">
    <h2 style="font-size: 17px; margin-top: 0; color: #f8fafc;">📦 Cryptographic Bill of Materials (CBOM) Inventory</h2>
    <table>
      <thead>
        <tr><th>Algorithm</th><th>Category</th><th>PQC Status</th><th>Source File</th><th>Count</th></tr>
      </thead>
      <tbody>{assets_rows if assets_rows else "<tr><td colspan='5' style='padding:15px;text-align:center;'>No cryptographic assets detected.</td></tr>"}</tbody>
    </table>
  </div>

  <div class="card">
    <h2 style="font-size: 17px; margin-top: 0; color: #f8fafc;">🌐 TLS 1.3 Post-Quantum Endpoint Probe Results</h2>
    <table>
      <thead>
        <tr><th>Endpoint Host</th><th>PQC Status</th><th>Negotiated Group / Cipher</th><th>Latency</th></tr>
      </thead>
      <tbody>{endpoints_rows if endpoints_rows else "<tr><td colspan='4' style='padding:15px;text-align:center;'>No endpoint scans recorded.</td></tr>"}</tbody>
    </table>
  </div>
</body>
</html>"""
        return html
