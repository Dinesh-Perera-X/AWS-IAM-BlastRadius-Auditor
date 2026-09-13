import json
from datetime import datetime
from typing import Dict, Any, List

class BlastRadiusReporter:
    """
    Exports IAM risk metrics to SIEM-compatible JSON
    and generates visual HTML audit reports.
    """

    @staticmethod
    def export_json(audit_result: Dict[str, Any], filepath: str = "iam_blast_radius_report.json") -> None:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(audit_result, f, indent=2)

    @staticmethod
    def export_html(audit_result: Dict[str, Any], filepath: str = "iam_blast_radius_dossier.html") -> None:
        radius = audit_result["blast_radius"]
        score = radius["score"]
        sev = radius["severity"]
        score_color = "#ef4444" if score >= 75 else "#f59e0b" if score >= 40 else "#10b981"

        privesc_rows = ""
        for p in audit_result.get("privesc_findings", []):
            privesc_rows += f"""
            <tr>
                <td><code>{p['id']}</code></td>
                <td><strong>{p['name']}</strong></td>
                <td><span class="badge badge-critical">{p['severity']}</span></td>
                <td><code style="color: #38bdf8;">{p['mitre_id']}</code></td>
                <td>{p['description']}</td>
            </tr>
            """

        wildcard_rows = ""
        for w in audit_result.get("wildcard_findings", []):
            wildcard_rows += f"""
            <tr>
                <td>Statement #{w['statement_index']}</td>
                <td><code>{w['issue']}</code></td>
                <td><span class="badge {'badge-critical' if w['severity'] == 'CRITICAL' else 'badge-high'}">{w['severity']}</span></td>
                <td>{w['description']}</td>
            </tr>
            """

        factors_html = "".join([f"<li>{f}</li>" for f in radius["contributing_factors"]])

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS IAM Blast Radius Audit Dossier</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 30px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ border-bottom: 2px solid #334155; padding-bottom: 20px; margin-bottom: 25px; }}
        .header h1 {{ margin: 0 0 8px 0; color: #38bdf8; font-size: 26px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 30px; }}
        .stat-card {{ background: #1e293b; padding: 18px; border-radius: 8px; border-left: 4px solid #38bdf8; }}
        .stat-card.critical {{ border-left-color: #ef4444; }}
        .stat-val {{ font-size: 28px; font-weight: bold; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; font-size: 14px; margin-bottom: 25px; }}
        th, td {{ padding: 14px 16px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0f172a; color: #94a3b8; text-transform: uppercase; font-size: 12px; letter-spacing: 0.05em; }}
        tr:hover {{ background: #243248; }}
        .badge {{ padding: 4px 10px; border-radius: 9999px; font-weight: bold; font-size: 11px; }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid #ef4444; }}
        .badge-high {{ background: rgba(245, 158, 11, 0.2); color: #fcd34d; border: 1px solid #f59e0b; }}
        .panel {{ background: #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 25px; border-left: 4px solid {score_color}; }}
        ul {{ margin: 0; padding-left: 20px; color: #cbd5e1; }}
        li {{ margin-bottom: 6px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>☁️ AWS IAM Blast Radius & CIEM Forensic Dossier</h1>
            <div style="color: #94a3b8; font-size: 13px;">Target: {audit_result.get('target', 'IAM Policy')} | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%SZ')}</div>
        </div>

        <div class="stats-grid">
            <div class="stat-card critical">
                <div style="color: #94a3b8; font-size: 13px;">Blast Radius Score</div>
                <div class="stat-val" style="color: {score_color};">{score}/100</div>
            </div>
            <div class="stat-card">
                <div style="color: #94a3b8; font-size: 13px;">Risk Classification</div>
                <div class="stat-val" style="color: {score_color};">{sev}</div>
            </div>
            <div class="stat-card">
                <div style="color: #94a3b8; font-size: 13px;">PrivEsc Paths</div>
                <div class="stat-val" style="color: #38bdf8;">{len(audit_result.get('privesc_findings', []))}</div>
            </div>
            <div class="stat-card">
                <div style="color: #94a3b8; font-size: 13px;">Wildcard Grants</div>
                <div class="stat-val" style="color: #f59e0b;">{len(audit_result.get('wildcard_findings', []))}</div>
            </div>
        </div>

        <div class="panel">
            <h3 style="margin: 0 0 10px 0; color: #38bdf8;">Impact Justifications & Exposure Summary</h3>
            <ul>{factors_html}</ul>
        </div>

        <h3 style="color: #ef4444;">🚨 Viable Privilege Escalation Vectors</h3>
        <table>
            <thead>
                <tr>
                    <th>Rule ID</th>
                    <th>Attack Vector</th>
                    <th>Severity</th>
                    <th>MITRE ID</th>
                    <th>Exploitation Mechanism</th>
                </tr>
            </thead>
            <tbody>
                {privesc_rows if privesc_rows else '<tr><td colspan="5" style="text-align: center; color: #10b981;">No privilege escalation paths detected.</td></tr>'}
            </tbody>
        </table>

        <h3 style="color: #38bdf8;">🔍 Wildcard & Boundary Violations</h3>
        <table>
            <thead>
                <tr>
                    <th>Scope</th>
                    <th>Issue Type</th>
                    <th>Severity</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                {wildcard_rows if wildcard_rows else '<tr><td colspan="4" style="text-align: center; color: #10b981;">No unrestricted wildcards detected.</td></tr>'}
            </tbody>
        </table>
    </div>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_template)
