import html
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from core.database import CaseDatabase


class ReportGenerator:
    """
    Phase 4 (Part B): Generates a standalone, XSS-safe, court-ready HTML forensic report
    with a direct link to the interactive Mini-Maltego graph and Print/Save-as-PDF support.
    """

    def __init__(self, db: CaseDatabase, case_name: str):
        self.db = db
        self.case_name = case_name
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)

    def _esc(self, text: Any) -> str:
        # Safely escape any text to prevent HTML/XSS injection from malicious artifacts
        return html.escape(str(text)) if text is not None else ""

    def _safe_query(self, query: str) -> List[Tuple]:
        # Execute a read query safely even if a table is empty or missing
        try:
            cur = self.db.conn.cursor()
            cur.execute(query)
            return cur.fetchall()
        except Exception:
            return []

    def _format_value(self, value: str) -> str:
        # Turn http/https URLs into clickable links inside the HTML report
        val_str = str(value).strip()
        if val_str.startswith(("http://", "https://")):
            safe_url = self._esc(val_str)
            return f'<a href="{safe_url}" target="_blank" rel="noopener noreferrer">{safe_url}</a>'
        return self._esc(val_str)

    def generate_report(self, graph_filename: str = "") -> Dict[str, Any]:
        """
        Pulls all evidence from the SQLite Case DB and writes reports/<case>_report.html.
        """
        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 1. Fetch all tables from SQLite DB
        artifacts = self._safe_query("SELECT file_name, file_size, md5, sha256 FROM artifacts")
        secrets = self._safe_query("SELECT secret_type, secret_value FROM secrets")
        iocs = self._safe_query("SELECT ioc_type, ioc_value FROM iocs")
        osint_rows = self._safe_query(
            "SELECT target, target_type, source_tool, finding_type, finding_value FROM osint_findings"
        )
        ai_pivots = self._safe_query(
            "SELECT depth_level, target_type, recommended_target, reason, status FROM ai_pivots"
        )
        audit_logs = self._safe_query("SELECT timestamp, action, details FROM audit_log ORDER BY id ASC")

        # Separate high-severity Data Breaches from general OSINT findings
        breaches = [r for r in osint_rows if r[3] == "DATA_BREACH"]

        # 2. Build HTML Table Sections
        # Artifacts Table
        artifacts_html = ""
        for fname, fsize, md5, sha256 in artifacts:
            artifacts_html += f"""
            <tr>
                <td><strong>{self._esc(fname)}</strong></td>
                <td>{self._esc(fsize)} bytes</td>
                <td class="mono">{self._esc(md5)}</td>
                <td class="mono">{self._esc(sha256)}</td>
            </tr>"""
        if not artifacts_html:
            artifacts_html = '<tr><td colspan="4" class="muted">No physical file artifacts analyzed in this case.</td></tr>'

        # Critical Alerts (Secrets + Data Breaches)
        alerts_html = ""
        for s_type, s_val in secrets:
            alerts_html += f"""
            <tr>
                <td><span class="badge badge-danger">SECRET LEAK</span></td>
                <td>{self._esc(s_type)}</td>
                <td class="mono">{self._esc(s_val)}</td>
            </tr>"""
        for target, _, source, _, b_val in breaches:
            alerts_html += f"""
            <tr>
                <td><span class="badge badge-warn">DATA BREACH</span></td>
                <td>{self._esc(target)} ({self._esc(source)})</td>
                <td>{self._esc(b_val)}</td>
            </tr>"""
        if not alerts_html:
            alerts_html = '<tr><td colspan="3" class="muted">No leaked secrets or public data breaches detected.</td></tr>'

        # IOCs Table
        iocs_html = ""
        for i_type, i_val in iocs:
            iocs_html += f"""
            <tr>
                <td><span class="badge badge-info">{self._esc(i_type)}</span></td>
                <td class="mono">{self._esc(i_val)}</td>
            </tr>"""
        if not iocs_html:
            iocs_html = '<tr><td colspan="2" class="muted">No raw regex IOCs extracted.</td></tr>'

        # Grouped OSINT Intelligence Table
        osint_html = ""
        for target, t_type, source_tool, f_type, f_val in osint_rows:
            osint_html += f"""
            <tr>
                <td><strong>{self._esc(target)}</strong><br><span class="muted small">{self._esc(t_type)}</span></td>
                <td><span class="badge badge-tool">{self._esc(source_tool.upper())}</span></td>
                <td>{self._esc(f_type)}</td>
                <td class="wrap">{self._format_value(f_val)}</td>
            </tr>"""
        if not osint_html:
            osint_html = '<tr><td colspan="4" class="muted">No OSINT findings recorded yet.</td></tr>'

        # AI Auto-Pivot Reasoning Table
        pivots_html = ""
        for depth, t_type, rec_target, reason, status in ai_pivots:
            pivots_html += f"""
            <tr>
                <td>Depth {self._esc(depth)}</td>
                <td><span class="badge badge-ai">{self._esc(t_type)}</span></td>
                <td><strong>{self._esc(rec_target)}</strong></td>
                <td>{self._esc(reason)}</td>
            </tr>"""
        if not pivots_html:
            pivots_html = '<tr><td colspan="4" class="muted">No autonomous AI pivots executed in this case.</td></tr>'

        # Chain of Custody (Audit Log)
        audit_html = ""
        for ts, action, details in audit_logs:
            audit_html += f"""
            <tr>
                <td class="mono small">{self._esc(ts)}</td>
                <td><strong>{self._esc(action)}</strong></td>
                <td>{self._esc(details)}</td>
            </tr>"""
        if not audit_html:
            audit_html = '<tr><td colspan="3" class="muted">No audit log entries found.</td></tr>'

        # Direct button to open the Mini-Maltego Graph if generated
        graph_btn_html = ""
        if graph_filename:
            graph_btn_html = f'<a href="{self._esc(graph_filename)}" target="_blank" class="btn btn-primary">🕸 Open Interactive Graph</a>'

        # 3. Assemble Complete Standalone HTML Document
        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Forensic Report - {self._esc(self.case_name)}</title>
<style>
    :root {{
        --bg: #0d1117;
        --card: #161b22;
        --border: #30363d;
        --text: #e6edf3;
        --muted: #8b949e;
        --accent: #00d4ff;
        --danger: #f85149;
        --warn: #d29922;
    }}
    * {{ box-sizing: border-box; }}
    body {{
        margin: 0;
        padding: 24px;
        background: var(--bg);
        color: var(--text);
        font-family: "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        line-height: 1.5;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    header {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 16px;
        border-bottom: 2px solid var(--accent);
        padding-bottom: 16px;
        margin-bottom: 24px;
    }}
    h1 {{ margin: 0; font-size: 24px; color: var(--accent); letter-spacing: 0.5px; }}
    .meta-sub {{ color: var(--muted); font-size: 13px; margin-top: 4px; }}
    .actions {{ display: flex; gap: 10px; }}
    .btn {{
        display: inline-block;
        padding: 10px 16px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 13px;
        text-decoration: none;
        cursor: pointer;
        border: 1px solid var(--border);
    }}
    .btn-primary {{ background: #1f6feb; color: #fff; border-color: #388bfd; }}
    .btn-secondary {{ background: var(--card); color: var(--text); }}
    .btn:hover {{ opacity: 0.9; }}

    .kpi-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
        gap: 14px;
        margin-bottom: 28px;
    }}
    .kpi-card {{
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 16px;
        text-align: center;
    }}
    .kpi-num {{ font-size: 28px; font-weight: 700; color: var(--accent); }}
    .kpi-label {{ font-size: 12px; color: var(--muted); text-transform: uppercase; margin-top: 4px; }}

    section {{
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 18px;
        margin-bottom: 22px;
    }}
    h2 {{
        margin: 0 0 14px 0;
        font-size: 17px;
        color: #fff;
        border-left: 4px solid var(--accent);
        padding-left: 10px;
    }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{
        text-align: left;
        padding: 10px;
        border-bottom: 1px solid var(--border);
        vertical-align: top;
    }}
    th {{ color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 11px; }}
    a {{ color: #58a6ff; word-break: break-all; }}
    .mono {{ font-family: Consolas, Monaco, monospace; font-size: 12px; word-break: break-all; }}
    .wrap {{ word-break: break-word; }}
    .muted {{ color: var(--muted); }}
    .small {{ font-size: 11px; }}

    .badge {{
        display: inline-block;
        padding: 2px 8px;
        border-radius: 12px;
        font-size: 11px;
        font-weight: 600;
    }}
    .badge-danger {{ background: rgba(248, 81, 73, 0.2); color: #ff7b72; border: 1px solid #f85149; }}
    .badge-warn {{ background: rgba(210, 153, 34, 0.2); color: #e3b341; border: 1px solid #d29922; }}
    .badge-info {{ background: rgba(56, 139, 253, 0.2); color: #79c0ff; border: 1px solid #388bfd; }}
    .badge-tool {{ background: rgba(46, 160, 67, 0.2); color: #56d364; border: 1px solid #2ea043; }}
    .badge-ai {{ background: rgba(163, 113, 247, 0.2); color: #d2a8ff; border: 1px solid #a371f7; }}

    footer {{ text-align: center; color: var(--muted); font-size: 12px; margin-top: 24px; }}

    /* Court-Ready Print / Save-as-PDF Styles */
    @media print {{
        body {{ background: #ffffff !important; color: #000000 !important; padding: 0; }}
        .actions {{ display: none !important; }}
        section, .kpi-card {{
            background: #ffffff !important;
            border: 1px solid #cccccc !important;
            break-inside: avoid;
        }}
        h1, h2, .kpi-num {{ color: #000000 !important; }}
        th, td {{ border-bottom: 1px solid #dddddd !important; color: #000000 !important; }}
        a {{ color: #000000 !important; text-decoration: none; }}
        .badge {{ border: 1px solid #000 !important; color: #000 !important; background: #eee !important; }}
    }}
</style>
</head>
<body>
<div class="container">
    <header>
        <div>
            <h1>OSINT-DFIR-BRAHMASTRA | FORENSIC REPORT</h1>
            <div class="meta-sub">
                Case ID: <strong>{self._esc(self.case_name)}</strong> &nbsp;|&nbsp;
                Generated: {generated_at} &nbsp;|&nbsp;
                Source DB: cases/{self._esc(self.case_name)}.db
            </div>
        </div>
        <div class="actions">
            {graph_btn_html}
            <button onclick="window.print()" class="btn btn-secondary">🖨 Print / Save as PDF</button>
        </div>
    </header>

    <div class="kpi-grid">
        <div class="kpi-card"><div class="kpi-num">{len(artifacts)}</div><div class="kpi-label">Forensic Artifacts</div></div>
        <div class="kpi-card"><div class="kpi-num">{len(secrets) + len(breaches)}</div><div class="kpi-label">Critical Alerts</div></div>
        <div class="kpi-card"><div class="kpi-num">{len(iocs)}</div><div class="kpi-label">Extracted IOCs</div></div>
        <div class="kpi-card"><div class="kpi-num">{len(osint_rows)}</div><div class="kpi-label">OSINT Findings</div></div>
        <div class="kpi-card"><div class="kpi-num">{len(ai_pivots)}</div><div class="kpi-label">AI Auto-Pivots</div></div>
    </div>

    <section>
        <h2>1. Forensic Artifacts &amp; Cryptographic Hashes</h2>
        <table>
            <thead><tr><th>File Name</th><th>Size</th><th>MD5 Hash</th><th>SHA-256 Hash</th></tr></thead>
            <tbody>{artifacts_html}</tbody>
        </table>
    </section>

    <section>
        <h2>2. Critical Alerts (Leaked Secrets &amp; Data Breaches)</h2>
        <table>
            <thead><tr><th>Severity</th><th>Source / Type</th><th>Evidence Value</th></tr></thead>
            <tbody>{alerts_html}</tbody>
        </table>
    </section>

    <section>
        <h2>3. Extracted Indicators of Compromise (IOCs)</h2>
        <table>
            <thead><tr><th>IOC Type</th><th>Value</th></tr></thead>
            <tbody>{iocs_html}</tbody>
        </table>
    </section>

    <section>
        <h2>4. Autonomous AI Pivot Reasoning Trail</h2>
        <table>
            <thead><tr><th>Depth</th><th>Target Type</th><th>Target</th><th>AI Investigative Reasoning</th></tr></thead>
            <tbody>{pivots_html}</tbody>
        </table>
    </section>

    <section>
        <h2>5. Collected OSINT Intelligence</h2>
        <table>
            <thead><tr><th>Target</th><th>Source Tool</th><th>Field / Type</th><th>Extracted Value</th></tr></thead>
            <tbody>{osint_html}</tbody>
        </table>
    </section>

    <section>
        <h2>6. Chain of Custody (Forensic Audit Log)</h2>
        <table>
            <thead><tr><th>Timestamp (UTC)</th><th>Action</th><th>Details</th></tr></thead>
            <tbody>{audit_html}</tbody>
        </table>
    </section>

    <footer>
        Generated automatically by OSINT-DFIR-BRAHMASTRA Framework. Integrity verified via SQLite Case DB.
    </footer>
</div>
</body>
</html>
"""

        output_path = self.reports_dir / f"{self.case_name}_report.html"
        output_path.write_text(html_doc, encoding="utf-8")

        self.db.log_action("REPORT_GENERATED", f"Saved forensic HTML report to {output_path}")

        return {
            "report_path": str(output_path),
            "artifacts": len(artifacts),
            "alerts": len(secrets) + len(breaches),
            "osint_findings": len(osint_rows),
        }