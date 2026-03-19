# Developed by Galal Noaman – RedShadow_V2
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v2/modules/report.py

import json
import os
from datetime import datetime


def _cvss_badge(score):
    """Returns a colour class string for HTML based on CVSS score."""
    try:
        s = float(score)
        if s >= 8.0:
            return "high"
        elif s >= 5.0:
            return "medium"
        else:
            return "low"
    except Exception:
        return "unknown"


def generate_report(input_file, output_file, html_output=None):
    """
    Generates a Markdown report and optionally an HTML report.

    Args:
        input_file (str):    Path to analysis_results.json
        output_file (str):   Path for .md output
        html_output (str):   Path for .html output (optional)
    """

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as error:
        print(f"[!] Failed to read input file: {error}")
        return

    if not isinstance(data, list):
        print("[!] Invalid input format – expected a list of analysis results.")
        return

    # ── Stats ──
    total_cves = 0
    high_severity = 0
    medium_severity = 0
    low_severity = 0
    generated_on = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # ─────────────────────────────────────
    # Markdown Report
    # ─────────────────────────────────────

    report_lines = [
        "# 🛡️ RedShadow Reconnaissance Report",
        "",
        f"**Input File:** `{input_file}`",
        f"**Generated On:** `{generated_on}`",
        ""
    ]

    for entry in data:
        url     = entry.get("url", "N/A")
        ip      = entry.get("ip", "N/A")
        hostname = entry.get("hostname", "N/A")
        tech_matches = entry.get("tech_matches", [])

        def max_cvss(match):
            cves = match.get("cves", [])
            return max((cve.get("cvss", 0) for cve in cves if isinstance(cve.get("cvss"), (int, float))), default=0)

        tech_matches.sort(key=max_cvss, reverse=True)

        report_lines.append(f"---\n## 🔗 `{url}`")
        report_lines.append(f"- **IP Address:** `{ip}`")
        report_lines.append(f"- **Hostname:** `{hostname}`")

        if tech_matches:
            report_lines.append("- **Detected Technologies & CVEs:**")
            for match in tech_matches:
                tech = match.get("tech", "Unknown")
                ports = ", ".join(match.get("ports", ["N/A"]))
                cves = match.get("cves", [])
                report_lines.append(f"  - `{tech}` on ports `{ports}`")
                if cves:
                    for cve in cves:
                        cve_id = cve.get("cve", "Unknown")
                        cvss   = cve.get("cvss", "N/A")
                        cve_url = cve.get("url", "#")
                        try:
                            score = float(cvss)
                            if score >= 8.0:
                                high_severity += 1
                            elif score >= 5.0:
                                medium_severity += 1
                            else:
                                low_severity += 1
                        except Exception:
                            pass
                        total_cves += 1
                        report_lines.append(f"    - [{cve_id}]({cve_url}) (CVSS: {cvss})")
                else:
                    report_lines.append("    - No CVEs matched.")
        else:
            report_lines.append("- ❌ No known vulnerable technologies detected.")

        report_lines.append("")

    report_lines += [
        "---",
        "### 📊 Vulnerability Summary",
        f"- Total Targets Analysed: **{len(data)}**",
        f"- Total CVEs Detected: **{total_cves}**",
        f"- 🔴 High Severity (CVSS ≥ 8.0): **{high_severity}**",
        f"- 🟡 Medium (5.0 ≤ CVSS < 8.0): **{medium_severity}**",
        f"- 🟢 Low (CVSS < 5.0): **{low_severity}**",
    ]

    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else ".", exist_ok=True)

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(report_lines))
        print(f"[✓] Markdown report created: {output_file}")
    except Exception as error:
        print(f"[!] Could not write Markdown report: {error}")

    # ─────────────────────────────────────
    # HTML Report
    # ─────────────────────────────────────

    if not html_output:
        return

    html_entries = ""

    for entry in data:
        url         = entry.get("url", "N/A")
        ip          = entry.get("ip", "N/A")
        hostname    = entry.get("hostname", "N/A")
        tech_matches = entry.get("tech_matches", [])

        def max_cvss_html(match):
            cves = match.get("cves", [])
            return max((cve.get("cvss", 0) for cve in cves if isinstance(cve.get("cvss"), (int, float))), default=0)

        tech_matches.sort(key=max_cvss_html, reverse=True)

        cve_rows = ""
        for match in tech_matches:
            tech = match.get("tech", "Unknown")
            ports = ", ".join(match.get("ports", ["N/A"]))
            cves = match.get("cves", [])
            if cves:
                for cve in cves:
                    cve_id   = cve.get("cve", "Unknown")
                    cvss     = cve.get("cvss", "N/A")
                    cve_url  = cve.get("url", "#")
                    badge    = _cvss_badge(cvss)
                    cve_rows += f"""
                    <tr>
                        <td><code>{tech}</code></td>
                        <td>{ports}</td>
                        <td><a href="{cve_url}" target="_blank">{cve_id}</a></td>
                        <td><span class="badge {badge}">{cvss}</span></td>
                    </tr>"""
            else:
                cve_rows += f"""
                    <tr>
                        <td><code>{tech}</code></td>
                        <td>{ports}</td>
                        <td colspan="2" style="color:#888;">No CVEs matched</td>
                    </tr>"""

        if not tech_matches:
            cve_rows = """
                    <tr><td colspan="4" style="color:#888; text-align:center;">
                        No vulnerable technologies detected
                    </td></tr>"""

        html_entries += f"""
        <div class="target-card">
            <div class="target-header">
                <span class="target-url">🔗 {url}</span>
                <span class="target-meta">IP: {ip} | Host: {hostname}</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Technology</th>
                        <th>Port</th>
                        <th>CVE</th>
                        <th>CVSS</th>
                    </tr>
                </thead>
                <tbody>{cve_rows}
                </tbody>
            </table>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RedShadow Report – {generated_on}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            padding: 2rem;
            line-height: 1.6;
        }}
        header {{
            border-bottom: 1px solid #30363d;
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}
        header h1 {{
            font-size: 1.8rem;
            color: #58a6ff;
        }}
        header p {{
            color: #8b949e;
            margin-top: 0.3rem;
            font-size: 0.9rem;
        }}
        .summary {{
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
        }}
        .stat-box {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1rem 1.5rem;
            min-width: 140px;
            text-align: center;
        }}
        .stat-box .num {{
            font-size: 2rem;
            font-weight: bold;
            display: block;
        }}
        .stat-box .label {{
            font-size: 0.8rem;
            color: #8b949e;
        }}
        .stat-box.high .num {{ color: #f85149; }}
        .stat-box.medium .num {{ color: #e3b341; }}
        .stat-box.low .num {{ color: #3fb950; }}
        .stat-box.total .num {{ color: #58a6ff; }}
        .target-card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            overflow: hidden;
        }}
        .target-header {{
            background: #1c2128;
            padding: 0.8rem 1.2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 0.5rem;
            border-bottom: 1px solid #30363d;
        }}
        .target-url {{
            font-weight: bold;
            color: #58a6ff;
            font-size: 1rem;
        }}
        .target-meta {{
            font-size: 0.8rem;
            color: #8b949e;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th {{
            background: #1c2128;
            text-align: left;
            padding: 0.6rem 1rem;
            font-size: 0.8rem;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border-bottom: 1px solid #30363d;
        }}
        td {{
            padding: 0.6rem 1rem;
            border-bottom: 1px solid #21262d;
            font-size: 0.9rem;
        }}
        tr:last-child td {{ border-bottom: none; }}
        a {{ color: #58a6ff; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        code {{
            background: #21262d;
            padding: 0.1em 0.4em;
            border-radius: 4px;
            font-size: 0.85em;
        }}
        .badge {{
            display: inline-block;
            padding: 0.15em 0.5em;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
        }}
        .badge.high    {{ background: #3d1c1c; color: #f85149; }}
        .badge.medium  {{ background: #2d2200; color: #e3b341; }}
        .badge.low     {{ background: #0d2a17; color: #3fb950; }}
        .badge.unknown {{ background: #21262d; color: #8b949e; }}
        footer {{
            margin-top: 3rem;
            padding-top: 1rem;
            border-top: 1px solid #30363d;
            font-size: 0.8rem;
            color: #8b949e;
            text-align: center;
        }}
    </style>
</head>
<body>

<header>
    <h1>🛡️ RedShadow Reconnaissance Report</h1>
    <p>Generated: {generated_on} &nbsp;|&nbsp; Input: {input_file}</p>
</header>

<div class="summary">
    <div class="stat-box total">
        <span class="num">{len(data)}</span>
        <span class="label">Targets</span>
    </div>
    <div class="stat-box total">
        <span class="num">{total_cves}</span>
        <span class="label">Total CVEs</span>
    </div>
    <div class="stat-box high">
        <span class="num">{high_severity}</span>
        <span class="label">High (≥8.0)</span>
    </div>
    <div class="stat-box medium">
        <span class="num">{medium_severity}</span>
        <span class="label">Medium (5–7.9)</span>
    </div>
    <div class="stat-box low">
        <span class="num">{low_severity}</span>
        <span class="label">Low (&lt;5.0)</span>
    </div>
</div>

{html_entries}

<footer>
    RedShadow V2 &nbsp;|&nbsp; Developed by Galal Noaman &nbsp;|&nbsp; For lawful use only
</footer>

</body>
</html>"""

    try:
        os.makedirs(os.path.dirname(html_output) if os.path.dirname(html_output) else ".", exist_ok=True)
        with open(html_output, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"[✓] HTML report created: {html_output}")
    except Exception as error:
        print(f"[!] Could not write HTML report: {error}")