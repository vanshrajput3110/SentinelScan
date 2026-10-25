"""CSV and HTML report generation."""
from __future__ import annotations
import csv
import html
import json
from pathlib import Path
from typing import Any


def write_json_report(result: dict[str, Any], path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def write_csv_report(result: dict[str, Any], path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["check", "severity", "title", "evidence", "recommendation", "details"]
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for finding in result.get("findings", []):
            writer.writerow({field: finding.get(field, "") for field in fields})
    return path


def write_html_report(result: dict[str, Any], path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    findings = result.get("findings", [])
    counts = {level: sum(1 for f in findings if f.get("severity") == level)
              for level in ("HIGH", "MEDIUM", "LOW", "INFO")}
    rows = []
    for f in findings:
        severity = html.escape(str(f.get("severity", "INFO")))
        rows.append(
            "<tr>"
            f"<td><span class='severity {severity.lower()}'>{severity}</span></td>"
            f"<td>{html.escape(str(f.get('title', '')))}</td>"
            f"<td>{html.escape(str(f.get('evidence', '')))}</td>"
            f"<td>{html.escape(str(f.get('recommendation', '')))}</td>"
            "</tr>"
        )
    target = html.escape(str(result.get("target_url", "")))
    final_url = html.escape(str(result.get("final_url", "")))
    scan_time = html.escape(str(result.get("scan_time_utc", "")))
    status = html.escape(str(result.get("http_status", "")))
    body = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SentinelScan Report</title>
<style>
body{{font-family:system-ui,Arial,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#202938}}
h1{{margin-bottom:.2rem}} .muted{{color:#5b6573}} .summary{{display:flex;flex-wrap:wrap;gap:.7rem;margin:1.2rem 0}}
.card{{border:1px solid #d8dee8;border-radius:10px;padding:.8rem 1rem;min-width:100px}}
table{{width:100%;border-collapse:collapse;margin-top:1rem}} th,td{{text-align:left;vertical-align:top;border-bottom:1px solid #d8dee8;padding:.7rem;overflow-wrap:anywhere}}
th{{background:#f3f5f8}} .severity{{font-weight:700}} .high{{color:#b42318}} .medium{{color:#b54708}} .low{{color:#175cd3}} .info{{color:#475467}}
.notice{{background:#f8fafc;border-left:4px solid #64748b;padding:1rem;margin-top:1.2rem}}
</style></head><body>
<h1>SentinelScan</h1><p class="muted">Automated web security configuration report</p>
<div class="card"><strong>Target</strong><br>{target}<br><strong>Final URL</strong><br>{final_url}<br>
<strong>HTTP status:</strong> {status}<br><strong>Scan time (UTC):</strong> {scan_time}</div>
<div class="summary">
<div class="card"><strong>High</strong><br>{counts['HIGH']}</div>
<div class="card"><strong>Medium</strong><br>{counts['MEDIUM']}</div>
<div class="card"><strong>Low</strong><br>{counts['LOW']}</div>
<div class="card"><strong>Info</strong><br>{counts['INFO']}</div>
</div>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>Recommendation</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<div class="notice"><strong>Scope and limitations:</strong> {html.escape(str(result.get('disclaimer', 'Configuration checks only.')))}
This report does not prove exploitability, and missing headers are not automatically exploitable vulnerabilities. Manually verify findings and assess application context.</div>
</body></html>"""
    path.write_text(body, encoding="utf-8")
    return path
