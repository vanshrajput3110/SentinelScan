"""SentinelScan: Automated Web Security Configuration Scanner.

Author: Vansh Rajput
Program: IBM SkillsBuild Cyber Security 2026

Non-invasive configuration checks for one authorized HTTP(S) URL. This is not
an exploit tool or a full vulnerability scanner. Findings require manual review.
"""
from __future__ import annotations
import argparse
import csv
import html
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import requests

VERSION = "1.0.0"
SECURITY_HEADERS = {
    "Content-Security-Policy": ("MEDIUM", "Define a policy suitable for the application; test in report-only mode before enforcing."),
    "Strict-Transport-Security": ("MEDIUM", "After confirming HTTPS works across the site and subdomains, configure an appropriate HSTS max-age."),
    "X-Content-Type-Options": ("LOW", "Set X-Content-Type-Options: nosniff."),
    "X-Frame-Options": ("LOW", "Set DENY or SAMEORIGIN, or use CSP frame-ancestors as appropriate."),
    "Referrer-Policy": ("LOW", "Choose a policy suitable for the application, commonly strict-origin-when-cross-origin."),
}
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def validate_url(url: str) -> str:
    """Validate a complete HTTP(S) URL and reject embedded credentials."""
    url = (url or "").strip()
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a complete URL beginning with http:// or https://")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded usernames or passwords are not accepted.")
    if any(ch.isspace() for ch in url):
        raise ValueError("URL must not contain whitespace.")
    return url


def finding(check: str, severity: str, title: str, evidence: str, recommendation: str) -> dict[str, str]:
    return {"check": check, "severity": severity, "title": title,
            "evidence": evidence, "recommendation": recommendation}


def scan_url(url: str, timeout: float = 8.0) -> dict:
    """Make one ordinary GET request (following redirects) and inspect headers."""
    url = validate_url(url)
    if timeout <= 0 or timeout > 60:
        raise ValueError("Timeout must be greater than 0 and no more than 60 seconds.")
    with requests.Session() as session:
        response = session.get(url, headers={"User-Agent": "SentinelScan/1.0 (authorized security configuration audit)",
                                             "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
                               timeout=timeout, allow_redirects=True)
    headers = {str(k).lower(): str(v).strip() for k, v in response.headers.items()}
    final_url = response.url
    final_scheme = urlparse(final_url).scheme.lower()
    findings: list[dict[str, str]] = []

    if urlparse(url).scheme.lower() == "http":
        if final_scheme == "https" and response.history:
            findings.append(finding("transport", "INFO", "HTTP redirects to HTTPS",
                f"Initial URL used HTTP; final URL is {final_url}",
                "No action required for this observed redirect. Verify other routes also redirect."))
        else:
            findings.append(finding("transport", "MEDIUM", "HTTP was not observed upgrading to HTTPS",
                f"Initial URL: {url}; final URL: {final_url}",
                "Serve the site over HTTPS and redirect HTTP requests to HTTPS. This check covers only the tested URL."))
    else:
        findings.append(finding("transport", "INFO", "HTTPS used", f"Final URL scheme: {final_scheme or 'unknown'}",
            "Ensure the TLS certificate is valid and sensitive pages use HTTPS."))

    for header, (severity, recommendation) in SECURITY_HEADERS.items():
        value = headers.get(header.lower())
        if value:
            findings.append(finding("headers", "INFO", f"{header} present", f"Observed value: {value[:300]}",
                "Review the value for suitability; presence alone does not prove the policy is effective."))
        else:
            findings.append(finding("headers", severity, f"Missing {header}", f"{header} response header was not present.", recommendation))

    allow_origin = headers.get("access-control-allow-origin")
    allow_credentials = headers.get("access-control-allow-credentials", "").lower()
    if allow_origin == "*" and allow_credentials == "true":
        findings.append(finding("cors", "MEDIUM", "Potentially inconsistent CORS configuration",
            "Access-Control-Allow-Origin is '*' and Access-Control-Allow-Credentials is 'true'.",
            "Review CORS middleware and browser behavior. This combination alone is not proof of exploitable access."))
    elif allow_origin == "*":
        findings.append(finding("cors", "INFO", "Wildcard CORS origin observed", "Access-Control-Allow-Origin: *",
            "Confirm the resource is intentionally public and does not expose sensitive data."))
    elif allow_origin:
        findings.append(finding("cors", "INFO", "CORS origin explicitly configured",
            f"Access-Control-Allow-Origin: {allow_origin[:300]}",
            "Verify the origin is intentionally allow-listed and cannot expose sensitive responses to untrusted origins."))
    else:
        findings.append(finding("cors", "INFO", "No Access-Control-Allow-Origin header observed",
            "The response did not include Access-Control-Allow-Origin.",
            "This is not necessarily a problem; enable CORS only when cross-origin access is required."))
    if headers.get("server"):
        findings.append(finding("information-disclosure", "INFO", "Server header disclosed",
            f"Server: {headers['server'][:200]}",
            "Consider minimizing unnecessary version details. A Server header alone is not a vulnerability."))

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["check"], f["title"]))
    return {"tool": "SentinelScan", "version": VERSION,
            "scan_time_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "target_url": url, "final_url": final_url, "http_status": response.status_code,
            "redirect_count": len(response.history), "findings": findings,
            "disclaimer": "Configuration checks only; findings require context and manual verification."}


def write_reports(result: dict, out_dir: Path) -> None:
    """Write JSON, CSV and HTML reports from a scan result."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "scan.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    fields = ["check", "severity", "title", "evidence", "recommendation"]
    with (out_dir / "scan.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(result["findings"])
    rows = []
    for item in result["findings"]:
        cells = "".join(f"<td>{html.escape(str(item[k]))}</td>" for k in fields)
        rows.append(f"<tr>{cells}</tr>")
    document = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>SentinelScan Report</title><style>body{font-family:Arial,sans-serif;margin:2rem;color:#222}table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{border:1px solid #ccc;padding:.6rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#eee}</style></head><body>"""
    document += f"<h1>SentinelScan Report</h1><p><b>Target:</b> {html.escape(result['target_url'])}</p>"
    document += f"<p><b>Final URL:</b> {html.escape(result['final_url'])} | <b>Status:</b> {result['http_status']} | <b>Redirects:</b> {result['redirect_count']}</p>"
    document += "<table><thead><tr>" + "".join(f"<th>{html.escape(k.title())}</th>" for k in fields) + "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    document += f"<p>{html.escape(result['disclaimer'])}</p></body></html>"
    (out_dir / "scan.html").write_text(document, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Non-invasive web security configuration checks for an authorized URL.")
    parser.add_argument("url", help="Target URL including http:// or https://")
    parser.add_argument("--timeout", type=float, default=8.0, help="Request timeout in seconds (default: 8)")
    parser.add_argument("--out", default="reports", help="Report output directory (default: reports)")
    args = parser.parse_args(argv)
    try:
        result = scan_url(args.url, args.timeout)
    except ValueError as exc:
        print(f"[INPUT ERROR] {exc}", file=sys.stderr)
        return 2
    except requests.exceptions.Timeout:
        print("[NETWORK ERROR] Request timed out.", file=sys.stderr)
        return 3
    except requests.exceptions.SSLError:
        print("[TLS ERROR] TLS validation failed. Certificate verification is not disabled.", file=sys.stderr)
        return 4
    except requests.exceptions.RequestException as exc:
        print(f"[NETWORK ERROR] Request failed: {exc}", file=sys.stderr)
        return 3
    out_dir = Path(args.out)
    write_reports(result, out_dir)
    print("SENTINELSCAN — WEB SECURITY CONFIGURATION AUDIT")
    print(f"Target: {result['target_url']}\nFinal URL: {result['final_url']}\nHTTP status: {result['http_status']}\nRedirects: {result['redirect_count']}")
    for item in result["findings"]:
        print(f"[{item['severity']}] {item['title']}\n  Evidence: {item['evidence']}\n  Recommendation: {item['recommendation']}")
    print(f"Reports saved to: {out_dir.resolve()}")
    print("Review findings manually. Use only on websites you own or are authorized to test.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
