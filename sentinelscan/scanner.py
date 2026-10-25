"""Core checks for SentinelScan.

This tool performs non-invasive HTTP configuration checks only. It is not a
full vulnerability scanner and does not test for exploitability.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse
import requests


SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "description": "Helps restrict the sources from which a page may load content.",
        "recommendation": "Define a Content-Security-Policy appropriate to the application. Test in report-only mode before enforcing."
    },
    "Strict-Transport-Security": {
        "severity": "MEDIUM",
        "description": "Tells supporting browsers to use HTTPS for future visits.",
        "recommendation": "After confirming HTTPS works across the site and subdomains, configure an appropriate HSTS max-age."
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "description": "Reduces MIME-type sniffing by browsers.",
        "recommendation": "Set X-Content-Type-Options: nosniff."
    },
    "X-Frame-Options": {
        "severity": "LOW",
        "description": "Can help prevent clickjacking in browsers that support it.",
        "recommendation": "Set X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors as appropriate."
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Controls how much referrer information is sent with requests.",
        "recommendation": "Choose a policy suitable for the application, commonly strict-origin-when-cross-origin."
    },
}

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


@dataclass
class Finding:
    check: str
    severity: str
    title: str
    evidence: str
    recommendation: str
    details: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def validate_url(url: str) -> str:
    """Validate a public HTTP(S) URL string before making a request."""
    url = (url or "").strip()
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a complete URL beginning with http:// or https://")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded usernames or passwords are not accepted.")
    if any(ch.isspace() for ch in url):
        raise ValueError("URL must not contain whitespace.")
    return url


def _finding(check: str, severity: str, title: str, evidence: str,
             recommendation: str, details: str = "") -> Finding:
    return Finding(check, severity, title, evidence, recommendation, details)


def analyze_response(url: str, response: Any, redirect_history: list[Any] | None = None) -> list[Finding]:
    """Analyze an HTTP response-like object. Designed for easy unit testing."""
    findings: list[Finding] = []
    headers = {str(k).lower(): str(v).strip() for k, v in response.headers.items()}
    final_url = getattr(response, "url", url)
    final_scheme = urlparse(final_url).scheme.lower()
    history = redirect_history if redirect_history is not None else getattr(response, "history", [])

    if urlparse(url).scheme.lower() == "http":
        if final_scheme == "https" and history:
            findings.append(_finding(
                "transport", "INFO", "HTTP redirects to HTTPS",
                f"Initial URL used HTTP; final URL is {final_url}",
                "No action required for this observed redirect. Verify all relevant routes also redirect."
            ))
        else:
            findings.append(_finding(
                "transport", "MEDIUM", "HTTP was not observed upgrading to HTTPS",
                f"Initial URL: {url}; final URL: {final_url}",
                "Serve the site over HTTPS and redirect HTTP requests to HTTPS. This check only observes the tested URL."
            ))
    else:
        findings.append(_finding(
            "transport", "INFO", "HTTPS used",
            f"Final URL scheme: {final_scheme or 'unknown'}",
            "Ensure the TLS certificate is valid and all sensitive pages use HTTPS."
        ))

    for header, meta in SECURITY_HEADERS.items():
        value = headers.get(header.lower())
        if not value:
            findings.append(_finding(
                "headers", meta["severity"], f"Missing {header}",
                f"{header} response header was not present.",
                meta["recommendation"], meta["description"]
            ))
        else:
            findings.append(_finding(
                "headers", "INFO", f"{header} present",
                f"Observed value: {value[:300]}",
                "Review the value for suitability; presence alone does not prove the policy is effective.",
                meta["description"]
            ))

    allow_origin = headers.get("access-control-allow-origin")
    allow_credentials = headers.get("access-control-allow-credentials", "").lower()
    if allow_origin == "*" and allow_credentials == "true":
        findings.append(_finding(
            "cors", "MEDIUM", "Potentially inconsistent CORS configuration",
            "Access-Control-Allow-Origin is '*' and Access-Control-Allow-Credentials is 'true'.",
            "Review CORS middleware and verify the actual browser behavior. Browsers do not permit credentialed responses with wildcard origin, so this combination is not by itself proof of exploitable access."
        ))
    elif allow_origin == "*":
        findings.append(_finding(
            "cors", "INFO", "Wildcard CORS origin observed",
            "Access-Control-Allow-Origin: *",
            "Confirm that the resource is intentionally public and does not expose user-specific or sensitive data."
        ))
    elif allow_origin:
        findings.append(_finding(
            "cors", "INFO", "CORS origin explicitly configured",
            f"Access-Control-Allow-Origin: {allow_origin[:300]}",
            "Verify the origin is allow-listed intentionally and that untrusted origins cannot access sensitive responses."
        ))
    else:
        findings.append(_finding(
            "cors", "INFO", "No Access-Control-Allow-Origin header observed",
            "The response did not include Access-Control-Allow-Origin.",
            "This is not necessarily a problem; enable CORS only when cross-origin access is required."
        ))

    server = headers.get("server")
    if server:
        findings.append(_finding(
            "information-disclosure", "INFO", "Server header disclosed",
            f"Server: {server[:200]}",
            "Consider minimizing unnecessary version details in server banners. A Server header alone is not a vulnerability."
        ))

    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.check, f.title))


def scan_url(url: str, timeout: float = 8.0, user_agent: str = "SentinelScan/1.0 (authorized security configuration audit)") -> dict[str, Any]:
    """Fetch and audit one URL. Does not crawl or submit forms."""
    url = validate_url(url)
    if timeout <= 0 or timeout > 60:
        raise ValueError("Timeout must be greater than 0 and no more than 60 seconds.")
    headers = {"User-Agent": user_agent, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
    with requests.Session() as session:
        response = session.get(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
            stream=False,
        )
        # Keep the request non-invasive and avoid reading/rendering the response body.
        findings = analyze_response(url, response, response.history)
        return {
            "tool": "SentinelScan",
            "version": "1.0.0",
            "scan_time_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "target_url": url,
            "final_url": response.url,
            "http_status": response.status_code,
            "redirect_count": len(response.history),
            "findings": [f.to_dict() for f in findings],
            "disclaimer": "Configuration checks only; findings require context and manual verification."
        }
