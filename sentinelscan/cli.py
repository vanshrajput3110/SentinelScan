"""Command-line interface for SentinelScan."""
from __future__ import annotations
import argparse
import sys
from pathlib import Path
import requests
from .scanner import scan_url
from .reports import write_csv_report, write_html_report, write_json_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinelscan",
        description="Audit HTTP security configuration on a website you own or are authorized to test."
    )
    parser.add_argument("url", help="Target URL, including http:// or https://")
    parser.add_argument("--timeout", type=float, default=8.0, help="Request timeout in seconds (default: 8)")
    parser.add_argument("--out", default="reports", help="Output directory (default: reports)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = scan_url(args.url, timeout=args.timeout)
    except ValueError as exc:
        print(f"[INPUT ERROR] {exc}", file=sys.stderr)
        return 2
    except requests.exceptions.Timeout:
        print("[NETWORK ERROR] Request timed out. Try a longer timeout or check connectivity.", file=sys.stderr)
        return 3
    except requests.exceptions.SSLError:
        print("[TLS ERROR] TLS validation failed. The certificate or TLS connection may be invalid.", file=sys.stderr)
        print("SentinelScan does not disable certificate verification.", file=sys.stderr)
        return 4
    except requests.exceptions.RequestException as exc:
        print(f"[NETWORK ERROR] Request failed: {exc}", file=sys.stderr)
        return 3

    out = Path(args.out)
    write_json_report(result, out / "scan.json")
    write_csv_report(result, out / "scan.csv")
    write_html_report(result, out / "scan.html")

    findings = result["findings"]
    counts = {level: sum(1 for f in findings if f["severity"] == level)
              for level in ("HIGH", "MEDIUM", "LOW", "INFO")}
    print("=" * 58)
    print("SENTINELSCAN — WEB SECURITY CONFIGURATION AUDIT")
    print("=" * 58)
    print(f"Target:       {result['target_url']}")
    print(f"Final URL:    {result['final_url']}")
    print(f"HTTP status:  {result['http_status']}")
    print(f"Redirects:    {result['redirect_count']}")
    print("-" * 58)
    for finding in findings:
        print(f"[{finding['severity']:<6}] {finding['title']}")
        print(f"         Evidence: {finding['evidence']}")
        print(f"         Fix:      {finding['recommendation']}")
    print("-" * 58)
    print("Summary: " + " | ".join(f"{level}: {counts[level]}" for level in counts))
    print(f"Reports saved to: {out.resolve()}/")
    print("Reminder: review findings manually; this is not a full vulnerability scanner.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
