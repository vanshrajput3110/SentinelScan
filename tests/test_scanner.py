import unittest
from types import SimpleNamespace
from sentinelscan.scanner import analyze_response, validate_url
from sentinelscan.reports import write_csv_report, write_html_report, write_json_report
import tempfile
from pathlib import Path


class ScannerTests(unittest.TestCase):
    def fake_response(self, headers=None, url="https://example.test", history=None, status=200):
        return SimpleNamespace(headers=headers or {}, url=url, history=history or [], status_code=status)

    def test_validate_url_accepts_http_and_https(self):
        self.assertEqual(validate_url("https://example.test"), "https://example.test")
        self.assertEqual(validate_url("http://example.test"), "http://example.test")

    def test_validate_url_rejects_missing_scheme(self):
        with self.assertRaises(ValueError):
            validate_url("example.test")

    def test_validate_url_rejects_credentials(self):
        with self.assertRaises(ValueError):
            validate_url("https://user:pass@example.test")

    def test_missing_headers_are_reported(self):
        findings = analyze_response("https://example.test", self.fake_response())
        titles = [f.title for f in findings]
        self.assertIn("Missing Content-Security-Policy", titles)
        self.assertIn("Missing Strict-Transport-Security", titles)

    def test_present_headers_are_not_marked_missing(self):
        response = self.fake_response(headers={
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        })
        findings = analyze_response("https://example.test", response)
        titles = [f.title for f in findings]
        self.assertNotIn("Missing Content-Security-Policy", titles)
        self.assertIn("Content-Security-Policy present", titles)

    def test_cors_wildcard_is_informational(self):
        findings = analyze_response(
            "https://example.test",
            self.fake_response(headers={"Access-Control-Allow-Origin": "*"})
        )
        cors = [f for f in findings if f.check == "cors"]
        self.assertEqual(cors[0].severity, "INFO")
        self.assertIn("Wildcard", cors[0].title)

    def test_http_without_upgrade_is_medium(self):
        response = self.fake_response(url="http://example.test")
        findings = analyze_response("http://example.test", response)
        self.assertTrue(any(f.title == "HTTP was not observed upgrading to HTTPS"
                            and f.severity == "MEDIUM" for f in findings))

    def test_reports_are_created_and_escape_html(self):
        result = {
            "target_url": "https://example.test/?q=<script>",
            "final_url": "https://example.test/",
            "scan_time_utc": "2026-01-01T00:00:00+00:00",
            "http_status": 200,
            "disclaimer": "Test report",
            "findings": [{
                "check": "headers", "severity": "LOW", "title": "<script>alert(1)</script>",
                "evidence": "test", "recommendation": "fix", "details": ""
            }]
        }
        with tempfile.TemporaryDirectory() as tmp:
            write_json_report(result, Path(tmp) / "scan.json")
            write_csv_report(result, Path(tmp) / "scan.csv")
            html_path = write_html_report(result, Path(tmp) / "scan.html")
            content = html_path.read_text(encoding="utf-8")
            self.assertIn("&lt;script&gt;", content)
            self.assertNotIn("<script>alert(1)</script>", content)
            self.assertTrue((Path(tmp) / "scan.csv").exists())
            self.assertTrue((Path(tmp) / "scan.json").exists())


if __name__ == "__main__":
    unittest.main()
