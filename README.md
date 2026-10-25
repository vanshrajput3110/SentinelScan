# SentinelScan — Automated Web Security Configuration Scanner

**Student:** Vansh Rajput  
**Program:** IBM SkillsBuild Cyber Security 2026  
**Language:** Python 3  
**Project type:** Defensive web-security configuration auditing

## Project description

SentinelScan is a command-line tool that checks a single URL for selected HTTP security-configuration signals. It observes HTTP-to-HTTPS redirect behavior; checks for Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, and Referrer-Policy; reviews selected CORS headers; and notes whether a Server response header is disclosed. Findings include severity, evidence, and remediation guidance. Reports are generated in JSON, CSV, and HTML formats.

This is an introductory configuration checker, not a full vulnerability scanner. A missing header does not automatically mean a site is vulnerable, and findings require manual review.

## Technologies used

- Python 3.10+
- `requests` for HTTP requests
- Python standard library (`argparse`, `json`, `csv`, `html`, `unittest`, etc.)
- `unittest` for automated tests

## Dataset

This project does not require a static dataset. It analyzes HTTP response headers from the URL supplied at runtime. For safe demonstrations, use a local test server or a website you own or have explicit permission to assess. No external dataset is used.

## Project files

- `VanshRajput_SentinelScan.py` — main command-line entry point
- `sentinelscan/` — scanner logic, report generation, and CLI implementation
- `requirements.txt` — Python dependency list
- `tests/` — automated unit tests
- `ARCHITECTURE.md` — architecture and workflow notes

## Setup

### Windows PowerShell

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### macOS/Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Run the project

Run from the repository root:

```bash
python VanshRajput_SentinelScan.py https://example.com
```

Choose an output directory or timeout if needed:

```bash
python VanshRajput_SentinelScan.py https://example.com --out reports/example --timeout 12
```

The tool writes `scan.json`, `scan.csv`, and `scan.html` into the output directory. Replace `https://example.com` with a target you are authorized to test.

## Run tests

```bash
python -m unittest discover -s tests -v
```

## Security and limitations

- Use only against systems you own or have explicit authorization to assess.
- The scanner sends a normal HTTP GET request and does not crawl, exploit, submit forms, or brute-force.
- TLS certificate verification remains enabled.
- Results are heuristic and do not prove a site is secure or exploitable.

## License

See `LICENSE`.
