# Architecture

```text
User / CLI
   |
   v
URL validation + request timeout
   |
   v
HTTP GET (redirects followed; TLS verification enabled)
   |
   v
Response metadata analyzer
   |-- HTTPS / redirect observation
   |-- security header checks
   |-- CORS response-header review
   |-- Server banner note
   |
   v
Findings (severity + evidence + remediation)
   |
   +--> JSON
   +--> CSV
   +--> HTML
```

The scanner is intentionally non-invasive and does not crawl or exploit targets.
