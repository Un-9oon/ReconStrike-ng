# ReconStrike

**Advanced Web & Network Vulnerability Assessment Framework**

ReconStrike is a professional-grade vulnerability scanner built in Python that performs comprehensive security assessments against web applications and network endpoints. Designed for penetration testers, security auditors, and DevSecOps teams.

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![Modules](https://img.shields.io/badge/scan%20modules-43-green.svg)
![License](https://img.shields.io/badge/license-MIT-brightgreen.svg)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010%202021-orange.svg)
![PCI DSS](https://img.shields.io/badge/PCI%20DSS-v4.0-red.svg)

---

## Features

### Core Scanning Engine
- **43 vulnerability scan modules** covering OWASP Top 10 and beyond
- **Zero false positive architecture** -- baseline comparison, double-verification, structural validation
- **Concurrent crawler** -- multi-threaded discovery (5-10x faster than sequential)
- **WAF detection** -- identifies 10+ WAF/CDN products before scanning
- **Technology stack fingerprinting** -- frameworks, servers, CMS, CDN, analytics

### Scan Modules

| Category | Modules |
|----------|---------|
| **Reconnaissance** | fingerprint, portscan, subdomain, subdomain_takeover |
| **Configuration & Headers** | headers, ssl, misconfig, cors, session_security |
| **Injection** | sqli, xss, dom_xss, ssti, cmd_injection, nosql, ldap_injection, xxe, second_order |
| **Authentication & Authorization** | auth, jwt, idor, oauth_misconfig, mass_assignment |
| **Client-Side** | csrf, open_redirect, prototype_pollution, hpp |
| **Server-Side** | ssrf, lfi, file_upload, request_smuggling, deserialization, cache_poisoning, host_header, http_method, race_condition, websocket_security |
| **Information & Discovery** | directory, info_disclosure, graphql, business_logic |
| **Advanced** | cve_check, zero_day |

### Advanced Features
- **8 scan profiles** -- quick, standard, deep, aggressive, passive, api, owasp, full
- **OWASP Top 10 & PCI DSS v4.0 compliance mapping** with pass/fail scoring
- **Scan diffing** -- compare current results against previous scans to track remediation
- **API endpoint security** -- auto-discovers and tests REST API endpoints
- **WAF detection** -- Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, F5, Sucuri, and more
- **Rate limiting** -- configurable requests per second
- **Proxy support** -- HTTP and SOCKS5 proxy routing (Tor-compatible)
- **Scope control** -- include/exclude URL patterns via regex
- **JSON output** -- machine-readable output for automation pipelines
- **CI/CD integration** -- exit codes based on severity thresholds
- **Authenticated scanning** -- auto-detect login forms and maintain sessions
- **Progress tracking** -- real-time progress bar with ETA
- **HTML reports** -- professional dark-themed reports with risk scoring and executive summary
- **PDF reports** -- exportable PDF reports for stakeholder distribution

---

## Installation

```bash
git clone https://github.com/cyphersec-404/ReconStrike.git
cd ReconStrike
pip install -r requirements.txt
```

---

## Usage

### Basic Scan
```bash
python3 reconstrike.py -t https://target.com
```

### Scan Profiles
```bash
# Quick recon (5 modules, depth 2)
python3 reconstrike.py -t https://target.com --profile quick

# Deep scan (all modules, depth 5)
python3 reconstrike.py -t https://target.com --profile deep

# Aggressive (all modules, depth 7)
python3 reconstrike.py -t https://target.com --profile aggressive

# API-focused
python3 reconstrike.py -t https://api.target.com --profile api --api-scan

# OWASP compliance check
python3 reconstrike.py -t https://target.com --profile owasp --compliance

# Passive recon only (no injection tests)
python3 reconstrike.py -t https://target.com --profile passive

# Full scan (all 43 modules)
python3 reconstrike.py -t https://target.com --profile full
```

### Authenticated Scanning
```bash
python3 reconstrike.py -t https://target.com \
  --auth-url https://target.com/login \
  -u admin -p password123
```

### Selective Modules
```bash
# Run specific modules
python3 reconstrike.py -t https://target.com --modules sqli,xss,headers,ssl

# List all available modules
python3 reconstrike.py --list-modules

# Run all except slow ones
python3 reconstrike.py -t https://target.com --exclude-modules portscan,subdomain
```

### Advanced Options
```bash
# With proxy (Tor, Burp, etc.)
python3 reconstrike.py -t https://target.com --proxy socks5://127.0.0.1:9050

# Rate-limited scan
python3 reconstrike.py -t https://target.com --rate-limit 10

# JSON output for automation
python3 reconstrike.py -t https://target.com --json --json-file results.json

# Compare with previous scan
python3 reconstrike.py -t https://target.com --diff

# Compliance report
python3 reconstrike.py -t https://target.com --compliance

# CI/CD pipeline (exit 1 on critical, 2 on high)
python3 reconstrike.py -t https://target.com --ci --severity-threshold HIGH -q
```

### Custom Headers & Cookies
```bash
python3 reconstrike.py -t https://target.com \
  --cookie "session=abc123; token=xyz" \
  --header "Authorization: Bearer eyJ..." \
  --header "X-Custom: value"
```

---

## Logging

ReconStrike uses Python's structured logging system with configurable verbosity:

```bash
# Verbose output (DEBUG level)
python3 reconstrike.py -t https://target.com --verbose

# Quiet mode (WARNING and above only)
python3 reconstrike.py -t https://target.com --quiet

# Disable colored output (useful for piping/logging)
python3 reconstrike.py -t https://target.com --no-color

# Write logs to a file
python3 reconstrike.py -t https://target.com --log-file scan.log

# Combine flags
python3 reconstrike.py -t https://target.com --verbose --log-file debug.log --no-color
```

---

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| **HTML Report** | `-o report.html` | Professional dark-themed report with risk scoring |
| **PDF Report** | `-o report.pdf` | Exportable PDF for stakeholders |
| **JSON** | `--json` | Machine-readable output to stdout |
| **JSON File** | `--json-file out.json` | Save JSON to file |
| **CLI Summary** | (default) | Color-coded terminal output |
| **Quiet Mode** | `-q` | Minimal output for CI/CD |

---

## CI/CD Integration

ReconStrike integrates into CI/CD pipelines with exit codes based on severity thresholds:

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install ReconStrike
        run: |
          git clone https://github.com/cyphersec-404/ReconStrike.git
          cd ReconStrike
          pip install -r requirements.txt

      - name: Run security scan
        run: |
          cd ReconStrike
          python3 reconstrike.py \
            -t ${{ vars.SCAN_TARGET }} \
            --profile quick \
            --ci \
            --severity-threshold HIGH \
            --quiet \
            --no-color \
            --json-file results.json

      - name: Upload scan results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-scan-results
          path: ReconStrike/results.json
```

Exit codes: `0` = no findings above threshold, `1` = critical findings, `2` = high findings.

---

## Compliance

ReconStrike maps findings to industry frameworks:

- **OWASP Top 10 (2021)** -- A01 through A10 category mapping with pass/fail
- **PCI DSS v4.0** -- Requirements 6.5.1 through 6.5.10

Use `--compliance` to generate the compliance report section in both CLI and HTML output.

---

## Disclaimer

This tool is intended for **authorized security testing only**. Only use ReconStrike against systems you own or have explicit written permission to test. Unauthorized scanning is illegal. The authors are not responsible for misuse.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
