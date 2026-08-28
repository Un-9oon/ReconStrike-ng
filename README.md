# ReconStrike-ng

**Advanced Web & Network Vulnerability Assessment Framework**

ReconStrike-ng is a professional-grade vulnerability scanner built in Python that performs comprehensive security assessments against web applications and network endpoints. Designed for penetration testers, security auditors, and DevSecOps teams.

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![Modules](https://img.shields.io/badge/scan%20modules-43-green.svg)
![License](https://img.shields.io/badge/license-MIT-brightgreen.svg)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010%202021-orange.svg)
![PCI DSS](https://img.shields.io/badge/PCI%20DSS-v4.0-red.svg)

---

<!-- Terminal demo: record with `asciinema rec` and embed here -->
<!-- asciinema or GIF demo coming soon -->

---

## Features

### Core Scanning Engine
- **43 vulnerability scan modules** covering OWASP Top 10 and beyond
- **False positive reduction** -- baseline comparison, double-verification, structural validation
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

### Option 1: Docker (Recommended)

Run ReconStrike-ng in a fully isolated sandbox -- no access to your host system, browser, or services.

```bash
git clone https://github.com/Un-9oon/ReconStrike-ng.git
cd ReconStrike-ng
sudo apt install docker.io   # if not already installed
```

```bash
# Quick scan (sandboxed)
./reconstrike-sandbox.sh -t https://target.com --profile quick

# Deep scan with Tor (sandboxed)
./reconstrike-sandbox.sh -t https://target.com --tor --rotate-ua --profile deep

# Reports save to ./reconstrike-output/
```

The sandbox automatically:
- Drops all Linux capabilities
- Blocks access to host filesystem and services
- Enforces read-only root filesystem
- Prevents privilege escalation (even with root inside container)
- Limits memory (512MB), CPU (2 cores), and processes (256)
- Destroys the container after scan completes

### Option 2: Virtual Machine (Maximum Isolation)

For users who want MAC rotation or complete kernel-level isolation:

```bash
# Inside a VM (VirtualBox/KVM with Bridged Adapter):
git clone https://github.com/Un-9oon/ReconStrike-ng.git
cd ReconStrike-ng
pip install -r requirements.txt

# Full isolation + MAC + IP + UA rotation
reconstrike-ng -t https://target.com --tor --rotate-mac --rotate-ua --anm --profile deep
```

VM advantages over Docker:
- MAC rotation works (virtual NIC bridges to real network)
- Separate kernel (harder to escape)
- Snapshot and revert after scan (zero trace)

### Option 3: Direct Install

```bash
git clone https://github.com/Un-9oon/ReconStrike-ng.git
cd ReconStrike-ng
pip install -r requirements.txt
```

| | Docker | VM | Direct |
|--|--------|-----|--------|
| Host isolation | High | Highest | None |
| MAC rotation | No | Yes | Yes (needs root) |
| IP rotation (Tor/Proxy) | Yes | Yes | Yes |
| Setup time | 2 min | 30 min | 1 min |
| Recommended for | Most users | Paranoid mode | Dev/testing |

---

## Usage

### Basic Scan
```bash
reconstrike-ng -t https://target.com
```

### Scan Profiles
```bash
# Quick recon (5 modules, depth 2)
reconstrike-ng -t https://target.com --profile quick

# Deep scan (all modules, depth 5)
reconstrike-ng -t https://target.com --profile deep

# Aggressive (all modules, depth 7)
reconstrike-ng -t https://target.com --profile aggressive

# API-focused
reconstrike-ng -t https://api.target.com --profile api --api-scan

# OWASP compliance check
reconstrike-ng -t https://target.com --profile owasp --compliance

# Passive recon only (no injection tests)
reconstrike-ng -t https://target.com --profile passive

# Full scan (all 43 modules)
reconstrike-ng -t https://target.com --profile full
```

### Authenticated Scanning
```bash
reconstrike-ng -t https://target.com \
  --auth-url https://target.com/login \
  -u admin -p password123
```

### Selective Modules
```bash
# Run specific modules
reconstrike-ng -t https://target.com --modules sqli,xss,headers,ssl

# List all available modules
reconstrike-ng --list-modules

# Run all except slow ones
reconstrike-ng -t https://target.com --exclude-modules portscan,subdomain
```

### Advanced Options
```bash
# With proxy (Tor, Burp, etc.)
reconstrike-ng -t https://target.com --proxy socks5://127.0.0.1:9050

# Rate-limited scan
reconstrike-ng -t https://target.com --rate-limit 10

# JSON output for automation
reconstrike-ng -t https://target.com --json --json-file results.json

# Compare with previous scan
reconstrike-ng -t https://target.com --diff

# Compliance report
reconstrike-ng -t https://target.com --compliance

# CI/CD pipeline (exit 1 on critical, 2 on high)
reconstrike-ng -t https://target.com --ci --severity-threshold HIGH -q
```

### Network Scanning

```bash
# Scan a single host (top-1000 ports)
reconstrike-ng --network-scan 192.168.1.1

# Scan a CIDR range
reconstrike-ng --network-scan 192.168.1.0/24

# Custom ports and speed
reconstrike-ng --network-scan 10.0.0.1 --ports 1-65535 --scan-speed 5

# Combine with web scan
reconstrike-ng -t https://target.com --network-scan 192.168.1.0/24
```

### Nikto-Style Misconfiguration Scan

```bash
# Run Nikto scanner (sensitive files, debug endpoints, misconfigs)
reconstrike-ng -t https://target.com --nikto

# Included automatically in full profile
reconstrike-ng -t https://target.com --profile full
```

### Static Analysis (SAST)

```bash
# Scan local source code for vulnerabilities
reconstrike-ng --sast-dir /path/to/source

# Combine DAST + SAST
reconstrike-ng -t https://target.com --sast-dir /path/to/source
```

SAST modules: hardcoded secrets, insecure functions, SQL injection patterns, insecure cryptography, path traversal risks, sensitive data exposure.

### DAST Interception Proxy

```bash
# Start passive analysis proxy
reconstrike-ng -t https://target.com --dast-proxy --proxy-port 8087

# Configure your browser to use http://127.0.0.1:8087 as proxy
# Import CA cert from ~/.reconstrike-ng/ca/ca.crt into browser
```

### Custom Headers & Cookies
```bash
reconstrike-ng -t https://target.com \
  --cookie "session=abc123; token=xyz" \
  --header "Authorization: Bearer eyJ..." \
  --header "X-Custom: value"
```

---

## Logging

ReconStrike-ng uses Python's structured logging system with configurable verbosity:

```bash
# Verbose output (DEBUG level)
reconstrike-ng -t https://target.com --verbose

# Quiet mode (WARNING and above only)
reconstrike-ng -t https://target.com --quiet

# Disable colored output (useful for piping/logging)
reconstrike-ng -t https://target.com --no-color

# Write logs to a file
reconstrike-ng -t https://target.com --log-file scan.log

# Combine flags
reconstrike-ng -t https://target.com --verbose --log-file debug.log --no-color
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

ReconStrike-ng integrates into CI/CD pipelines with exit codes based on severity thresholds:

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
          git clone https://github.com/Un-9oon/ReconStrike-ng.git
          cd ReconStrike-ng
          pip install -r requirements.txt

      - name: Run security scan
        run: |
          cd ReconStrike-ng
          reconstrike-ng \
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
          path: ReconStrike-ng/results.json
```

Exit codes: `0` = no findings above threshold, `1` = critical findings, `2` = high findings.

---

## Compliance

ReconStrike-ng maps findings to industry frameworks:

- **OWASP Top 10 (2021)** -- A01 through A10 category mapping with pass/fail
- **PCI DSS v4.0** -- Requirements 6.5.1 through 6.5.10

Use `--compliance` to generate the compliance report section in both CLI and HTML output.

---

## Disclaimer

This tool is intended for **authorized security testing only**. Only use ReconStrike-ng against systems you own or have explicit written permission to test. Unauthorized scanning is illegal. The authors are not responsible for misuse.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
