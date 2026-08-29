# Changelog

All notable changes to ReconStrike will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-08-29

### Features
- 43 scan modules covering OWASP Top 10, PCI DSS, and advanced attack categories
- Concurrent multi-threaded crawler with depth control and URL/form deduplication
- Adaptive Network Masking (ANM) — runtime IP/MAC/UA rotation via Tor, proxy pools, DHCP, and MAC spoofing
- Stealth mode with full browser profile emulation and human-like timing patterns
- WAF detection and automatic adaptive rate-limiting/evasion
- Technology stack fingerprinting and service identification
- DAST interception proxy with passive traffic analysis, CA certificate generation, and HAR export
- Network port scanning with service fingerprinting, CPE/CVE correlation, and NVD integration
- Static Application Security Testing (SAST) engine for local source code analysis
- Nikto-style misconfiguration and sensitive file scanning with false-positive fingerprinting
- Scan diffing — compare current results against previous baseline scans
- Compliance mapping for OWASP Top 10 and PCI DSS frameworks
- Professional HTML dark-theme reports with risk scoring, module summary cards, and findings tables
- PDF report generation with executive summary and detailed findings
- JSON output for CI/CD pipeline integration with configurable severity thresholds
- API endpoint discovery and testing
- 8 scan profiles: quick, standard, deep, aggressive, passive, api, owasp, full
- Authenticated scanning with credential-safe handling (file-based passwords, env vars)
- Docker containerized execution with non-root user and hash-verified dependencies
- Debian/Kali Linux packaging (.deb)
- Structured logging with --verbose, --quiet, --no-color, --log-file flags
- SIGINT handler for graceful shutdown with MAC address restoration

### Security
- Thread-safe findings and rate limiting with proper locks
- SSRF protection via private IP checking on all outbound requests
- Response size limiting (10MB cap) to prevent memory exhaustion
- Auth form domain validation — refuses cross-domain credential submission
- HTTP downgrade protection — blocks credential transmission over plain HTTP
- Credential redaction in reports, logs, and curl reproduction commands
- Path sanitization for all file output to prevent directory traversal
- Hostname validation before subprocess execution
- Secure file permissions (0o600 for reports, 0o700 for directories)
