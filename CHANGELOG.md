# Changelog

All notable changes to ReconStrike-ng will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [3.1.0] - 2026-07-25

### Added
- 14 new scan modules: request_smuggling, websocket_security, race_condition, cache_poisoning, dom_xss, prototype_pollution, mass_assignment, ldap_injection, oauth_misconfig, open_redirect, http_method, business_logic, second_order, host_header
- Python logging module with --verbose, --quiet, --no-color, --log-file flags
- Test suite with pytest (tests for core, modules, reporter, CLI, diff_scan)
- GitHub Actions CI/CD pipeline (Python 3.10-3.12, linting)
- pyproject.toml for modern Python packaging
- MANIFEST.in for sdist builds
- CHANGELOG.md and CONTRIBUTING.md
- --list-modules CLI flag
- --password-file and RECONSTRIKE_PASSWORD env var for secure credential handling
- --no-color flag for non-TTY environments
- Kali Linux packaging files (debian/, desktop entry)

### Changed
- Version bumped to 3.1.0 with single source of truth in scanner/__init__.py
- All print() calls replaced with structured logging
- Silent except Exception: pass replaced with logger.debug() calls
- api_scanner.py now uses safe session instead of raw requests.Session()

### Fixed
- Removed unused dependencies (jinja2, python-nmap)
- Added missing fpdf2 to setup.py install_requires
- Fixed duplicate requests entry in requirements.txt
- Password no longer visible in ps output (warning + alternatives added)

### Security
- Thread-safe findings and rate limiting with proper locks
- SSRF protection via private IP checking
- Response size limiting (10MB cap)
- Auth form domain validation
- Credential redaction in reports and curl commands

## [3.0.0] - 2026-07-23

### Added
- 29 scan modules covering OWASP Top 10 + advanced categories
- CVE database integration with active exploit testing
- Zero-day heuristic fuzzing engine
- Session security, GraphQL, HPP, NoSQL injection, subdomain takeover, deserialization modules
- "How It Was Found" detection method in reports
- Findings summary table at end of reports
- Scan diffing and baseline comparison
- Auto-evasion and adaptive rate limiting
- WAF detection and technology fingerprinting
- Compliance mapping (OWASP, PCI DSS)
- 8 scan profiles (quick, standard, deep, aggressive, passive, api, owasp, full)
- HTML dark-theme reports, PDF reports, JSON output

## [2.0.0] - 2026-07-20

### Added
- Initial modular scanner framework
- Core vulnerability modules (SQL injection, XSS, CSRF, SSRF, etc.)
- Concurrent crawler with thread pool
- HTML and JSON reporting
