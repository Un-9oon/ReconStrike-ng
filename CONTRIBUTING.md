# Contributing to ReconStrike

Thank you for your interest in contributing to ReconStrike. This guide will help you get started.

## Development Setup

1. Fork and clone the repository:

```bash
git clone https://github.com/<your-username>/ReconStrike-ng.git
cd ReconStrike-ng
```

2. Create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt  # pytest, black, flake8
```

4. Verify everything works:

```bash
python3 -m pytest tests/ -v
```

## Adding a New Scan Module

All scan modules live in `scanner/modules/`. Each module must follow this structure:

```python
"""
Module: module_name
Description: Brief description of what this module detects.
"""

import logging

logger = logging.getLogger(__name__)


def run(session):
    """
    Run the scan module.

    Args:
        session: ScanSession object providing:
            - session.target_url: The target URL
            - session.crawled_urls: Set of discovered URLs
            - session.forms: List of discovered forms
            - session.session: requests.Session with auth cookies
            - session.config: ScanConfig with rate_limit, depth, etc.
            - session.add_finding(): Report a vulnerability

    Returns:
        list: List of Finding objects (also added via session.add_finding)
    """
    findings = []
    logger.info("Starting module_name scan on %s", session.target_url)

    # Your detection logic here

    for url in session.crawled_urls:
        # Test each URL
        try:
            response = session.session.get(url, timeout=10)
            # Analyze response...

            if vulnerability_detected:
                finding = session.add_finding(
                    title="Vulnerability Title",
                    severity="HIGH",  # CRITICAL, HIGH, MEDIUM, LOW, INFO
                    url=url,
                    description="What was found and why it matters.",
                    evidence="The specific response data proving the issue",
                    remediation="How to fix this vulnerability.",
                    detection_method="How ReconStrike detected this issue",
                )
                findings.append(finding)

        except Exception as e:
            logger.debug("Error testing %s: %s", url, e)

    logger.info("module_name scan complete: %d findings", len(findings))
    return findings
```

After creating the module file:

1. Register it in `scanner/core.py` in the `MODULES` dictionary
2. Add it to the appropriate scan profiles
3. Write tests in `tests/test_modules.py`
4. Update the module count in `README.md`

## Code Style

- **Formatter:** black (line length 120)
- **Linter:** flake8 (max line length 120)
- **Imports:** stdlib first, then third-party, then local (isort order)
- **Docstrings:** Required for all public functions and classes
- **Logging:** Use `logger.debug/info/warning/error` -- never bare `print()`
- **Error handling:** Always log exceptions, never use bare `except: pass`

Run before committing:

```bash
black --line-length 120 scanner/ tests/ reconstrike.py
flake8 --max-line-length 120 scanner/ tests/ reconstrike.py
```

## Testing

All new modules must include tests. Tests live in the `tests/` directory.

```bash
# Run all tests
python3 -m pytest tests/ -v

# Run tests for a specific area
python3 -m pytest tests/test_modules.py -v

# Run with coverage
python3 -m pytest tests/ --cov=scanner --cov-report=term-missing
```

Test requirements:

- Every new module must have at least one test in `test_modules.py`
- Tests must not make real network requests (use `unittest.mock` or `responses`)
- Tests must pass on Python 3.10, 3.11, and 3.12

## Pull Request Process

1. Create a feature branch from `main`:

```bash
git checkout -b feature/my-new-module
```

2. Make your changes, following the code style guidelines above.

3. Run the full test suite and linters:

```bash
black --line-length 120 --check .
flake8 --max-line-length 120 scanner/ tests/
python3 -m pytest tests/ -v
```

4. Commit with a clear message:

```bash
git commit -m "Add module_name scan module for detecting X"
```

5. Push and open a pull request against `main`.

6. In your PR description, include:
   - What the change does
   - How to test it
   - Any new dependencies added

## Security Vulnerability Reporting

If you discover a security vulnerability in ReconStrike itself (not in a target being scanned), **do not open a public issue**.

Instead, report it privately:

- Email: cyphersec.404@gmail.com
- Subject: `[SECURITY] ReconStrike vulnerability report`
- Include: description, reproduction steps, and impact assessment

You will receive a response within 48 hours. We will coordinate disclosure after a fix is available.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you agree to uphold a welcoming, inclusive, and harassment-free environment.
