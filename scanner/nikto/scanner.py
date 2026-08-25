"""Smart Nikto-style scanner with adaptive false-positive reduction.

Scans web servers for misconfigurations, dangerous files, debug endpoints,
and sensitive data leaks using the signature database.  Employs a
multi-layered false-positive reduction strategy:

1. **Adaptive 404 fingerprinting** — learns what the target's "not found"
   page looks like before scanning (hash-based and pattern-based).
2. **Content-based validation** — verifies that response bodies actually
   match the expected signature pattern, not just the status code.
3. **Soft-404 detection** — detects custom error pages that return HTTP 200
   for non-existent resources.
"""

import hashlib
import random
import re
import string
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

from scanner.core import Finding, Severity, ScanSession
from scanner.log import logger
from scanner.nikto.signatures import get_all_signatures, get_signature_count


# ---------------------------------------------------------------------------
# False-positive fingerprinting
# ---------------------------------------------------------------------------
class FPFingerprint:
    """Fingerprint a server's 'not found' responses for false-positive detection.

    Before scanning, we request several random non-existent paths and
    build a profile of what the server returns for missing pages.  This
    profile is then used to filter out false positives during the scan.
    """

    def __init__(self):
        self.fp_status_codes: set[int] = set()
        self.fp_body_hashes: set[str] = set()
        self.fp_body_lengths: set[int] = set()
        self.fp_body_patterns: list[str] = []
        self.fp_titles: set[str] = set()
        self.calibrated = False

    def calibrate(self, session: ScanSession, target: str, num_probes: int = 5):
        """Send random non-existent paths to learn the 404 fingerprint."""
        logger.info("Nikto: Calibrating false-positive detection...")

        for _ in range(num_probes):
            # Generate a random path that almost certainly doesn't exist
            rand_path = "/" + "".join(random.choices(string.ascii_lowercase, k=12))
            rand_ext = random.choice([".html", ".php", ".asp", ".jsp", "", ".bak"])
            probe_url = urljoin(target, rand_path + rand_ext)

            resp = session.get(probe_url, allow_redirects=False)
            if resp is None:
                continue

            self.fp_status_codes.add(resp.status_code)

            body = resp.text or ""
            body_hash = hashlib.md5(body.encode(errors="replace")).hexdigest()
            self.fp_body_hashes.add(body_hash)
            self.fp_body_lengths.add(len(body))

            # Extract page title
            title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            if title_match:
                self.fp_titles.add(title_match.group(1).strip().lower())

        self.calibrated = True
        logger.info(
            "Nikto: FP calibration complete — %d status codes, %d body hashes, %d titles",
            len(self.fp_status_codes), len(self.fp_body_hashes), len(self.fp_titles),
        )

    def is_false_positive(self, resp, signature: dict) -> bool:
        """Determine if a response is likely a false positive.

        Returns True if the response matches our 'not found' fingerprint
        and should be discarded.
        """
        if not self.calibrated:
            return False

        body = resp.text or ""
        body_hash = hashlib.md5(body.encode(errors="replace")).hexdigest()

        # Check 1: Exact body hash match with known 404 pages
        if body_hash in self.fp_body_hashes:
            return True

        # Check 2: Status code is a known soft-404 code AND no content match
        if resp.status_code in self.fp_status_codes and resp.status_code == 200:
            # The server returns 200 for non-existent pages (soft-404)
            # Only accept if the signature's content pattern matches
            if signature.get("match"):
                if not re.search(signature["match"], body, re.I):
                    return True
            else:
                # No content pattern to validate — likely false positive
                # Check body length similarity (within 10%)
                for fp_len in self.fp_body_lengths:
                    if fp_len > 0 and abs(len(body) - fp_len) / fp_len < 0.10:
                        return True

        # Check 3: Page title matches known 404 titles
        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if title_match:
            title = title_match.group(1).strip().lower()
            # Common 404 title patterns
            fp_keywords = ["not found", "404", "error", "page not found",
                           "does not exist", "unavailable", "missing"]
            if any(kw in title for kw in fp_keywords):
                # It's a 404 page that returned 200 — false positive
                if not signature.get("match") or not re.search(signature["match"], body, re.I):
                    return True

        return False


# ---------------------------------------------------------------------------
# Scanner engine
# ---------------------------------------------------------------------------
def _check_signature(session: ScanSession, target: str, sig: dict,
                     fp: FPFingerprint) -> dict | None:
    """Check a single signature against the target.

    Returns a finding dict if the signature matches, None otherwise.
    """
    url = urljoin(target, sig["path"])
    method = sig.get("method", "GET").upper()

    try:
        if method == "HEAD":
            resp = session.head(url, allow_redirects=False)
        elif method == "POST":
            # For POST signatures (like GraphQL), send a minimal probe
            resp = session.post(url, data="{}", headers={"Content-Type": "application/json"},
                                allow_redirects=False)
        else:
            resp = session.get(url, allow_redirects=False)
    except Exception:
        return None

    if resp is None:
        return None

    # Check if status code matches expected
    expected_statuses = sig.get("status", [200])
    if resp.status_code not in expected_statuses:
        return None

    # False-positive check
    if fp.is_false_positive(resp, sig):
        logger.debug("Nikto: FP filtered — %s (status %d)", sig["path"], resp.status_code)
        return None

    # Content pattern validation (if specified)
    if sig.get("match"):
        body = resp.text or ""
        if not re.search(sig["match"], body, re.I):
            return None

    # It's a real hit
    return {
        "path": sig["path"],
        "status_code": resp.status_code,
        "severity": sig["severity"],
        "category": sig["category"],
        "description": sig["description"],
        "cwe": sig.get("cwe", ""),
        "content_length": len(resp.text or ""),
        "url": url,
    }


def run(session: ScanSession) -> None:
    """Execute the Nikto-style misconfiguration scan."""
    target = session.config.target
    signatures = get_all_signatures()

    print(f"\n[*] Running Nikto-style misconfiguration scan ({get_signature_count()} signatures)...")

    # Phase 1: Calibrate false-positive detection
    fp = FPFingerprint()
    fp.calibrate(session, target)

    # Phase 2: Scan all signatures with concurrent workers
    hits = []
    total = len(signatures)
    scanned = 0

    workers = min(10, total)  # Limit concurrency to avoid overwhelming the target
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_check_signature, session, target, sig, fp): sig
            for sig in signatures
        }

        for future in as_completed(futures):
            scanned += 1
            if scanned % 20 == 0:
                print(f"  [*] Progress: {scanned}/{total} signatures checked...")

            result = future.result()
            if result:
                hits.append(result)

    # Phase 3: Report findings
    if not hits:
        print("  [+] No misconfigurations or sensitive files found.")
        return

    # Sort by severity
    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
                      Severity.LOW: 3, Severity.INFO: 4}
    hits.sort(key=lambda h: severity_order.get(h["severity"], 5))

    for hit in hits:
        session.add_finding(Finding(
            title=f"Nikto: {hit['description'][:80]}",
            severity=hit["severity"],
            description=hit["description"],
            evidence=f"Path: {hit['path']}\nHTTP Status: {hit['status_code']}\nContent-Length: {hit['content_length']}",
            remediation=(
                f"1. Remove or restrict access to {hit['path']}\n"
                f"2. Configure web server to deny access to sensitive files\n"
                f"3. Ensure no backup, debug, or configuration files are deployed to production"
            ),
            url=hit["url"],
            module="nikto",
            cwe=hit["cwe"],
            confirmed=True,
            location=hit["path"],
            detection_method=f"Nikto-style path enumeration with content-based validation and false-positive reduction (category: {hit['category']})",
            developer_fix=(
                f"Add the following to your web server configuration to block access:\n"
                f"  # Nginx:\n"
                f"  location ~ /{re.escape(hit['path'].lstrip('/'))} {{ return 404; }}\n"
                f"  # Apache:\n"
                f"  <Location \"{hit['path']}\">\n"
                f"    Require all denied\n"
                f"  </Location>"
            ),
        ))

    crit = sum(1 for h in hits if h["severity"] == Severity.CRITICAL)
    high = sum(1 for h in hits if h["severity"] == Severity.HIGH)
    med = sum(1 for h in hits if h["severity"] == Severity.MEDIUM)
    low = sum(1 for h in hits if h["severity"] in (Severity.LOW, Severity.INFO))

    print(f"  [+] Nikto scan complete: {len(hits)} findings "
          f"(CRITICAL:{crit} HIGH:{high} MEDIUM:{med} LOW/INFO:{low})")
