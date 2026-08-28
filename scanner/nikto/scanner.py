import hashlib
import random
import re
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

import requests

from scanner.core import Finding, Severity, ScanSession
from scanner.log import logger
from scanner.nikto.signatures import get_all_signatures, get_signature_count


class FPFingerprint:
    """Learns what a server's 404 looks like to filter false positives."""

    def __init__(self):
        self.fp_status_codes: set[int] = set()
        self.fp_body_hashes: set[str] = set()
        self.fp_body_lengths: set[int] = set()
        self.fp_titles: set[str] = set()
        self.calibrated = False

    def calibrate(self, session: ScanSession, target: str, num_probes: int = 5):
        logger.info("Nikto: Calibrating false-positive detection...")

        for _ in range(num_probes):
            rand_path = "/" + "".join(random.choices(string.ascii_lowercase, k=12))
            rand_ext = random.choice([".html", ".php", ".asp", ".jsp", "", ".bak"])
            resp = session.get(urljoin(target, rand_path + rand_ext), allow_redirects=False)
            if resp is None:
                continue

            self.fp_status_codes.add(resp.status_code)
            body = resp.text or ""
            self.fp_body_hashes.add(hashlib.sha256(body.encode(errors="replace")).hexdigest())
            self.fp_body_lengths.add(len(body))

            title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            if title_match:
                self.fp_titles.add(title_match.group(1).strip().lower())

        self.calibrated = True
        logger.info("Nikto: FP calibration done -- %d codes, %d hashes, %d titles",
                     len(self.fp_status_codes), len(self.fp_body_hashes), len(self.fp_titles))

    def is_false_positive(self, resp, signature: dict) -> bool:
        if not self.calibrated:
            return False

        body = resp.text or ""
        body_hash = hashlib.sha256(body.encode(errors="replace")).hexdigest()

        if body_hash in self.fp_body_hashes:
            return True

        # Soft-404: server returns 200 for nonexistent pages
        if resp.status_code in self.fp_status_codes and resp.status_code == 200:
            if signature.get("match"):
                if not re.search(signature["match"], body, re.I):
                    return True
            else:
                for fp_len in self.fp_body_lengths:
                    if fp_len > 0 and abs(len(body) - fp_len) / fp_len < 0.10:
                        return True

        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if title_match:
            title = title_match.group(1).strip().lower()
            fp_keywords = ["not found", "404", "error", "page not found",
                           "does not exist", "unavailable", "missing"]
            if any(kw in title for kw in fp_keywords):
                if not signature.get("match") or not re.search(signature["match"], body, re.I):
                    return True

        return False


def _check_signature(session: ScanSession, target: str, sig: dict,
                     fp: FPFingerprint) -> dict | None:
    url = urljoin(target, sig["path"])
    method = sig.get("method", "GET").upper()

    try:
        if method == "HEAD":
            resp = session.head(url, allow_redirects=False)
        elif method == "POST":
            resp = session.post(url, data="{}", headers={"Content-Type": "application/json"},
                                allow_redirects=False)
        else:
            resp = session.get(url, allow_redirects=False)
    except (requests.RequestException, ValueError):
        return None

    if resp is None or resp.status_code not in sig.get("status", [200]):
        return None

    if fp.is_false_positive(resp, sig):
        logger.debug("Nikto: FP filtered -- %s (status %d)", sig["path"], resp.status_code)
        return None

    if sig.get("match") and not re.search(sig["match"], resp.text or "", re.I):
        return None

    return {
        "path": sig["path"], "status_code": resp.status_code,
        "severity": sig["severity"], "category": sig["category"],
        "description": sig["description"], "cwe": sig.get("cwe", ""),
        "content_length": len(resp.text or ""), "url": url,
    }


def run(session: ScanSession) -> None:
    target = session.config.target
    signatures = get_all_signatures()
    logger.info("Running Nikto-style misconfiguration scan (%d signatures)...", get_signature_count())

    fp = FPFingerprint()
    fp.calibrate(session, target)

    hits = []
    total = len(signatures)
    scanned = 0

    with ThreadPoolExecutor(max_workers=min(10, total)) as executor:
        futures = {executor.submit(_check_signature, session, target, sig, fp): sig
                   for sig in signatures}
        for future in as_completed(futures):
            scanned += 1
            if scanned % 20 == 0:
                logger.info("Nikto: %d/%d checked...", scanned, total)
            result = future.result()
            if result:
                hits.append(result)

    if not hits:
        logger.info("Nikto: No misconfigurations found.")
        return

    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
                      Severity.LOW: 3, Severity.INFO: 4}
    hits.sort(key=lambda h: severity_order.get(h["severity"], 5))

    for hit in hits:
        session.add_finding(Finding(
            title="Nikto: {}".format(hit['description'][:80]),
            severity=hit["severity"],
            description=hit["description"],
            evidence="Path: {}\nHTTP Status: {}\nContent-Length: {}".format(
                hit['path'], hit['status_code'], hit['content_length']),
            remediation=(
                "1. Remove or restrict access to {}\n"
                "2. Configure web server to deny access to sensitive files\n"
                "3. Ensure no backup, debug, or configuration files are deployed to production"
            ).format(hit['path']),
            url=hit["url"], module="nikto", cwe=hit["cwe"], confirmed=True,
            location=hit["path"],
            detection_method="Nikto-style path enumeration with content validation and FP reduction (category: {})".format(hit['category']),
            developer_fix=(
                "Add the following to your web server configuration to block access:\n"
                "  # Nginx:\n"
                "  location ~ /{path} {{ return 404; }}\n"
                "  # Apache:\n"
                "  <Location \"{raw_path}\">\n"
                "    Require all denied\n"
                "  </Location>"
            ).format(path=re.escape(hit['path'].lstrip('/')), raw_path=hit['path']),
        ))

    by_sev = {s: sum(1 for h in hits if h["severity"] == s)
              for s in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]}
    low_info = sum(1 for h in hits if h["severity"] in (Severity.LOW, Severity.INFO))
    logger.info("Nikto: %d findings (CRITICAL:%d HIGH:%d MEDIUM:%d LOW/INFO:%d)",
                len(hits), by_sev[Severity.CRITICAL], by_sev[Severity.HIGH],
                by_sev[Severity.MEDIUM], low_info)
