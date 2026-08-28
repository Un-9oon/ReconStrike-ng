import json
import os
from datetime import datetime, timezone

from scanner.core import ScanSession
from scanner.log import logger

SCAN_HISTORY_DIR = os.path.expanduser("~/.reconstrike-ng/history")


def _safe_domain(target: str) -> str:
    import re
    from urllib.parse import urlparse
    domain = urlparse(target).netloc.replace(":", "_")
    return re.sub(r'[^a-zA-Z0-9._-]', '', domain) or "unknown"


def save_scan_results(session: ScanSession):
    os.makedirs(SCAN_HISTORY_DIR, mode=0o700, exist_ok=True)
    domain = _safe_domain(session.config.target)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(SCAN_HISTORY_DIR, "{}_{}.json".format(domain, timestamp))

    finding_fields = ["title", "severity", "description", "evidence", "remediation",
                      "url", "module", "cwe", "confirmed", "location", "parameter",
                      "payload", "curl_command", "reproduction_steps", "developer_fix",
                      "affected_component", "request_method", "response_status"]

    data = {
        "target": session.config.target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "duration": (session.end_time or 0) - (session.start_time or 0),
        "urls_scanned": len(session.crawled_urls),
        "forms_found": len(session.forms),
        "findings": [
            {k: (getattr(f, k).value if k == "severity" else getattr(f, k))
             for k in finding_fields}
            for f in session.findings
        ],
    }

    for dest in [filepath, os.path.join(SCAN_HISTORY_DIR, "{}_latest.json".format(domain))]:
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2)

    return filepath


def load_previous_scan(target: str) -> dict | None:
    latest = os.path.join(SCAN_HISTORY_DIR, "{}_latest.json".format(_safe_domain(target)))
    if not os.path.exists(latest):
        return None
    with open(latest) as fh:
        return json.load(fh)


def compute_diff(previous: dict, current_session: ScanSession) -> dict:
    prev_findings = {(f["title"], f["url"], f["module"]): f for f in previous.get("findings", [])}
    curr_findings = {(f.title, f.url, f.module): f for f in current_session.findings}

    prev_keys, curr_keys = set(prev_findings), set(curr_findings)

    return {
        "new": [curr_findings[k] for k in curr_keys - prev_keys],
        "fixed": [prev_findings[k] for k in prev_keys - curr_keys],
        "persistent": [curr_findings[k] for k in curr_keys & prev_keys],
        "previous_timestamp": previous.get("timestamp", "Unknown"),
        "previous_total": len(previous.get("findings", [])),
        "current_total": len(current_session.findings),
    }


def print_diff(diff: dict):
    def _get_attr(f, attr):
        return getattr(f, attr) if hasattr(f, attr) else f.get(attr, "?")

    logger.info("=" * 60)
    logger.info("SCAN COMPARISON (vs %s)", diff['previous_timestamp'][:19])
    logger.info("=" * 60)
    logger.info("  Previous: %d findings", diff['previous_total'])
    logger.info("  Current:  %d findings", diff['current_total'])

    if diff["new"]:
        logger.info("NEW VULNERABILITIES (%d)", len(diff['new']))
        for f in diff["new"]:
            sev = _get_attr(f, "severity")
            sev = sev.value if hasattr(sev, "value") else sev
            logger.info("  [+] [%s] %s", sev, _get_attr(f, "title"))

    if diff["fixed"]:
        logger.info("FIXED VULNERABILITIES (%d)", len(diff['fixed']))
        for f in diff["fixed"]:
            sev = _get_attr(f, "severity")
            sev = sev.value if hasattr(sev, "value") else sev
            logger.info("  [-] [%s] %s", sev, _get_attr(f, "title"))

    if diff["persistent"]:
        logger.info("PERSISTENT (%d)", len(diff['persistent']))
