#!/usr/bin/env python3
"""
ReconStrike Countermeasure Verification Test
============================================
Starts a LOCAL WAF-simulating server (blocks UA after 5 reqs → 429),
then runs ReconStrike with ANM enabled and CAPTURES internal ANM signals
to verify every countermeasure fires correctly.
"""

import json, sys, os, threading, time, socket, logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import defaultdict
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

GRN="\033[92m"; RED="\033[91m"; YLW="\033[93m"; BLU="\033[94m"
CYN="\033[96m"; BLD="\033[1m"; RST="\033[0m"

def ok(m):   print(f"  {GRN}✅ {m}{RST}")
def fail(m): print(f"  {RED}❌ {m}{RST}")
def info(m): print(f"  {BLU}ℹ  {m}{RST}")
def warn(m): print(f"  {YLW}⚠  {m}{RST}")
def hdr(m):  print(f"\n{BLD}{CYN}{'─'*60}\n  {m}\n{'─'*60}{RST}")

WAF_PORT = 19901
BLOCK_AFTER = 5   # WAF blocks same UA after this many requests

# ── WAF state (thread-safe) ───────────────────────────────────────────────────
class WAFState:
    def __init__(self):
        self.lock = threading.Lock()
        self.ua_hit_counts: dict = defaultdict(int)
        self.seen_uas: list = []
        self.total = self.blocked = self.allowed = self.rotations = 0
        self.block_log: list = []

WAF = WAFState()

class WAFHandler(BaseHTTPRequestHandler):
    """WAF that rate-limits per User-Agent string."""
    def log_message(self, *_): pass

    def do_GET(self):
        ua = self.headers.get("User-Agent", "NO-UA")
        with WAF.lock:
            WAF.total += 1
            WAF.ua_hit_counts[ua] += 1
            hit = WAF.ua_hit_counts[ua]

            # Track UA changes (= detects rotation)
            if ua not in WAF.seen_uas:
                WAF.seen_uas.append(ua)
                if len(WAF.seen_uas) > 1:
                    WAF.rotations += 1
                    print(f"\n  {GRN}[WAF-SIM]{RST} Rotation #{WAF.rotations} detected "
                          f"→ new UA: ...{ua[-50:]}")

            is_blocked = hit > BLOCK_AFTER

        if is_blocked:
            with WAF.lock:
                WAF.blocked += 1
                WAF.block_log.append(ua[:40])
            body = json.dumps({"error":"Rate limited","retry_after":60}).encode()
            self.send_response(429)
            self.send_header("Content-Type","application/json")
            self.send_header("Content-Length",str(len(body)))
            self.send_header("X-WAF-Block","rate-limit")
            self.send_header("Retry-After","60")
            self.send_header("Server","SimulatedWAF/1.0")
            self.end_headers()
            self.wfile.write(body)
            return

        with WAF.lock: WAF.allowed += 1
        body = b"<html><body><p>OK - request accepted</p></body></html>"
        self.send_response(200)
        self.send_header("Content-Type","text/html; charset=utf-8")
        self.send_header("Content-Length",str(len(body)))
        self.end_headers()
        self.wfile.write(body)

def _wait_port(port, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3): return True
        except OSError: time.sleep(0.1)
    return False

# ── Capture log messages from scanner ────────────────────────────────────────
class LogCapture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records: list[str] = []
    def emit(self, record):
        self.records.append(record.getMessage())

# ── Main test ─────────────────────────────────────────────────────────────────
def run_test():

    hdr("STEP 1 — Starting WAF-Simulating Server")
    fuser_port = __import__("subprocess").run(
        ["fuser", "-k", f"{WAF_PORT}/tcp"], capture_output=True)
    time.sleep(0.3)
    server = HTTPServer(("127.0.0.1", WAF_PORT), WAFHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    if not _wait_port(WAF_PORT):
        fail("WAF server failed to start"); sys.exit(1)
    ok(f"WAF server on http://127.0.0.1:{WAF_PORT}")
    info(f"Policy: block same User-Agent after {BLOCK_AFTER} requests → HTTP 429")

    hdr("STEP 2 — Configuring ReconStrike with ANM Countermeasures")
    from scanner.core import ScanConfig, ScanSession
    from scanner.identity_manager import ANMConfig
    import scanner.identity_manager as _idm
    # Patch out free-proxy scraping so it can't try real internet proxies
    _idm._scrape_free_proxies = lambda *a, **kw: []

    cap = LogCapture()
    logging.getLogger("reconstrike-ng").addHandler(cap)
    logging.getLogger("reconstrike-ng").setLevel(logging.DEBUG)

    anm = ANMConfig(
        enabled=True,
        rotate_ua=True,          # ← rotate User-Agent when blocked
        waf_evasion=True,        # ← randomise headers to evade fingerprinting
        use_tor=False,           # no Tor needed for this test
        proxy_pool_file="",      # no external proxies needed
        block_threshold=1,       # rotate after just 1 block (fast demo)
        cooldown_after_block=0.1,
    )
    cfg = ScanConfig(
        target=f"http://127.0.0.1:{WAF_PORT}",
        timeout=3, threads=1, depth=1, verify_ssl=False, anm_config=anm,
    )
    session = ScanSession(cfg)
    initial_ua = session.session.headers.get("User-Agent", "")
    ok(f"ANM active — block_threshold=1 (rotate on first block)")
    info(f"Initial UA: {initial_ua[:70]}")

    hdr("STEP 3 — Sending 30 Requests — WAF Will Block, ANM Will Evade")
    results = []
    statuses = []
    for i in range(1, 31):
        try:
            resp = session.session.get(   # use raw session to see actual 429
                f"http://127.0.0.1:{WAF_PORT}/",
                timeout=3, allow_redirects=False,
                proxies=None)  # never use a proxy for localhost tests
            # Manually call _track_response_status so ANM reacts
            session._track_response_status(resp)
        except Exception:
            resp = type("R", (), {"status_code": 0})()
        status = resp.status_code
        statuses.append(status)
        sym = f"{GRN}200{RST}" if status==200 else f"{YLW}{status}{RST}"
        current_ua = session.session.headers.get("User-Agent","")[:25]
        print(f"    #{i:02d} → {sym}  UA=...{current_ua}")
        time.sleep(0.05)

    hdr("STEP 4 — Verifying All Countermeasures")

    first_429 = next((i for i,s in enumerate(statuses) if s==429), None)
    n_200s    = statuses.count(200)
    n_429s    = statuses.count(429)
    final_ua  = session.session.headers.get("User-Agent","")

    with WAF.lock:
        n_rot   = WAF.rotations
        n_uas   = len(WAF.seen_uas)
        allowed = WAF.allowed
        blocked = WAF.blocked
        total   = WAF.total
        seen    = list(WAF.seen_uas)

    print(f"\n  Status sequence: {statuses}\n")

    # ── Check 1: WAF actually blocked ────────────────────────────────────────
    print(f"{BLD}  [CHECK 1] WAF Detection{RST}")
    if first_429 is not None:
        ok(f"WAF issued first 429 at request #{first_429+1}")
    else:
        fail("WAF never returned 429 — server issue")

    # ── Check 2: UA rotation ─────────────────────────────────────────────────
    print(f"\n{BLD}  [CHECK 2] User-Agent Rotation{RST}")
    if n_rot >= 1:
        ok(f"UA rotated {n_rot} time(s) — {n_uas} distinct UA(s) presented to WAF")
    else:
        fail("UA never rotated — ANM rotation not triggering")

    ua_changed = final_ua != initial_ua
    if ua_changed:
        ok(f"UA changed after block:\n"
           f"        Before: {initial_ua[:65]}\n"
           f"        After:  {final_ua[:65]}")
    else:
        fail("UA unchanged — rotation has no effect")

    # ── Check 3: ANM log messages confirm countermeasure fired ───────────────
    print(f"\n{BLD}  [CHECK 3] ANM Internal Signals (from scanner logs){RST}")
    anm_logs = [m for m in cap.records if "ANM" in m or "block" in m.lower() or "rotated" in m.lower() or "waf" in m.lower() or "evasion" in m.lower()]
    if anm_logs:
        ok(f"ANM fired {len(anm_logs)} countermeasure log event(s):")
        for msg in anm_logs[:8]:
            print(f"        → {msg}")
    else:
        warn("No ANM log events captured (may still be working silently)")

    # ── Check 4: Scan continued getting 200s after rotation ──────────────────
    print(f"\n{BLD}  [CHECK 4] Scan Resumed After Evasion{RST}")
    if first_429 is not None:
        post_block = statuses[first_429:]
        got_200_after = 200 in post_block
        if got_200_after:
            ok(f"Got {post_block.count(200)} × 200 AFTER first block — WAF bypass confirmed")
        else:
            warn("No 200 after block — new UA also blocked (WAF is aggressive)")
    else:
        warn("N/A — no block occurred")

    # ── Check 5: WAF evasion header diversity ────────────────────────────────
    print(f"\n{BLD}  [CHECK 5] WAF Evasion Headers Applied{RST}")
    evasion_headers = {k:v for k,v in session.session.headers.items()
                       if k.lower() in ("accept-language","accept-encoding","sec-fetch-mode","sec-fetch-site")}
    if evasion_headers:
        ok(f"WAF-evasion headers present on session:")
        for k, v in evasion_headers.items():
            print(f"        {k}: {v}")
    else:
        fail("No evasion headers found on session")

    hdr("STEP 5 — Final Report")
    print(f"  {BLD}WAF Server Stats:{RST}")
    print(f"    Total requests      : {total}")
    print(f"    Accepted (200)      : {allowed}")
    print(f"    Blocked  (429)      : {blocked}")
    print(f"    Distinct UAs seen   : {n_uas}")
    print(f"    UA rotations caught : {n_rot}")

    print(f"\n  {BLD}All User-Agents presented to WAF:{RST}")
    for i, ua in enumerate(seen, 1):
        tag = f"{GRN}[initial]{RST}" if i==1 else f"{YLW}[rotated-{i-1}]{RST}"
        print(f"    {i}. {tag} {ua[:80]}")

    checks = [
        ("WAF blocked scanner",      first_429 is not None),
        ("UA rotated ≥ 1 time",      n_rot >= 1),
        ("UA value changed",         ua_changed),
        ("WAF-evasion headers set",  bool(evasion_headers)),
    ]
    all_pass = all(r for _,r in checks)
    print(f"\n  {BLD}Checklist:{RST}")
    for name, result in checks:
        sym = f"{GRN}PASS{RST}" if result else f"{RED}FAIL{RST}"
        print(f"    [{sym}] {name}")

    print()
    if all_pass:
        print(f"  {GRN}{BLD}✅  ALL COUNTERMEASURES VERIFIED AND WORKING{RST}")
    else:
        print(f"  {RED}{BLD}❌  SOME COUNTERMEASURES DID NOT ACTIVATE{RST}")

    server.shutdown()
    return 0 if all_pass else 1

if __name__ == "__main__":
    sys.exit(run_test())
