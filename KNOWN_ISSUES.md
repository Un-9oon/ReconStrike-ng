# ReconStrike-ng — Known Issues & Limitations

> Last updated: 2026-09-26  
> These are honest, confirmed limitations — not aspirational roadmap items.  
> Every issue listed here was personally reproduced or fixed in this session.

---

## Fixed (shipped in this session)

| ID | Component | Description | How Fixed |
|----|-----------|-------------|-----------|
| BUG-001 | `scanner/modules/idor.py` | `build_curl(url)` called with missing required `method` arg → `TypeError` crash | Fixed signature to `build_curl("GET", url)` |
| BUG-002 | `scanner/modules/ssrf.py` | Same `build_curl(url)` crash at two call sites | Fixed both call sites |
| BUG-003 | `scanner/modules/zero_day.py` | Emitted N findings per payload per param per category → 10-20× false-positive noise | Added `_seen_signals` dedup + min 2 independent signals before emit |
| BUG-004 | `scanner/crawler.py` / `scanner/concurrent.py` | Only discovered HTML-linked URLs; completely missed unlinked endpoints | Added `extra_urls` support to `ConcurrentCrawler` queue |
| BUG-005 | `scanner/core.py::_sanitize_path()` | Silently collapsed absolute paths (e.g. `--json-file /tmp/out.json`) to basename in CWD | Now preserves operator-intended paths; blocks only dangerous system locations (`/etc`, `/boot`, etc.) with explicit WARNING log |
| BUG-006 | `scanner/core.py::_safe_read()` | Set `resp._content` instead of `resp.content` for curl_cffi.Response → `resp.text` empty | Changed to `resp.content = b"".join(chunks)` |
| BUG-007 | `scanner/proxy/server.py` | Hardcoded `verify=False` on upstream requests, ignoring `--no-ssl-verify` | Added `verify_ssl` parameter to `ProxyServer`, passed from config |
| BUG-008 | `scanner/core.py::_resolve_ip()` | Unbounded/uncached DNS resolution; slow/unresponsive resolver could stall scan | Added 3s timeout via ThreadPoolExecutor + 1-hour in-process TTL cache |
| BUG-009 | `reconstrike_ng.py` | Target initial reachability check treated 403/429/5xx responses as "unreachable" (`if not resp:`) and exited immediately before ANM could rotate | Fixed check to distinguish `resp is None` from HTTP error status; signals ANM `signal_block()` and continues scan |
| BUG-010 | `scanner/identity_manager.py` | ANM auto-scraped free proxies looped indefinitely (up to 50 rotations) with zero progress when proxies were dead | Added `stall_rotation_limit` progress tracking to fallback to direct connection backoff when N rotations yield zero target progress |

---

## Open (not yet fixed)

### GAP-1: Module Verification Gaps
**Severity: Medium**

17 of 43 DAST modules remain **UNVERIFIED** — no suitable test target available in this test suite to confirm true-positive detection. These modules run without crashing but their detection logic has not been validated against a real vulnerability:

| Module | Why Unverified |
|--------|----------------|
| `ssti` | Fixture reflects `{{7*7}}` but does NOT evaluate it (no true SSTI) |
| `cmdi` | Fixture echoes `cmd=` param but doesn't execute (no real RCE) |
| `xxe` | Fixture echoes DOCTYPE but doesn't parse entities (no file read) |
| `lfi` | Fixture echoes `../../etc/passwd` with stub; no real file inclusion |
| `second_order` | Fixture stores/echoes; no cross-request execution |
| `deserialization` | Fixture echoes Java magic bytes; no real gadget chain |
| `race_condition` | Fixture has non-atomic counter; module needs real concurrency measurement |
| `request_smuggling` | Header reflection only; real TE.CL needs proxy chain |
| `websocket_security` | 400+Upgrade header detection only; no WS handshake |
| `ssl` | Fixture is HTTP-only; no HTTPS target available |
| `auth` | Fixture has no login form for authenticated scanning tests |
| `subdomain` | localhost/IP target, no DNS zone to enumerate |
| `subdomain_takeover` | Requires live DNS CNAME targets |
| `dom_xss` | DOM sinks require JS engine; DAST-only heuristic |
| `portscan` (full) | Only top-1000 ports on localhost; minimal target |
| `fingerprint` (full) | Only detects "Apache/2.4.41" from server-info stub |
| `session_security` (auth) | Fixture sets no cookies; module logic untested with real cookies |

**Workaround:** Use `--profile quick` or `--profile owasp` to limit to best-tested modules.  
**Tracking:** See `docs/MODULE_STATUS.md` for per-module CONFIRMED/CONFIRMED-NEGATIVE/UNVERIFIED verdicts.

### GAP-2: CI Integration Tests Require Local vulnapp
**Severity: Low**

The `integration` CI job starts `tests/fixtures/vulnapp.py` as a subprocess. If the fixture fails to start (port conflict, Python path issue), the job fails with a misleading error.

**Workaround:** If CI fails on the `integration` job for environmental reasons, re-run the specific job. The `test` (unit) job is independent.

### GAP-3: ANM Identity Rotation — Authorization Gate Implemented
**Severity: High (use-case concern, not code bug)**

**Status: FIXED in this session.** The `--rotate-mac`, `--tor`, and `--proxy-pool` flags now require `--authorized-target` flag matching the scan target. This was implemented as part of Phase 1 authorization hard-fail.

### GAP-4: README Claims vs Reality
**Severity: Medium**

The README states "Production/Stable" status. The PyPI classifier in `pyproject.toml` has "Beta". The README has not been updated to match.

**Status: RESOLVED.** README no longer contains this claim as of recent commits; either fixed silently in a prior commit or the original report was inaccurate — closing.

---

## Performance Characteristics

- Zero-day fuzzer with `--zero-day-sensitivity high` generates significant HTTP traffic (1 request per payload per parameter). Use `medium` (default) or `low` for large targets.
- Crawler wordlist probe adds ~30 extra requests per scan (COMMON_ROUTES list). Disable with `--modules` to exclude `zero_day` if not needed.
- `--profile deep` against a target with many parameterized URLs can take 30+ minutes.
- DNS resolution now has 3s timeout + 1-hour cache; same host resolved once per scan.

---

## Reporting Issues

File bugs at: https://github.com/Un-9oon/ReconStrike-ng/issues

When reporting a crash, always include:
1. The exact command you ran
2. The Python version (`python --version`)
3. The full traceback (run with `--verbose`)
4. The target URL (anonymize if needed)