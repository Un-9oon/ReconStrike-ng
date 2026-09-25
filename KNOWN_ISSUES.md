# ReconStrike-ng — Known Issues & Limitations

> Last updated: 2026-09-25  
> These are honest, confirmed limitations — not aspirational roadmap items.

---

## Fixed (shipped in this patch)

| ID | Component | Description | Fixed in |
|----|-----------|-------------|----------|
| BUG-001 | `scanner/modules/idor.py` | `build_curl(url)` called with missing required `method` arg → `TypeError` crash on any profile that includes `idor` module | v1.0.1 |
| BUG-002 | `scanner/modules/ssrf.py` | Same `build_curl(url)` crash at two call sites | v1.0.1 |
| BUG-003 | `scanner/modules/zero_day.py` | Emitted N findings per payload per param per category → 10-20× false-positive noise | v1.0.1 |
| BUG-004 | `scanner/crawler.py` | Only discovered HTML-linked URLs; completely missed unlinked endpoints like `/admin`, `/api/*`, `.env` | v1.0.1 |

---

## Open (not yet fixed)

### GAP-4: Module Verification Status Unknown
**Severity: Medium**

43 DAST modules exist, but only 2 have been systematically exercised against a deliberate target:
- `xss` — verified against `/xss?q=` endpoint  
- `sqli` — verified against `/sqli?id=` endpoint  

The remaining 41 modules have only been import-tested and signature-tested (unit tests), not end-to-end detection-tested. Some may have incorrect detection logic or dead code paths.

**Workaround:** Use `--profile quick` to limit exposure to the most-tested modules.  
**Tracking:** `docs/MODULE_STATUS.md` will be added once each module is verified.

### GAP-5: CI Integration Tests Require Local vulnapp
**Severity: Low**

The new `integration` CI job starts `tests/fixtures/vulnapp.py` as a subprocess. If the fixture fails to start (port conflict, Python path issue), the job will fail with a misleading error.

**Workaround:** If CI fails on the `integration` job for environmental reasons, re-run the specific job. The `test` (unit) job is independent.

### GAP-6: ANM Identity Rotation — No Authorization Gate
**Severity: High (use-case concern, not code bug)**

The `--rotate-mac` and `--anm` flags rotate MAC address and User-Agent without requiring explicit authorization confirmation. These are powerful capabilities that MUST only be used against systems you have written permission to test.

**Current state:** The tool warns via `logger.warning()` but does not require an `--i-have-authorization` flag.  
**Risk:** Accidental or malicious use against unauthorized targets.  
**Planned fix:** `--rotate-mac` will require `--authorized-target` flag in v1.1.0.

### GAP-7: README Claims vs Reality
**Severity: Medium**

The README states "Production/Stable" status. The PyPI classifier has been downgraded to "Beta". The README has not yet been updated to match.

**Planned fix:** README update pass in v1.1.0.

---

## Performance Characteristics

- Zero-day fuzzer with `--zero-day-sensitivity high` generates significant HTTP traffic (1 request per payload per parameter). Use `medium` (default) or `low` for large targets.
- Crawler wordlist probe adds ~30 extra requests per scan (COMMON_ROUTES list). Disable with `--modules` to exclude `zero_day` if not needed.
- `--profile deep` against a target with many parameterized URLs can take 30+ minutes.

---

## Reporting Issues

File bugs at: https://github.com/Un-9oon/ReconStrike-ng/issues

When reporting a crash, always include:
1. The exact command you ran
2. The Python version (`python --version`)
3. The full traceback (run with `--verbose`)
4. The target URL (anonymize if needed)
