#!/usr/bin/env python3
"""
Run all 43 modules individually against vulnapp and save findings to CSV.
This creates the baseline artifact for Phase 0.
"""
import subprocess
import csv
import time
import json
import os

ALL_MODULES = [
    "fingerprint", "portscan", "subdomain", "headers", "ssl", "sqli", "xss",
    "ssti", "csrf", "ssrf", "xxe", "lfi", "cmdi", "idor", "jwt", "upload",
    "directory", "info", "auth", "misconfig", "cors", "session_security",
    "cve_check", "zero_day", "nosql", "subdomain_takeover", "hpp", "graphql",
    "deserialization", "business_logic", "cache_poisoning", "dom_xss",
    "host_header", "http_method", "ldap_injection", "mass_assignment",
    "oauth_misconfig", "open_redirect", "prototype_pollution", "race_condition",
    "request_smuggling", "second_order", "websocket_security",
]

EXTRA_URLS_MAP = {
    "idor": "http://127.0.0.1:15789/user?id=1,http://127.0.0.1:15789/user?id=2",
    "cors": "http://127.0.0.1:15789/api/data",
    "hpp": "http://127.0.0.1:15789/xss?q=test",
    "cache_poisoning": "http://127.0.0.1:15789/cached",
    "sqli": "http://127.0.0.1:15789/sqli?id=1",
    "xss": "http://127.0.0.1:15789/xss?q=test",
    "ssti": "http://127.0.0.1:15789/ssti?name=test",
    "csrf": "http://127.0.0.1:15789/csrf-form",
    "ssrf": "http://127.0.0.1:15789/fetch?url=http://example.com",
    "xxe": "http://127.0.0.1:15789/xxe",
    "lfi": "http://127.0.0.1:15789/lfi?file=test",
    "cmdi": "http://127.0.0.1:15789/cmdi?cmd=test",
    "jwt": "http://127.0.0.1:15789/api/jwt-demo",
    "upload": "http://127.0.0.1:15789/upload",
    "directory": "http://127.0.0.1:15789/",
    "info": "http://127.0.0.1:15789/server-info",
    "auth": "http://127.0.0.1:15789/csrf-form",
    "misconfig": "http://127.0.0.1:15789/",
    "cors": "http://127.0.0.1:15789/api/data",
    "session_security": "http://127.0.0.1:15789/",
    "cve_check": "http://127.0.0.1:15789/",
    "zero_day": "http://127.0.0.1:15789/",
    "nosql": "http://127.0.0.1:15789/nosql?filter={}",
    "subdomain_takeover": "http://127.0.0.1:15789/",
    "graphql": "http://127.0.0.1:15789/graphql",
    "deserialization": "http://127.0.0.1:15789/deserialize",
    "business_logic": "http://127.0.0.1:15789/api/discount?pct=10",
    "dom_xss": "http://127.0.0.1:15789/xss?q=test",
    "host_header": "http://127.0.0.1:15789/host-reflect",
    "http_method": "http://127.0.0.1:15789/",
    "ldap_injection": "http://127.0.0.1:15789/ldap?username=test",
    "mass_assignment": "http://127.0.0.1:15789/api/user",
    "oauth_misconfig": "http://127.0.0.1:15789/oauth/callback?code=test",
    "open_redirect": "http://127.0.0.1:15789/redirect?url=http://example.com",
    "prototype_pollution": "http://127.0.0.1:15789/proto?__proto__[x]=y",
    "race_condition": "http://127.0.0.1:15789/race/increment",
    "request_smuggling": "http://127.0.0.1:15789/backend",
    "second_order": "http://127.0.0.1:15789/so/store",
    "websocket_security": "http://127.0.0.1:15789/ws",
    "fingerprint": "http://127.0.0.1:15789/",
    "portscan": "http://127.0.0.1:15789/",
    "subdomain": "http://127.0.0.1:15789/",
    "headers": "http://127.0.0.1:15789/",
    "ssl": "http://127.0.0.1:15789/",
}


def run_module(module, extra_urls):
    """Run a single module and return (finding_count, duration)."""
    json_file = f"/tmp/baseline_{module}.json"
    cmd = [
        "python", "reconstrike_ng.py",
        "-t", "http://127.0.0.1:15789",
        "--modules", module,
        "--quiet",
        "--json-file", json_file,
    ]
    if extra_urls:
        cmd.extend(["--extra-urls", extra_urls])

    start = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    duration = time.time() - start

    if os.path.exists(json_file):
        with open(json_file) as f:
            data = json.load(f)
        finding_count = data.get("summary", {}).get("total", 0)
    else:
        finding_count = 0

    return finding_count, round(duration, 1)


def main():
    csv_file = "docs/baseline_audit_20260926.csv"
    os.makedirs("docs", exist_ok=True)

    with open(csv_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["module", "finding_count", "duration"])

        for module in ALL_MODULES:
            extra_urls = EXTRA_URLS_MAP.get(module, "")
            print(f"Running {module}...", end=" ", flush=True)
            try:
                count, duration = run_module(module, extra_urls)
                writer.writerow([module, count, duration])
                print(f"{count} findings, {duration}s")
            except subprocess.TimeoutExpired:
                writer.writerow([module, "TIMEOUT", "120+"])
                print("TIMEOUT")
            except Exception as e:
                writer.writerow([module, "ERROR", str(e)])
                print(f"ERROR: {e}")

    print(f"\nBaseline saved to {csv_file}")


if __name__ == "__main__":
    main()