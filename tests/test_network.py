"""Tests for the network scanning engine (port scanner, service fingerprinter, NVD client)."""

import asyncio
import socket
import unittest
from unittest.mock import MagicMock, patch, AsyncMock

from scanner.network.port_scanner import (
    PortResult, HostResult, SPEED_PROFILES, TOP_1000_PORTS,
    SERVICE_NAMES, parse_port_range, scan_host, scan_network,
    _scan_port_async, _scan_host_async,
)
from scanner.network.service_fingerprint import (
    PROBES, fingerprint_port, fingerprint_host, _grab_banner,
)
from scanner.network.nvd_client import (
    NVDClient, build_cpe_string, SOFTWARE_CPE_MAP, CVEResult,
)


class TestPortRangeParsing(unittest.TestCase):
    """Tests for port range specification parsing."""

    def test_top_1000(self):
        ports = parse_port_range("top-1000")
        self.assertEqual(ports, TOP_1000_PORTS)

    def test_single_port(self):
        self.assertEqual(parse_port_range("80"), [80])

    def test_range(self):
        ports = parse_port_range("20-25")
        self.assertEqual(ports, [20, 21, 22, 23, 24, 25])

    def test_comma_separated(self):
        ports = parse_port_range("22,80,443")
        self.assertEqual(ports, [22, 80, 443])

    def test_mixed(self):
        ports = parse_port_range("22,80,8000-8005")
        self.assertEqual(ports, [22, 80, 8000, 8001, 8002, 8003, 8004, 8005])

    def test_full_range(self):
        ports = parse_port_range("all")
        self.assertEqual(len(ports), 65535)
        self.assertEqual(ports[0], 1)
        self.assertEqual(ports[-1], 65535)

    def test_invalid_port_ignored(self):
        ports = parse_port_range("80,abc,443")
        self.assertEqual(ports, [80, 443])

    def test_out_of_range_capped(self):
        ports = parse_port_range("0,1,65535,65536")
        self.assertEqual(ports, [1, 65535])

    def test_default_alias(self):
        self.assertEqual(parse_port_range("default"), TOP_1000_PORTS)


class TestPortResult(unittest.TestCase):
    """Tests for PortResult data structure."""

    def test_open_port(self):
        pr = PortResult(host="192.168.1.1", port=22, state="open", service="SSH")
        self.assertTrue(pr.is_open)
        self.assertEqual(pr.service, "SSH")

    def test_closed_port(self):
        pr = PortResult(host="192.168.1.1", port=23, state="closed")
        self.assertFalse(pr.is_open)

    def test_filtered_port(self):
        pr = PortResult(host="192.168.1.1", port=445, state="filtered")
        self.assertFalse(pr.is_open)


class TestHostResult(unittest.TestCase):
    """Tests for HostResult data structure."""

    def test_alive_host(self):
        hr = HostResult(
            ip="192.168.1.1",
            open_ports=[PortResult("192.168.1.1", 22, "open", "SSH")],
        )
        self.assertTrue(hr.is_alive)

    def test_dead_host(self):
        hr = HostResult(ip="192.168.1.2")
        self.assertFalse(hr.is_alive)


class TestSpeedProfiles(unittest.TestCase):
    """Tests for scan speed profiles."""

    def test_all_profiles_exist(self):
        for speed in range(1, 6):
            self.assertIn(speed, SPEED_PROFILES)

    def test_concurrency_increases_with_speed(self):
        prev = 0
        for speed in range(1, 6):
            curr = SPEED_PROFILES[speed]["concurrency"]
            self.assertGreater(curr, prev)
            prev = curr

    def test_timeout_decreases_with_speed(self):
        prev = 999
        for speed in range(1, 6):
            curr = SPEED_PROFILES[speed]["timeout"]
            self.assertLess(curr, prev)
            prev = curr


class TestServiceNames(unittest.TestCase):
    """Tests for the service name database."""

    def test_common_ports_have_names(self):
        self.assertEqual(SERVICE_NAMES[22], "SSH")
        self.assertEqual(SERVICE_NAMES[80], "HTTP")
        self.assertEqual(SERVICE_NAMES[443], "HTTPS")
        self.assertEqual(SERVICE_NAMES[3306], "MySQL")
        self.assertEqual(SERVICE_NAMES[6379], "Redis")

    def test_dangerous_ports_listed(self):
        self.assertIn(445, SERVICE_NAMES)   # SMB
        self.assertIn(3389, SERVICE_NAMES)  # RDP
        self.assertIn(2375, SERVICE_NAMES)  # Docker API


class TestAsyncPortScanner(unittest.TestCase):
    """Tests for the async port scanner."""

    def test_scan_closed_port(self):
        """Scanning a port with no listener should return closed or filtered."""
        result = asyncio.run(
            _scan_port_async("127.0.0.1", 1, 0.5, asyncio.Semaphore(10))
        )
        self.assertIn(result.state, ("closed", "filtered"))

    def test_scan_host_returns_host_result(self):
        """scan_host should return a HostResult even with no open ports."""
        with patch("scanner.network.port_scanner._scan_port_async") as mock:
            mock.return_value = PortResult("127.0.0.1", 1, "closed")
            result = scan_host("127.0.0.1", ports=[1])
            self.assertIsInstance(result, HostResult)


class TestServiceProbes(unittest.TestCase):
    """Tests for protocol probe definitions."""

    def test_probes_not_empty(self):
        self.assertGreater(len(PROBES), 10, "Should have 10+ protocol probes")

    def test_all_probes_have_required_fields(self):
        for probe in PROBES:
            self.assertTrue(probe.name, f"Probe missing name")
            self.assertIsInstance(probe.ports, list)
            self.assertIsInstance(probe.send, bytes)
            self.assertIsInstance(probe.match, list)

    def test_match_patterns_are_valid_regex(self):
        for probe in PROBES:
            for pattern, _ in probe.match:
                try:
                    re.compile(pattern, re.DOTALL | re.IGNORECASE)
                except re.error as e:
                    self.fail(f"Invalid regex in probe {probe.name}: {e}")

    def test_common_services_covered(self):
        probe_names = {p.name for p in PROBES}
        for svc in ["HTTP", "HTTPS", "SSH", "FTP", "SMTP", "MySQL", "Redis",
                     "MongoDB", "SMB", "RDP", "VNC", "DNS"]:
            self.assertIn(svc, probe_names, f"Missing probe for {svc}")


class TestFingerprinting(unittest.TestCase):
    """Tests for service fingerprinting."""

    def test_fingerprint_updates_port_result(self):
        pr = PortResult(host="127.0.0.1", port=22, state="open")

        with patch("scanner.network.service_fingerprint._grab_banner") as mock:
            mock.return_value = ("SSH", "OpenSSH_8.9", "SSH-2.0-OpenSSH_8.9")
            result = fingerprint_port("127.0.0.1", pr)
            self.assertEqual(result.service, "SSH")
            self.assertEqual(result.version, "OpenSSH_8.9")
            self.assertIn("SSH-2.0", result.banner)

    def test_fallback_to_service_names(self):
        pr = PortResult(host="127.0.0.1", port=22, state="open")

        with patch("scanner.network.service_fingerprint._grab_banner") as mock:
            mock.return_value = ("", "", "")
            result = fingerprint_port("127.0.0.1", pr)
            self.assertEqual(result.service, "SSH")  # Falls back to SERVICE_NAMES


class TestCPEBuilder(unittest.TestCase):
    """Tests for CPE string building."""

    def test_basic_cpe(self):
        cpe = build_cpe_string("apache", "http_server", "2.4.49")
        self.assertEqual(cpe, "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")

    def test_wildcard_version(self):
        cpe = build_cpe_string("nginx", "nginx")
        self.assertIn(":*:", cpe)

    def test_normalization(self):
        cpe = build_cpe_string("Apache", "HTTP Server", "2.4")
        self.assertIn("apache", cpe)
        self.assertIn("http_server", cpe)

    def test_software_cpe_map(self):
        for sw, (vendor, product) in SOFTWARE_CPE_MAP.items():
            self.assertTrue(vendor, f"Empty vendor for {sw}")
            self.assertTrue(product, f"Empty product for {sw}")


class TestNVDClient(unittest.TestCase):
    """Tests for the NVD API client."""

    def test_cache_roundtrip(self):
        import tempfile, os
        db_path = os.path.join(tempfile.mkdtemp(), "test_nvd.db")
        client = NVDClient(cache_path=db_path)

        # Store and retrieve
        client._store_cache("test_key", [{"cve_id": "CVE-2021-44228"}])
        cached = client._check_cache("test_key")
        self.assertIsNotNone(cached)
        self.assertEqual(cached[0]["cve_id"], "CVE-2021-44228")

    def test_cache_miss(self):
        import tempfile, os
        db_path = os.path.join(tempfile.mkdtemp(), "test_nvd2.db")
        client = NVDClient(cache_path=db_path)

        cached = client._check_cache("nonexistent")
        self.assertIsNone(cached)

    def test_parse_response(self):
        client = NVDClient()
        data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-44228",
                        "descriptions": [
                            {"lang": "en", "value": "Log4Shell RCE vulnerability"}
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 10.0,
                                        "baseSeverity": "CRITICAL",
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                    }
                                }
                            ]
                        },
                        "references": [
                            {"url": "https://example.com", "tags": ["Exploit"]}
                        ],
                        "weaknesses": [
                            {
                                "description": [
                                    {"lang": "en", "value": "CWE-917"}
                                ]
                            }
                        ],
                        "published": "2021-12-10T10:00:00.000",
                        "lastModified": "2023-01-01T00:00:00.000",
                    }
                }
            ]
        }
        results = client._parse_response(data)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].cve_id, "CVE-2021-44228")
        self.assertEqual(results[0].cvss_score, 10.0)
        self.assertEqual(results[0].cvss_severity, "CRITICAL")
        self.assertTrue(results[0].exploit_available)
        self.assertIn("CWE-917", results[0].weaknesses)


import re


if __name__ == "__main__":
    unittest.main()
