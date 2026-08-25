"""Tests for the Adaptive Network Masking (ANM) identity rotation engine."""

import os
import platform
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock

from scanner.identity_manager import (
    IdentityManager,
    ANMConfig,
    IdentityState,
    _generate_random_mac,
    _detect_default_interface,
    _get_current_mac,
    _UA_POOL,
)


class TestANMConfig(unittest.TestCase):
    """Tests for ANMConfig dataclass defaults."""

    def test_defaults(self):
        cfg = ANMConfig()
        self.assertFalse(cfg.enabled)
        self.assertFalse(cfg.use_tor)
        self.assertFalse(cfg.rotate_mac)
        self.assertTrue(cfg.rotate_ua)
        self.assertEqual(cfg.tor_socks_port, 9050)
        self.assertEqual(cfg.tor_control_port, 9051)
        self.assertEqual(cfg.block_threshold, 3)
        self.assertEqual(cfg.fail_threshold, 5)
        self.assertEqual(cfg.max_rotations_per_scan, 50)

    def test_custom_config(self):
        cfg = ANMConfig(
            enabled=True,
            use_tor=True,
            tor_password="secret",
            rotate_mac=True,
            max_rotations_per_scan=10,
        )
        self.assertTrue(cfg.enabled)
        self.assertTrue(cfg.use_tor)
        self.assertEqual(cfg.tor_password, "secret")
        self.assertEqual(cfg.max_rotations_per_scan, 10)


class TestMACGeneration(unittest.TestCase):
    """Tests for MAC address generation."""

    def test_format(self):
        mac = _generate_random_mac()
        parts = mac.split(":")
        self.assertEqual(len(parts), 6)
        for part in parts:
            self.assertEqual(len(part), 2)
            int(part, 16)  # should not raise

    def test_locally_administered_bit(self):
        """First octet should have the locally-administered bit set (bit 1)."""
        for _ in range(100):
            mac = _generate_random_mac()
            first_octet = int(mac.split(":")[0], 16)
            self.assertTrue(first_octet & 0x02, "Locally administered bit not set")

    def test_unicast_bit(self):
        """First octet should have the multicast bit cleared (bit 0)."""
        for _ in range(100):
            mac = _generate_random_mac()
            first_octet = int(mac.split(":")[0], 16)
            self.assertFalse(first_octet & 0x01, "Multicast bit is set")

    def test_uniqueness(self):
        """Generated MACs should be unique (probabilistic)."""
        macs = {_generate_random_mac() for _ in range(50)}
        self.assertGreater(len(macs), 45)  # allow a few collisions


class TestIdentityManagerInit(unittest.TestCase):
    """Tests for IdentityManager initialisation."""

    def test_disabled_no_setup(self):
        cfg = ANMConfig(enabled=False)
        mgr = IdentityManager(cfg)
        self.assertEqual(mgr.rotation_count, 0)
        self.assertEqual(mgr.state.ip_address, "unknown")

    def test_ua_rotation_initialised(self):
        cfg = ANMConfig(enabled=True, rotate_ua=True)
        mgr = IdentityManager(cfg)
        self.assertIn(mgr.current_ua, _UA_POOL)

    def test_proxy_pool_loading(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("http://proxy1:8080\n")
            f.write("socks5://proxy2:1080\n")
            f.write("# comment line\n")
            f.write("proxy3:3128\n")
            f.name
        try:
            cfg = ANMConfig(enabled=True, proxy_pool_file=f.name)
            mgr = IdentityManager(cfg)
            self.assertEqual(len(cfg.proxy_pool), 3)
            self.assertEqual(cfg.proxy_pool[0], "http://proxy1:8080")
            self.assertEqual(cfg.proxy_pool[1], "socks5://proxy2:1080")
            self.assertEqual(cfg.proxy_pool[2], "http://proxy3:3128")
        finally:
            os.unlink(f.name)

    def test_proxy_pool_missing_file(self):
        cfg = ANMConfig(enabled=True, proxy_pool_file="/nonexistent/proxy_list.txt")
        mgr = IdentityManager(cfg)
        self.assertEqual(len(cfg.proxy_pool), 0)


class TestUARotation(unittest.TestCase):
    """Tests for User-Agent rotation."""

    def test_ua_changes(self):
        cfg = ANMConfig(enabled=True, rotate_ua=True, min_rotation_interval=0)
        mgr = IdentityManager(cfg)
        initial_ua = mgr.current_ua

        # Force rotation several times — should get different UAs
        different = False
        for _ in range(20):
            mgr._rotate_ua()
            if mgr.current_ua != initial_ua:
                different = True
                break
        self.assertTrue(different, "UA never changed after multiple rotations")

    def test_ua_always_from_pool(self):
        cfg = ANMConfig(enabled=True, rotate_ua=True, min_rotation_interval=0)
        mgr = IdentityManager(cfg)
        for _ in range(50):
            mgr._rotate_ua()
            self.assertIn(mgr._state.user_agent, _UA_POOL)


class TestProxyPoolRotation(unittest.TestCase):
    """Tests for proxy pool round-robin cycling."""

    def test_round_robin(self):
        cfg = ANMConfig(
            enabled=True,
            proxy_pool=["http://p1:8080", "http://p2:8080", "http://p3:8080"],
            min_rotation_interval=0,
        )
        mgr = IdentityManager(cfg)

        # Force rotations and check proxies cycle correctly
        proxies_seen = []
        for _ in range(6):
            mgr._rotate_ip()
            proxies_seen.append(mgr._state.proxy)

        # Should cycle through all 3 proxies twice
        self.assertEqual(proxies_seen[0], "http://p2:8080")
        self.assertEqual(proxies_seen[1], "http://p3:8080")
        self.assertEqual(proxies_seen[2], "http://p1:8080")
        self.assertEqual(proxies_seen[3], "http://p2:8080")


class TestBlockSignaling(unittest.TestCase):
    """Tests for block/fail event signaling and threshold triggering."""

    def test_block_threshold_triggers_rotation(self):
        cfg = ANMConfig(
            enabled=True,
            rotate_ua=True,
            block_threshold=3,
            min_rotation_interval=0,
            cooldown_after_block=0,
            proxy_pool=["http://p1:8080", "http://p2:8080"],
        )
        mgr = IdentityManager(cfg)

        # Signal 2 blocks — below threshold, no rotation
        self.assertFalse(mgr.signal_block(429))
        self.assertFalse(mgr.signal_block(429))
        self.assertEqual(mgr.rotation_count, 0)

        # 3rd block — should trigger rotation
        self.assertTrue(mgr.signal_block(429))
        self.assertEqual(mgr.rotation_count, 1)

    def test_fail_threshold_triggers_rotation(self):
        cfg = ANMConfig(
            enabled=True,
            rotate_ua=True,
            fail_threshold=5,
            min_rotation_interval=0,
            cooldown_after_block=0,
            proxy_pool=["http://p1:8080", "http://p2:8080"],
        )
        mgr = IdentityManager(cfg)

        for _ in range(4):
            self.assertFalse(mgr.signal_connection_fail())

        self.assertTrue(mgr.signal_connection_fail())
        self.assertEqual(mgr.rotation_count, 1)

    def test_reset_counters(self):
        cfg = ANMConfig(enabled=True, block_threshold=3)
        mgr = IdentityManager(cfg)

        mgr.signal_block(403)
        mgr.signal_block(403)
        mgr.reset_counters()

        # After reset, counter should be at 0 — 2 more signals won't trigger
        mgr.signal_block(403)
        mgr.signal_block(403)
        self.assertEqual(mgr.rotation_count, 0)

    def test_max_rotations_cap(self):
        cfg = ANMConfig(
            enabled=True,
            rotate_ua=True,
            max_rotations_per_scan=2,
            min_rotation_interval=0,
            cooldown_after_block=0,
        )
        mgr = IdentityManager(cfg)

        # Force 3 rotations — only 2 should succeed
        self.assertTrue(mgr.rotate("test1"))
        self.assertTrue(mgr.rotate("test2"))
        self.assertFalse(mgr.rotate("test3"))
        self.assertEqual(mgr.rotation_count, 2)


class TestRateLimiting(unittest.TestCase):
    """Tests for rotation rate-limiting."""

    def test_min_interval_enforced(self):
        cfg = ANMConfig(
            enabled=True,
            rotate_ua=True,
            min_rotation_interval=100,  # 100 seconds — impossibly long
            cooldown_after_block=0,
        )
        mgr = IdentityManager(cfg)

        # First rotation should succeed
        self.assertTrue(mgr.rotate("first"))

        # Immediate second rotation should be rate-limited
        self.assertFalse(mgr.rotate("too-fast"))
        self.assertEqual(mgr.rotation_count, 1)


class TestSessionIntegration(unittest.TestCase):
    """Tests for apply_to_session."""

    def test_apply_proxy_and_ua(self):
        cfg = ANMConfig(
            enabled=True,
            rotate_ua=True,
            proxy_pool=["http://p1:8080"],
        )
        mgr = IdentityManager(cfg)
        mgr._state.proxy = "socks5://test:9050"
        mgr._state.user_agent = "TestBot/1.0"

        # Use a simple namespace object with real dicts
        class FakeSession:
            proxies = {}
            headers = {}

        fake = FakeSession()
        mgr.apply_to_session(fake)

        self.assertEqual(fake.proxies["http"], "socks5://test:9050")
        self.assertEqual(fake.proxies["https"], "socks5://test:9050")
        self.assertEqual(fake.headers["User-Agent"], "TestBot/1.0")


class TestRotationHistory(unittest.TestCase):
    """Tests for rotation history tracking."""

    def test_history_recorded(self):
        cfg = ANMConfig(
            enabled=True,
            rotate_ua=True,
            min_rotation_interval=0,
            cooldown_after_block=0,
        )
        mgr = IdentityManager(cfg)

        mgr.rotate("test_trigger")
        history = mgr.rotation_history
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["trigger"], "manual")
        self.assertIn("ua_rotated", history[0]["actions"])

    def test_summary_output(self):
        cfg = ANMConfig(enabled=True, rotate_ua=True)
        mgr = IdentityManager(cfg)
        summary = mgr.get_summary()
        self.assertTrue(summary["enabled"])
        self.assertEqual(summary["total_rotations"], 0)
        self.assertTrue(summary["methods"]["ua_rotation"])


class TestShutdown(unittest.TestCase):
    """Tests for graceful shutdown and MAC restoration."""

    def test_shutdown_idempotent(self):
        cfg = ANMConfig(enabled=True)
        mgr = IdentityManager(cfg)

        # Should not raise even when called multiple times
        mgr.shutdown()
        mgr.shutdown()
        self.assertTrue(mgr._shutting_down)


class TestScanSessionANMIntegration(unittest.TestCase):
    """End-to-end integration: ScanSession + IdentityManager."""

    def test_session_creates_identity_manager_when_anm_enabled(self):
        from scanner.core import ScanConfig, ScanSession
        cfg = ScanConfig(
            target="http://example.com",
            anm_config=ANMConfig(
                enabled=True,
                rotate_ua=True,
                proxy_pool=["http://p1:8080", "http://p2:8080"],
            ),
        )
        session = ScanSession(cfg)
        self.assertIsNotNone(session.identity_manager)
        self.assertIn(session.session.headers["User-Agent"], _UA_POOL)

    def test_session_no_anm_by_default(self):
        from scanner.core import ScanConfig, ScanSession
        cfg = ScanConfig(target="http://example.com")
        session = ScanSession(cfg)
        self.assertIsNone(session.identity_manager)

    @patch("scanner.identity_manager.IdentityManager.signal_block")
    @patch("scanner.identity_manager.IdentityManager.apply_to_session")
    def test_block_detection_triggers_anm(self, mock_apply, mock_signal_block):
        from scanner.core import ScanConfig, ScanSession
        mock_signal_block.return_value = True  # pretend rotation happened

        cfg = ScanConfig(
            target="http://example.com",
            anm_config=ANMConfig(
                enabled=True,
                rotate_ua=True,
                proxy_pool=["http://p1:8080"],
            ),
        )
        session = ScanSession(cfg)

        # Simulate 429 responses
        mock_resp = MagicMock()
        mock_resp.status_code = 429

        session._track_response_status(mock_resp)
        session._track_response_status(mock_resp)
        session._track_response_status(mock_resp)

        # signal_block should have been called at least once
        self.assertTrue(mock_signal_block.called)


class TestWAFEvasionHeaders(unittest.TestCase):
    """Tests for WAF evasion header randomisation."""

    def test_waf_headers_set_on_rotation(self):
        from scanner.identity_manager import _WAF_EVASION_HEADERS_POOL
        cfg = ANMConfig(
            enabled=True, rotate_ua=True, waf_evasion=True,
            min_rotation_interval=0, cooldown_after_block=0,
        )
        mgr = IdentityManager(cfg)
        mgr._rotate_waf_headers()
        self.assertIn(mgr._waf_headers, _WAF_EVASION_HEADERS_POOL)

    def test_waf_headers_applied_to_session(self):
        cfg = ANMConfig(enabled=True, waf_evasion=True)
        mgr = IdentityManager(cfg)
        mgr._waf_headers = {"Accept-Language": "fr-FR,fr;q=0.9"}
        mgr._state.user_agent = "TestBot/1.0"

        class FakeSession:
            proxies = {}
            headers = {}

        fake = FakeSession()
        mgr.apply_to_session(fake)
        self.assertEqual(fake.headers["Accept-Language"], "fr-FR,fr;q=0.9")

    def test_waf_triggered_on_ip_block(self):
        cfg = ANMConfig(
            enabled=True, rotate_ua=True, waf_evasion=True,
            min_rotation_interval=0, cooldown_after_block=0,
            proxy_pool=["http://p1:8080", "http://p2:8080"],
            block_threshold=1,
        )
        mgr = IdentityManager(cfg)
        mgr.signal_block(403)
        history = mgr.rotation_history
        self.assertTrue(len(history) > 0)
        self.assertIn("waf_headers_randomised", history[-1]["actions"])


class TestExponentialBackoff(unittest.TestCase):
    """Tests for the exponential backoff last-resort strategy."""

    def test_backoff_when_no_ip_rotation_available(self):
        cfg = ANMConfig(
            enabled=True, rotate_ua=False, waf_evasion=False,
            auto_scrape_proxies=False, dhcp_renewal=False,
            min_rotation_interval=0, cooldown_after_block=0,
            max_rotations_per_scan=5,
        )
        mgr = IdentityManager(cfg)

        # With everything disabled except backoff, rotation should still succeed
        with patch.object(mgr, '_apply_exponential_backoff', return_value=5.0):
            result = mgr.rotate("test")
            self.assertTrue(result)
            history = mgr.rotation_history
            self.assertTrue(any("backoff" in a for a in history[-1]["actions"]))


class TestFallbackChain(unittest.TestCase):
    """Tests for the full IP rotation fallback chain."""

    def test_tor_failure_falls_through_to_proxy_pool(self):
        cfg = ANMConfig(
            enabled=True, use_tor=True, rotate_ua=True,
            proxy_pool=["http://p1:8080"],
            min_rotation_interval=0, cooldown_after_block=0,
        )
        mgr = IdentityManager(cfg)

        # Mock Tor to fail — should fall through to proxy pool
        with patch("scanner.identity_manager._send_tor_newnym", return_value=False):
            result = mgr._rotate_ip()
            self.assertTrue(result)
            self.assertEqual(mgr._state.proxy, "http://p1:8080")

    @patch("scanner.identity_manager._scrape_free_proxies")
    def test_auto_scrape_when_no_pool(self, mock_scrape):
        mock_scrape.return_value = ["http://scraped1:8080", "http://scraped2:8080"]
        cfg = ANMConfig(
            enabled=True, auto_scrape_proxies=True,
            min_rotation_interval=0, cooldown_after_block=0,
        )
        mgr = IdentityManager(cfg)
        result = mgr._rotate_ip()
        self.assertTrue(result)
        mock_scrape.assert_called_once()
        self.assertIn(mgr._state.proxy, ["http://scraped1:8080", "http://scraped2:8080"])

    @patch("scanner.identity_manager._renew_dhcp_lease")
    @patch("scanner.identity_manager._scrape_free_proxies")
    def test_dhcp_fallback_when_scrape_fails(self, mock_scrape, mock_dhcp):
        mock_scrape.return_value = []
        mock_dhcp.return_value = True
        cfg = ANMConfig(
            enabled=True, auto_scrape_proxies=True, dhcp_renewal=True,
            min_rotation_interval=0, cooldown_after_block=0,
        )
        mgr = IdentityManager(cfg)
        result = mgr._rotate_ip()
        self.assertTrue(result)
        mock_dhcp.assert_called_once()
        self.assertEqual(mgr._state.proxy, "")  # direct after DHCP

    @patch("scanner.identity_manager._renew_dhcp_lease")
    @patch("scanner.identity_manager._scrape_free_proxies")
    def test_all_strategies_exhausted(self, mock_scrape, mock_dhcp):
        mock_scrape.return_value = []
        mock_dhcp.return_value = False
        cfg = ANMConfig(
            enabled=True, auto_scrape_proxies=True, dhcp_renewal=True,
            min_rotation_interval=0, cooldown_after_block=0,
        )
        mgr = IdentityManager(cfg)
        result = mgr._rotate_ip()
        self.assertFalse(result)


class TestCombinedBanScenario(unittest.TestCase):
    """Tests for combined IP + MAC ban edge cases."""

    def test_connection_fail_rotates_both_ip_and_mac(self):
        cfg = ANMConfig(
            enabled=True, rotate_ua=True, rotate_mac=True,
            network_interface="fake0",
            proxy_pool=["http://p1:8080", "http://p2:8080"],
            fail_threshold=1, min_rotation_interval=0, cooldown_after_block=0,
        )
        mgr = IdentityManager(cfg)

        with patch("scanner.identity_manager._set_mac_address", return_value=True):
            result = mgr.signal_connection_fail()
            self.assertTrue(result)
            history = mgr.rotation_history
            actions = history[-1]["actions"]
            self.assertIn("ip_rotated", actions)
            self.assertIn("mac_rotated", actions)
            self.assertIn("ua_rotated", actions)

    def test_ip_block_does_not_rotate_mac(self):
        """HTTP 429/403 means IP-level block, not device ban — MAC stays."""
        cfg = ANMConfig(
            enabled=True, rotate_ua=True, rotate_mac=True,
            network_interface="fake0",
            proxy_pool=["http://p1:8080", "http://p2:8080"],
            block_threshold=1, min_rotation_interval=0, cooldown_after_block=0,
        )
        mgr = IdentityManager(cfg)
        mgr.signal_block(429)
        history = mgr.rotation_history
        actions = history[-1]["actions"]
        self.assertIn("ip_rotated", actions)
        self.assertNotIn("mac_rotated", actions)


class TestNewConfigDefaults(unittest.TestCase):
    """Tests for new fallback config fields."""

    def test_fallback_defaults_enabled(self):
        cfg = ANMConfig()
        self.assertTrue(cfg.auto_scrape_proxies)
        self.assertTrue(cfg.dhcp_renewal)
        self.assertTrue(cfg.waf_evasion)

    def test_summary_includes_new_methods(self):
        cfg = ANMConfig(enabled=True)
        mgr = IdentityManager(cfg)
        summary = mgr.get_summary()
        self.assertIn("auto_scrape_proxies", summary["methods"])
        self.assertIn("dhcp_renewal", summary["methods"])
        self.assertIn("waf_evasion", summary["methods"])


if __name__ == "__main__":
    unittest.main()
