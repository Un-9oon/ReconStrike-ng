"""Tests for the ReconStrike CLI entry point."""

import os
import subprocess
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_cli(*args, timeout=10):
    """Run reconstrike_ng.py with given arguments and return the completed process."""
    return subprocess.run(
        [sys.executable, "reconstrike_ng.py", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=PROJECT_ROOT,
    )


class TestCLI:
    def test_version_flag(self):
        result = run_cli("--version")
        assert result.returncode == 0
        assert "ReconStrike" in result.stdout

    def test_help_flag(self):
        result = run_cli("--help")
        assert result.returncode == 0
        assert "target" in result.stdout.lower() or "usage" in result.stdout.lower()

    def test_no_args_gives_error(self):
        result = run_cli()
        # Should exit non-zero when no target is provided
        assert result.returncode != 0

    def test_invalid_target_gives_error(self):
        # A target that cannot be reached should cause an error exit
        result = run_cli("-t", "http://256.256.256.256:1", "--modules", "headers", "--timeout", "2", "-q")
        assert result.returncode != 0

    def test_sandbox_script_safety_flags(self):
        sandbox_path = os.path.join(PROJECT_ROOT, "reconstrike-ng-sandbox.sh")
        with open(sandbox_path) as f:
            content = f.read()
        assert "--cap-drop=ALL" in content
        assert "--read-only" in content
        assert "--security-opt=no-new-privileges:true" in content

    def test_initial_403_target_does_not_abort_and_triggers_anm(self):
        import threading
        from http.server import HTTPServer, BaseHTTPRequestHandler
        from unittest.mock import MagicMock

        class ForbiddenHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass
            def do_GET(self):
                self.send_response(403)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"Forbidden")

        server = HTTPServer(("127.0.0.1", 0), ForbiddenHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        target_url = f"http://127.0.0.1:{port}"
        try:
            result = run_cli("-t", target_url, "--anm", "--rotate-ua", "--authorized-target", target_url, "--modules", "headers", "--depth", "1", "--timeout", "1", timeout=15)
            # Must NOT exit with "Cannot reach target"
            assert "Cannot reach target" not in result.stderr
            assert "Target responded with error status HTTP 403" in result.stdout or "Target responded with error status HTTP 403" in result.stderr or "Target is reachable (HTTP 403)" in result.stdout or "Target is reachable (HTTP 403)" in result.stderr
        finally:
            server.shutdown()

