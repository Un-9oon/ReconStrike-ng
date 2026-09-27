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
