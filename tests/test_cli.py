"""Tests for the ReconStrike-ng CLI entry point."""

import subprocess
import sys

import pytest


def run_cli(*args, timeout=10):
    """Run reconstrike.py with given arguments and return the completed process."""
    return subprocess.run(
        [sys.executable, "reconstrike.py", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd="/home/we/ReconStrike-ng",
    )


class TestCLI:
    def test_version_flag(self):
        result = run_cli("--version")
        assert result.returncode == 0
        assert "ReconStrike-ng" in result.stdout or "3.0" in result.stdout

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
