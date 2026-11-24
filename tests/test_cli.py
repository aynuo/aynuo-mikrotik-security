from pathlib import Path
import subprocess
import sys

import aynuo
import aynuomodules.audit


ROOT = Path(__file__).resolve().parents[1]
LEGACY_NAME = "Sa" + "ra"


def run_cli(*arguments):
    return subprocess.run(
        [sys.executable, str(ROOT / "aynuo.py"), *arguments],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )


def test_cli_and_package_imports_resolve():
    assert callable(aynuo.main)
    assert callable(aynuomodules.audit.run)


def test_top_level_help_and_version_use_aynuo_branding():
    help_result = run_cli("--help")
    assert help_result.returncode == 0
    assert "AYNUO MikroTik Security Assessment Platform CLI" in help_result.stdout
    assert "{trust-host,audit,cve}" in help_result.stdout
    assert LEGACY_NAME not in help_result.stdout and LEGACY_NAME.upper() not in help_result.stdout

    version_result = run_cli("--version")
    assert version_result.returncode == 0
    assert "AYNUO 4.0.0" in version_result.stdout


def test_audit_help_preserves_existing_options():
    result = run_cli("audit", "--help")
    assert result.returncode == 0
    assert "ip" in result.stdout and "username" in result.stdout
    assert "--port" in result.stdout and "SSH port" in result.stdout
    assert "--plaintext" not in result.stdout and "--no-verify-tls" not in result.stdout
    assert LEGACY_NAME not in result.stdout and LEGACY_NAME.upper() not in result.stdout


def test_audit_command_parses_without_network_access(monkeypatch):
    captured = {}

    def capture(arguments):
        captured.update(vars(arguments))

    monkeypatch.setattr(aynuo, "banner", lambda: None)
    monkeypatch.setattr(aynuo, "run_audit", capture)
    monkeypatch.setattr(
        sys,
        "argv",
        ["aynuo", "audit", "192.168.88.1", "admin", "--port", "2222"],
    )
    aynuo.main()
    assert captured["command"] == "audit"
    assert captured["ip"] == "192.168.88.1"
    assert captured["username"] == "admin"
    assert captured["port"] == 2222


def test_legacy_entrypoint_and_package_are_removed():
    assert not (ROOT / f"{LEGACY_NAME.lower()}.py").exists()
    assert not (ROOT / f"{LEGACY_NAME.lower()}modules").exists()

