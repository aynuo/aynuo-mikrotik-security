import json
import socket

import paramiko
import pytest

from app.services import live
from app.services.live import LiveAuditError, PreparedTarget


class FakeSession:
    def __init__(self):
        self.closed = False
        self.commands = []

    def run(self, command):
        self.commands.append(command)
        if command.startswith("/system identity"):
            return "name: branch-router\n"
        if command.startswith("/system resource"):
            return "version: 7.25.1\nboard-name: CHR\n"
        if command.startswith("/ip ssh"):
            return "strong-crypto: no\n"
        if command.startswith("/ip service"):
            return '0 name="telnet" port=23 disabled=no available-from=""\n'
        return ""

    def close(self):
        self.closed = True


def test_prepare_target_restricts_ssrf_and_supports_custom_port(monkeypatch):
    assert live.prepare_target("192.168.88.1", 2222).port == 2222
    with pytest.raises(LiveAuditError, match="approved management networks"):
        live.prepare_target("8.8.8.8", 22)
    with pytest.raises(LiveAuditError, match="between 1 and 65535"):
        live.prepare_target("192.168.88.1", 0)
    with pytest.raises(LiveAuditError, match="without a URL scheme"):
        live.prepare_target("ssh://192.168.88.1", 22)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.88.1", 22)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 22)),
    ])
    with pytest.raises(LiveAuditError, match="approved management networks"):
        live.prepare_target("router.example", 22)


def test_routeros_detail_parser_handles_settings_records_and_wrapping():
    assert live.parse_detail("  version: 7.25.1\n board-name: x86 VMware\n") == [
        {"version": "7.25.1", "board-name": "x86 VMware"}
    ]
    rows = live.parse_detail('Flags: X - disabled\n0 name="ssh" port=22 disabled=no\n  available-from=192.168.1.0/24\n1 X name="telnet" port=23 disabled=yes\n')
    assert rows[0]["name"] == "ssh" and rows[0]["port"] == 22
    assert rows[0]["available-from"] == "192.168.1.0/24"
    assert rows[1]["disabled"] is True
    dynamic = live.parse_detail('2 D name="ssh" port=22 address=""\n')
    assert dynamic[0]["dynamic"] is True


def test_host_key_enrollment_requires_exact_fingerprint(tmp_path, monkeypatch):
    key = paramiko.RSAKey.generate(1024)
    observed = {"host": "192.168.88.1", "port": 22, "key_type": key.get_name(),
                "fingerprint": live._fingerprint(key), "key_base64": key.get_base64(), "trusted": False}
    monkeypatch.setattr(live, "inspect_host_key", lambda *args, **kwargs: dict(observed))
    target = PreparedTarget("192.168.88.1", "192.168.88.1", 22)
    with pytest.raises(LiveAuditError, match="changed before enrollment"):
        live.enroll_host_key(target, "SHA256:wrongfingerprint000000", path=tmp_path / "known_hosts")
    result = live.enroll_host_key(target, observed["fingerprint"], path=tmp_path / "known_hosts")
    assert result["trusted"] is True
    assert live._load_host_keys(tmp_path / "known_hosts").lookup("192.168.88.1")[key.get_name()] == key


def test_unknown_host_key_fails_before_authentication(tmp_path):
    with pytest.raises(LiveAuditError) as exc:
        live.connect_ssh(PreparedTarget("192.168.88.1", "192.168.88.1", 22), "user", "secret", known_hosts=tmp_path / "missing")
    assert exc.value.code == "host_key_unknown" and "secret" not in exc.value.public_message


def test_shared_ssh_engine_is_read_only_and_normalized(monkeypatch):
    session = FakeSession(); stages = []
    monkeypatch.setattr(live, "connect_ssh", lambda *args, **kwargs: session)
    result = live.run_live_audit(PreparedTarget("192.168.88.1", "192.168.88.1", 22), "auditor", "unique-secret", progress=stages.append)
    assert result["source"] == "SSH" and result["assessment_type"] == "AUDIT"
    assert result["device"]["identity"] == "branch-router" and result["device"]["routeros_version"] == "7.25.1"
    assert {"MGMT-001", "MGMT-002", "PROTO-006"} <= {row["id"] for row in result["findings"]}
    assert "unique-secret" not in json.dumps(result)
    assert session.closed and all(" set " not in command and " add " not in command and " remove " not in command for command in session.commands)
    assert stages == ["connecting_and_authenticating", "retrieving_router_information", "collecting_configuration", "running_security_checks", "generating_results"]


def test_unified_scan_connects_once_and_isolates_component_failure(monkeypatch):
    session = FakeSession(); connections = []; components = []
    monkeypatch.setattr(live, "connect_ssh", lambda *args, **kwargs: connections.append(1) or session)
    monkeypatch.setattr(live, "assess_cves", lambda *args, **kwargs: (_ for _ in ()).throw(live.CVEAssessmentError("CVE data unavailable")))
    result = live.run_unified_scan(
        PreparedTarget("192.168.88.1", "192.168.88.1", 22), "auditor", "secret",
        component_progress=lambda name, state: components.append((name, state)),
    )
    assert len(connections) == 1 and session.closed
    assert result["audit"] and result["component_status"]["audit"]["status"] == "completed"
    assert result["cve"] is None and result["component_status"]["cve"]["status"] == "failed"
    assert result["summary"]["scan_status"] == "partial"
    assert ("audit", "completed") in components and ("cve", "failed") in components


def test_authentication_failure_is_redacted(tmp_path, monkeypatch):
    key = paramiko.RSAKey.generate(1024)
    hosts = paramiko.HostKeys(); hosts.add("192.168.88.1", key.get_name(), key); hosts.save(str(tmp_path / "known_hosts"))
    class Client:
        def set_missing_host_key_policy(self, policy): pass
        def connect(self, **kwargs): raise paramiko.AuthenticationException()
        def close(self): pass
    monkeypatch.setattr(live.paramiko, "SSHClient", Client)
    with pytest.raises(LiveAuditError) as exc:
        live.connect_ssh(PreparedTarget("192.168.88.1", "192.168.88.1", 22), "user", "secret", known_hosts=tmp_path / "known_hosts")
    assert exc.value.code == "authentication_failed" and "secret" not in exc.value.public_message


def test_connection_failure_is_public_and_safe(tmp_path, monkeypatch):
    key = paramiko.RSAKey.generate(1024)
    hosts = paramiko.HostKeys(); hosts.add("192.168.88.1", key.get_name(), key); hosts.save(str(tmp_path / "known_hosts"))
    class Client:
        def set_missing_host_key_policy(self, policy): pass
        def connect(self, **kwargs): raise OSError("private network diagnostic")
        def close(self): pass
    monkeypatch.setattr(live.paramiko, "SSHClient", Client)
    with pytest.raises(LiveAuditError) as exc:
        live.connect_ssh(PreparedTarget("192.168.88.1", "192.168.88.1", 22), "user", "secret", known_hosts=tmp_path / "known_hosts")
    assert exc.value.code == "ssh_unreachable"
    assert "diagnostic" not in exc.value.public_message and "secret" not in exc.value.public_message

