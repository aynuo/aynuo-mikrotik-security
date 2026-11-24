"""Verified, read-only RouterOS SSH collection shared by web and CLI."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
import shlex
import socket
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import paramiko

from app.core.config import SSH_ALLOWED_NETWORKS, SSH_KNOWN_HOSTS
from app.services.engine import CONTROL_REQUIREMENTS, assess
from app.services.parser import COLLECTION_SECTIONS, RouterExport, redact, scalar
from aynuomodules.cve import CVEAssessmentError, assess as assess_cves


HOSTNAME = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
ERROR_TEXT = re.compile(r"(?im)^\s*(?:failure:|syntax error|bad command name|expected end of command)")
Progress = Callable[[str], None]
_known_hosts_lock = threading.Lock()


class LiveAuditError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.public_message = message


@dataclass(frozen=True)
class PreparedTarget:
    hostname: str
    resolved_ip: str
    port: int

    @property
    def hostkey_name(self) -> str:
        return self.hostname if self.port == 22 else f"[{self.hostname}]:{self.port}"


def prepare_target(host: str, port: int) -> PreparedTarget:
    host = host.strip().rstrip(".")
    if not host or "://" in host or any(char.isspace() for char in host):
        raise LiveAuditError("invalid_target", "Enter an IP address or hostname without a URL scheme.")
    if not 1 <= port <= 65535:
        raise LiveAuditError("invalid_port", "The SSH port must be between 1 and 65535.")
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
        host = str(literal)
        addresses = {literal}
    except ValueError:
        if not HOSTNAME.fullmatch(host):
            raise LiveAuditError("invalid_target", "The router hostname is not valid.")
        try:
            answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise LiveAuditError("dns_failure", "The router hostname could not be resolved.") from exc
        addresses = {ipaddress.ip_address(answer[4][0]) for answer in answers}
    if not addresses:
        raise LiveAuditError("dns_failure", "The router hostname did not resolve to an address.")
    if any(not any(address in network for network in SSH_ALLOWED_NETWORKS) for address in addresses):
        raise LiveAuditError("target_not_allowed", "The router is outside AYNUO's approved management networks.")
    selected = sorted(addresses, key=lambda address: (address.version, int(address)))[0]
    return PreparedTarget(host, str(selected), port)


def _fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def inspect_host_key(target: PreparedTarget, timeout: float = 10) -> dict:
    sock = None
    transport = None
    try:
        sock = socket.create_connection((target.resolved_ip, target.port), timeout)
        transport = paramiko.Transport(sock)
        transport.banner_timeout = timeout
        transport.start_client(timeout=timeout)
        key = transport.get_remote_server_key()
        return {
            "host": target.hostname, "port": target.port, "key_type": key.get_name(),
            "fingerprint": _fingerprint(key), "key_base64": key.get_base64(),
            "trusted": _trusted_key(target, key),
        }
    except (socket.timeout, TimeoutError) as exc:
        raise LiveAuditError("connection_timeout", "The SSH server did not respond before the timeout.") from exc
    except (OSError, paramiko.SSHException) as exc:
        raise LiveAuditError("ssh_unreachable", "The SSH service could not be reached or did not complete its handshake.") from exc
    finally:
        if transport:
            transport.close()
        elif sock:
            sock.close()


def _load_host_keys(path: Path = SSH_KNOWN_HOSTS) -> paramiko.HostKeys:
    keys = paramiko.HostKeys()
    if path.exists():
        try:
            keys.load(str(path))
        except (OSError, paramiko.SSHException) as exc:
            raise LiveAuditError("known_hosts_invalid", "AYNUO's known_hosts file could not be read safely.") from exc
    return keys


def _trusted_key(target: PreparedTarget, key: paramiko.PKey, path: Path = SSH_KNOWN_HOSTS) -> bool:
    expected = _load_host_keys(path).lookup(target.hostkey_name)
    return bool(expected and key.get_name() in expected and expected[key.get_name()] == key)


def enroll_host_key(
    target: PreparedTarget,
    expected_fingerprint: str,
    *,
    timeout: float = 10,
    path: Path = SSH_KNOWN_HOSTS,
) -> dict:
    observed = inspect_host_key(target, timeout)
    if observed["fingerprint"] != expected_fingerprint:
        raise LiveAuditError("host_key_changed", "The SSH host key changed before enrollment; verify the router directly.")
    key_class = paramiko.PKey.from_type_string(observed["key_type"], base64.b64decode(observed["key_base64"]))
    with _known_hosts_lock:
        keys = _load_host_keys(path)
        existing = keys.lookup(target.hostkey_name)
        if existing and any(saved != key_class for saved in existing.values()):
            raise LiveAuditError("host_key_changed", "A different SSH host key is already trusted for this router.")
        path.parent.mkdir(parents=True, exist_ok=True)
        keys.add(target.hostkey_name, key_class.get_name(), key_class)
        keys.save(str(path))
    observed["trusted"] = True
    return observed


class _PinnedKeyPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, expected: list[paramiko.PKey]):
        self.expected = expected

    def missing_host_key(self, client, hostname, key):
        if key not in self.expected:
            raise paramiko.BadHostKeyException(hostname, key, self.expected[0])


class SSHSession:
    def __init__(self, client: paramiko.SSHClient, timeout: float):
        self.client = client
        self.timeout = timeout

    def run(self, command: str) -> str:
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=self.timeout)
            stdin.close()
            output = stdout.read(5 * 1024 * 1024 + 1).decode("utf-8", "replace")
            error_output = stderr.read(64 * 1024 + 1).decode("utf-8", "replace")
            status = stdout.channel.recv_exit_status()
        except (socket.timeout, TimeoutError) as exc:
            raise LiveAuditError("command_timeout", "A read-only RouterOS command timed out.") from exc
        except (OSError, paramiko.SSHException) as exc:
            raise LiveAuditError("connection_lost", "The SSH connection was lost during collection.") from exc
        if len(output.encode("utf-8")) > 5 * 1024 * 1024:
            raise LiveAuditError("output_too_large", "RouterOS returned more data than AYNUO can safely process.")
        combined = (output + "\n" + error_output).strip()
        if status != 0 or ERROR_TEXT.search(combined):
            raise KeyError(redact(combined[:500]) or "Unsupported RouterOS command")
        return output

    def close(self):
        self.client.close()


def connect_ssh(
    target: PreparedTarget,
    username: str,
    password: str,
    *,
    timeout: float = 10,
    known_hosts: Path = SSH_KNOWN_HOSTS,
) -> SSHSession:
    keys = _load_host_keys(known_hosts).lookup(target.hostkey_name)
    if not keys:
        raise LiveAuditError("host_key_unknown", "The router SSH host key is not trusted. Inspect and enroll it first.")
    client = paramiko.SSHClient()
    expected_keys = list(keys.values())
    client.set_missing_host_key_policy(_PinnedKeyPolicy(expected_keys))
    try:
        client.connect(
            hostname=target.resolved_ip, port=target.port, username=username, password=password,
            timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
            allow_agent=False, look_for_keys=False,
        )
        transport = client.get_transport()
        observed = transport.get_remote_server_key() if transport else None
        if observed not in expected_keys:
            raise paramiko.BadHostKeyException(target.hostname, observed, expected_keys[0])
        return SSHSession(client, timeout)
    except paramiko.AuthenticationException as exc:
        client.close()
        raise LiveAuditError("authentication_failed", "SSH authentication failed. Check the username and password.") from exc
    except paramiko.BadHostKeyException as exc:
        client.close()
        raise LiveAuditError("host_key_changed", "The router SSH host key does not match the enrolled key.") from exc
    except (socket.timeout, TimeoutError) as exc:
        client.close()
        raise LiveAuditError("connection_timeout", "The router did not respond before the SSH timeout.") from exc
    except (OSError, paramiko.SSHException) as exc:
        client.close()
        raise LiveAuditError("ssh_unreachable", "The router could not be reached through SSH.") from exc


def _tokens(text: str) -> list[str]:
    lexer = shlex.shlex(text, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def parse_detail(text: str) -> list[dict]:
    """Parse RouterOS ``print detail`` or settings output into dictionaries."""
    clean = ANSI.sub("", text).replace("\r", "")
    lines = [line.rstrip() for line in clean.splitlines() if line.strip()]
    lines = [line for line in lines if not line.lstrip().startswith(("Flags:", "Columns:"))]
    if not lines:
        return []
    colon_pairs = []
    for line in lines:
        match = re.match(r"^\s*([A-Za-z0-9_-]+):\s*(.*)$", line)
        if match:
            colon_pairs.append((match.group(1), match.group(2)))
    if colon_pairs and len(colon_pairs) == len(lines):
        return [{key: scalar(value) for key, value in colon_pairs}]

    blocks: list[str] = []
    current = ""
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(";;;"):
            continue
        new_record = bool(re.match(r"^(?:\d+\s+|[A-Z*!-]+\s+\d+\s+|\d+\s+[A-Z*!-]+\s+)", stripped))
        if new_record and current:
            blocks.append(current)
            current = stripped
        else:
            current = f"{current} {stripped}".strip()
    if current:
        blocks.append(current)

    rows = []
    for block in blocks:
        prefix = re.match(r"^(?:(?P<before>[A-Z*!-]+)\s+)?\d+\s+(?:(?P<after>[A-Z*!-]+)\s+)?", block)
        flags = ((prefix.group("before") or "") + (prefix.group("after") or "")) if prefix else ""
        if prefix:
            block = block[prefix.end():]
        row = {}
        try:
            parts = _tokens(block)
        except ValueError:
            parts = block.split()
        for token in parts:
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            if key and re.fullmatch(r"[A-Za-z0-9_-]+", key):
                row[key] = scalar(value)
        if "D" in flags:
            row["dynamic"] = True
        if "X" in flags:
            row["disabled"] = True
        if "I" in flags:
            row["invalid"] = True
        if row:
            rows.append(row)
    return rows


EXTRA_PATHS = {
    "interface", "ip/address", "ip/route", "ipv6/address", "ipv6/route",
    "ip/firewall/raw", "ip/firewall/mangle", "interface/wireguard",
    "ip/ipsec/peer", "ip/ipsec/profile", "system/ntp/client", "system/clock",
}
COLLECTION_PATHS = COLLECTION_SECTIONS | {
    "interface", "ip/address", "ip/route", "ipv6/address", "ipv6/route",
    "ip/firewall/raw", "ip/firewall/mangle", "interface/wireguard",
    "ip/ipsec/peer", "ip/ipsec/profile",
}


def _command(path: str) -> str:
    suffix = "print detail without-paging" if path in COLLECTION_PATHS else "print"
    return f"/{path.replace('/', ' ')} {suffix}"


def collect_snapshot(session: SSHSession, target: PreparedTarget, progress: Progress) -> RouterExport:
    progress("retrieving_router_information")
    snapshot = RouterExport()
    for path in ("system/identity", "system/resource"):
        try:
            rows = parse_detail(session.run(_command(path)))
        except KeyError as exc:
            raise LiveAuditError("insufficient_permissions", "The SSH account cannot read required system information.") from exc
        if not rows:
            raise LiveAuditError("insufficient_permissions", "RouterOS returned no required system information over SSH.")
        snapshot.present_sections.add(path)
        snapshot.sections[path] = rows
    identity = snapshot.settings("system/identity")
    resource = snapshot.settings("system/resource")
    snapshot.identity["name"] = str(identity.get("name") or "")
    snapshot.metadata["routeros_version"] = str(resource.get("version") or "")
    snapshot.metadata["hardware_model"] = str(resource.get("board-name") or "")

    paths = {
        path for groups in CONTROL_REQUIREMENTS.values() for group in groups for path in group
    } | EXTRA_PATHS
    paths -= {"system/identity", "system/resource"}
    progress("collecting_configuration")
    for path in sorted(paths):
        try:
            rows = parse_detail(session.run(_command(path)))
        except KeyError:
            snapshot.warnings.append(f"RouterOS menu unsupported or not permitted: /{path.replace('/', ' ')}")
            continue
        snapshot.present_sections.add(path)
        snapshot.sections[path] = rows
    return snapshot


def collect_device_info(
    target: PreparedTarget,
    username: str,
    password: str,
    *,
    timeout: float = 10,
    known_hosts: Path = SSH_KNOWN_HOSTS,
) -> dict:
    session = connect_ssh(target, username, password, timeout=timeout, known_hosts=known_hosts)
    try:
        identity = parse_detail(session.run(_command("system/identity")))
        resource = parse_detail(session.run(_command("system/resource")))
        if not identity or not resource:
            raise LiveAuditError("insufficient_permissions", "The SSH account cannot read RouterOS device information.")
        return {
            "identity": identity[0].get("name"), "routeros_version": resource[0].get("version"),
            "hardware_model": resource[0].get("board-name"), "management_ip": target.resolved_ip,
            "target": target.hostname,
        }
    finally:
        session.close()


def run_live_audit(
    target: PreparedTarget,
    username: str,
    password: str,
    *,
    timeout: float = 10,
    known_hosts: Path = SSH_KNOWN_HOSTS,
    progress: Progress | None = None,
) -> dict:
    progress = progress or (lambda stage: None)
    progress("connecting_and_authenticating")
    session = connect_ssh(target, username, password, timeout=timeout, known_hosts=known_hosts)
    try:
        snapshot = collect_snapshot(session, target, progress)
        progress("running_security_checks")
        result = assess(snapshot)
        progress("generating_results")
        result["source"] = "SSH"
        result["device"]["management_ip"] = target.resolved_ip
        result["device"]["target"] = target.hostname
        return result
    finally:
        session.close()


def run_unified_scan(
    target: PreparedTarget,
    username: str,
    password: str,
    *,
    timeout: float = 10,
    known_hosts: Path = SSH_KNOWN_HOSTS,
    progress: Progress | None = None,
    component_progress: Callable[[str, str], None] | None = None,
) -> dict:
    """Collect once over SSH, then run audit and CVE engines independently."""
    progress = progress or (lambda stage: None)
    component_progress = component_progress or (lambda component, status: None)
    progress("connecting_and_authenticating")
    session = connect_ssh(target, username, password, timeout=timeout, known_hosts=known_hosts)
    try:
        snapshot = collect_snapshot(session, target, progress)
    finally:
        session.close()

    device = {
        "identity": snapshot.identity.get("name"),
        "routeros_version": snapshot.metadata.get("routeros_version"),
        "hardware_model": snapshot.metadata.get("hardware_model"),
        "management_ip": target.resolved_ip,
        "target": target.hostname,
    }
    progress("running_assessments")

    def audit_task():
        component_progress("audit", "running")
        result = assess(snapshot)
        result["source"] = "SSH"
        result["device"].update(device)
        component_progress("audit", "completed")
        return result

    def cve_task():
        component_progress("cve", "running")
        version = device.get("routeros_version")
        if not version:
            raise CVEAssessmentError("RouterOS did not return a version; CVE applicability is unknown.")
        result = assess_cves(str(version), source="SSH", device=device)
        component_progress("cve", "completed")
        return result

    results = {"audit": None, "cve": None}
    states = {"audit": {"status": "failed", "error": None}, "cve": {"status": "failed", "error": None}}
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="aynuo-scan") as pool:
        futures = {name: pool.submit(task) for name, task in (("audit", audit_task), ("cve", cve_task))}
        for name, future in futures.items():
            try:
                results[name] = future.result()
                states[name] = {"status": "completed", "error": None}
            except (CVEAssessmentError, LiveAuditError) as exc:
                message = exc.public_message if isinstance(exc, LiveAuditError) else str(exc)
                states[name] = {"status": "failed", "error": message}
                component_progress(name, "failed")
            except Exception as exc:
                states[name] = {"status": "failed", "error": f"{name.title()} assessment failed safely ({type(exc).__name__})."}
                component_progress(name, "failed")

    progress("generating_results")
    audit_summary = (results["audit"] or {}).get("summary", {})
    cve_summary = (results["cve"] or {}).get("summary", {})
    return {
        "product": "AYNUO", "assessment_type": "SCAN", "source": "SSH",
        "created_at": datetime.now(timezone.utc).isoformat(), "device": device,
        "routeros_version": device.get("routeros_version"),
        "component_status": states, "audit": results["audit"], "cve": results["cve"],
        "summary": {
            "score": audit_summary.get("score"),
            "audit_findings": len((results["audit"] or {}).get("findings", [])),
            "total_cves": cve_summary.get("total_cves"),
            "potential_cves": cve_summary.get("potential_cves"),
            "scan_status": "completed" if all(state["status"] == "completed" for state in states.values()) else "partial",
        },
    }

