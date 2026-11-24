#!/usr/bin/env python3
"""AYNUO v4.0 command-line interface."""
from __future__ import annotations

import argparse
import sys
from getpass import getpass

from app.services.live import (
    LiveAuditError, collect_device_info, enroll_host_key, inspect_host_key,
    prepare_target, run_live_audit,
)
from aynuomodules import cve
from aynuomodules.report import error, finding, header, info

INDENT = "    "
VERSION = "4.0.0"


def banner():
    print(r"""
       _ __   ___   _ _   _  ___
      / \ \ / / \ | | | | |/ _ \
     / _ \\ V /|  \| | | | | | | |
    / ___ \| | | |\  | |_| | |_| |
   /_/   \_\_| |_| \_|\___/ \___/
""")
    print(INDENT + f"AYNUO v{VERSION}: MikroTik Security Assessment Platform")
    print(INDENT + "Secure live transport: SSH with enrolled host keys\n")


def _target(args):
    return prepare_target(args.ip, args.port)


def trust_host(args):
    try:
        target = _target(args)
        observed = inspect_host_key(target, args.timeout)
        print(f"Host: {observed['host']}:{observed['port']}")
        print(f"Key type: {observed['key_type']}")
        print(f"Fingerprint: {observed['fingerprint']}")
        if observed["trusted"]:
            info("This exact host key is already trusted.")
            return
        if not args.yes and input("Trust this exact SSH host key? Type 'yes': ").strip().lower() != "yes":
            error("Host key enrollment cancelled.")
            return
        enroll_host_key(target, observed["fingerprint"], timeout=args.timeout)
        info("SSH host key enrolled in AYNUO known_hosts.")
    except LiveAuditError as exc:
        error(exc.public_message)
        raise SystemExit(1) from exc


def run_audit(args):
    password = getpass(f"[?] SSH password for {args.username}@{args.ip}: ")
    try:
        target = _target(args)
        result = run_live_audit(
            target, args.username, password, timeout=args.timeout,
            progress=lambda stage: info(stage.replace("_", " ").capitalize()),
        )
    except LiveAuditError as exc:
        error(exc.public_message)
        raise SystemExit(1) from exc
    finally:
        password = ""
    header([
        ("Target:", f"{args.ip}:{args.port}"), ("User:", args.username),
        ("Identity:", result["device"].get("identity")),
        ("RouterOS:", result["device"].get("routeros_version")),
        ("Board:", result["device"].get("hardware_model")), ("Transport:", "SSH"),
    ])
    for item in result["findings"]:
        finding(item["id"], item["severity"], item["title"], item["evidence"], item["impact"], item["remediation"])
    info(f"Score {result['summary']['score']}/100; coverage {result['summary']['evaluated_controls']}/{result['summary']['total_controls']}")


def run_cve(args):
    if args.version:
        try:
            cve.run(args.version)
        except cve.CVEAssessmentError as exc:
            error(str(exc))
            raise SystemExit(1) from exc
        return
    if not args.ip or not args.username:
        error("Give ip and username, or --version")
        raise SystemExit(2)
    password = getpass(f"[?] SSH password for {args.username}@{args.ip}: ")
    try:
        target = _target(args)
        device = collect_device_info(target, args.username, password, timeout=args.timeout)
        version = device.get("routeros_version")
        if not version:
            raise LiveAuditError("version_unavailable", "RouterOS did not return a version over SSH.")
        header([("Target:", f"{args.ip}:{args.port}"), ("Identity:", device.get("identity")),
                ("RouterOS:", version), ("Transport:", "SSH")])
        cve.run(str(version))
    except (LiveAuditError, cve.CVEAssessmentError) as exc:
        error(exc.public_message if isinstance(exc, LiveAuditError) else str(exc))
        raise SystemExit(1) from exc
    finally:
        password = ""


def _connection_arguments(parser):
    parser.add_argument("ip", help="RouterOS IP address or hostname")
    parser.add_argument("username", help="RouterOS SSH username")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=float, default=10, help="Connection timeout in seconds")


def main():
    banner()
    parser = argparse.ArgumentParser(prog="aynuo", description="AYNUO MikroTik Security Assessment Platform CLI")
    parser.add_argument("--version", action="version", version=f"AYNUO {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    mode = sub.add_parser("trust-host", help="Inspect and explicitly enroll a RouterOS SSH host key")
    mode.add_argument("ip")
    mode.add_argument("--port", type=int, default=22)
    mode.add_argument("--timeout", type=float, default=10)
    mode.add_argument("--yes", action="store_true", help="Enroll the displayed key without interactive confirmation")
    mode.set_defaults(func=trust_host)

    mode = sub.add_parser("audit", help="Run a read-only RouterOS security audit over SSH")
    _connection_arguments(mode)
    mode.set_defaults(func=run_audit)

    mode = sub.add_parser("cve", help="Assess RouterOS CVEs using NVD data")
    mode.add_argument("ip", nargs="?", help="RouterOS IP address (not needed with --version)")
    mode.add_argument("username", nargs="?", help="RouterOS SSH username (not needed with --version)")
    mode.add_argument("--version", help="Assess this RouterOS version without connecting, e.g. 7.25.1")
    mode.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    mode.add_argument("--timeout", type=float, default=10)
    mode.set_defaults(func=run_cve)

    try:
        args = parser.parse_args()
        args.func(args)
    except KeyboardInterrupt:
        error("Interrupted by user")
        raise SystemExit(1)


if __name__ == "__main__":
    main()

