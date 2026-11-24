"""Offline assessment engine for RouterOS text exports."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from app.core.config import SEVERITY_WEIGHTS
from app.services.parser import RouterExport, redact
from aynuomodules import audit


CATEGORIES = {
    "FW": "Firewall", "HW": "System Hardening", "LOG": "Monitoring and Logging",
    "MGMT": "Administrative Access", "NAT": "Firewall", "PROTO": "Network Exposure",
    "SYS": "System Hardening", "USER": "Authentication and Accounts",
    "VPN": "VPN Security", "WIFI": "Wireless Security",
}

# A control is only counted as evaluated when its evidence source exists in
# the export. Each tuple is an OR group; strings inside a tuple are ANDed.
CONTROL_REQUIREMENTS = {
    "MGMT-001": (("ip/service",),), "MGMT-002": (("ip/service",),),
    "MGMT-003": (("user",),), "MGMT-004": (("user",),),
    "PROTO-001": (("tool/mac-server/mac-winbox",),),
    "PROTO-002": (("tool/mac-server",),), "PROTO-003": (("tool/mac-server/ping",),),
    "PROTO-004": (("ip/neighbor/discovery-settings",),), "PROTO-005": (("tool/romon",),),
    "PROTO-006": (("ip/ssh",),), "PROTO-007": (("ip/smb",),),
    "PROTO-008": (("ip/upnp",),), "PROTO-009": (("tool/bandwidth-server",),),
    "PROTO-010": (("ip/cloud",),), "PROTO-011": (("snmp",),),
    "PROTO-012": (("snmp",),), "PROTO-013": (("ip/dns",),),
    "USER-002": (("user/settings",),),
    "SYS-001": (("system/routerboard/settings",), ("system/resource",)),
    "HW-001": (("interface/ethernet/poe",), ("interface/ethernet",)),
    "WIFI-001": (("interface/wifi/security",), ("interface/wifi",), ("interface/wireless/security-profiles",)),
    "WIFI-002": (("interface/wifi/security",), ("interface/wifi",), ("interface/wireless",)),
    "FW-001": (("ip/firewall/filter",),), "NAT-001": (("ip/firewall/nat",),),
    "VPN-001": (("interface/pptp-server/server", "interface/l2tp-server/server"),),
    "LOG-001": (("system/logging",),),
}


class OfflineAPI:
    def __init__(self, export: RouterExport):
        self.export = export

    def path(self, *parts):
        return self.export.get("/".join(parts))


def _available(export: RouterExport, control_id: str) -> bool:
    if control_id in {"PROTO-011", "PROTO-012"}:
        # Disabled SNMP makes community settings irrelevant. Enabled SNMP
        # needs the community menu before either community control can pass.
        if not export.has("snmp"):
            return False
        return not export.settings("snmp").get("enabled") or export.has("snmp/community")
    if control_id == "SYS-001":
        board = str(export.settings("system/resource").get("board-name", ""))
        return export.has("system/routerboard/settings") or (export.has("system/resource") and "CHR" in board)
    groups = CONTROL_REQUIREMENTS[control_id]
    return any(all(export.has(path) for path in group) for group in groups)


def _finding(fid: str, severity: str, title: str, evidence: list[str], impact: str, remediation: str) -> dict:
    return {
        "id": fid, "severity": severity, "title": title,
        "category": CATEGORIES.get(fid.split("-")[0], "Other"),
        "section": fid.split("-")[0], "description": title,
        "evidence": [redact(str(item)) for item in evidence], "impact": impact,
        "remediation": remediation, "status": "failed",
    }


def _supplementary_findings(export: RouterExport) -> list[dict]:
    findings: list[dict] = []
    if export.has("ip/firewall/filter"):
        rules = [row for row in export.get("ip/firewall/filter") if not row.get("disabled")]
        terminal = [row for row in rules if row.get("chain") == "input" and row.get("action") in {"drop", "reject"}]
        if not terminal:
            findings.append(_finding(
                "FW-001", "high", "No input-chain deny rule found",
                [f"enabled filter rules inspected: {len(rules)}", "no input action=drop/reject rule present"],
                "Traffic not explicitly accepted may reach services on the router itself.",
                "Add a final input-chain drop rule after required management and established/related accepts.",
            ))

    if export.has("ip/firewall/nat"):
        sensitive_ports = {"21", "22", "23", "80", "443", "8291", "8728", "8729"}
        exposed = []
        for rule in export.get("ip/firewall/nat"):
            ports = set(str(rule.get("dst-port", "")).split(","))
            unrestricted = not any(rule.get(key) for key in ("src-address", "src-address-list"))
            if (not rule.get("disabled") and rule.get("chain") == "dstnat"
                    and rule.get("action") in {"dst-nat", "redirect"}
                    and ports & sensitive_ports and unrestricted):
                exposed.append(",".join(sorted(ports & sensitive_ports)))
        if exposed:
            findings.append(_finding(
                "NAT-001", "high", "Sensitive management port forwarded without a source restriction",
                [f"dstnat sensitive ports: {ports}" for ports in exposed],
                "Internet clients may be able to reach administrative services through destination NAT.",
                "Remove the forwarding rule or restrict it with a trusted src-address/src-address-list and firewall policy.",
            ))

    insecure_vpn = []
    pptp = export.settings("interface/pptp-server/server")
    l2tp = export.settings("interface/l2tp-server/server")
    if pptp.get("enabled"):
        insecure_vpn.append("PPTP server enabled")
    if l2tp.get("enabled") and l2tp.get("use-ipsec") in {False, "no", "optional"}:
        insecure_vpn.append(f"L2TP use-ipsec={l2tp.get('use-ipsec')}")
    if insecure_vpn:
        findings.append(_finding(
            "VPN-001", "high", "Legacy or unprotected VPN server enabled", insecure_vpn,
            "PPTP and L2TP without required IPsec do not provide modern transport security.",
            "Disable PPTP and require IPsec for L2TP, or migrate clients to WireGuard/IPsec.",
        ))

    if export.has("system/logging"):
        rows = [row for row in export.get("system/logging") if not row.get("disabled")]
        security_topics = ("account", "critical", "error", "warning")
        if not any(any(topic in str(row.get("topics", "")) for topic in security_topics) for row in rows):
            findings.append(_finding(
                "LOG-001", "low", "No security-relevant logging rule found",
                [f"enabled logging rules inspected: {len(rows)}"],
                "Authentication and system security events may not be retained for investigation.",
                "Configure logging for account, critical, error, and warning topics to protected local or remote storage.",
            ))
    return findings


def assess(export: RouterExport) -> dict:
    findings: list[dict] = []

    def capture(fid, severity, title, evidence, impact, fix):
        findings.append(_finding(fid, severity, title, evidence, impact, fix))

    audit.run(OfflineAPI(export), reporter=capture)
    findings.extend(_supplementary_findings(export))
    findings.sort(key=lambda item: (-(SEVERITY_WEIGHTS[item["severity"]]), item["id"]))

    failed_ids = {finding["id"] for finding in findings}
    controls = []
    for control_id in CONTROL_REQUIREMENTS:
        if control_id in failed_ids:
            status, reason = "failed", None
        elif _available(export, control_id):
            status, reason = "passed", None
        else:
            status, reason = "not_evaluated", "Required configuration section is absent from the export."
        controls.append({"id": control_id, "status": status, "reason": reason})

    evaluated = sum(control["status"] != "not_evaluated" for control in controls)
    failed = len(failed_ids)
    passed = sum(control["status"] == "passed" for control in controls)
    total = len(controls)
    penalty = sum(SEVERITY_WEIGHTS[finding["severity"]] for finding in findings)
    score = max(0, 100 - penalty)
    severity = Counter(finding["severity"] for finding in findings)
    return {
        "product": "AYNUO",
        "assessment_type": "AUDIT",
        "source": "OFFLINE",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "device": {
            "identity": export.identity.get("name"),
            "routeros_version": export.metadata.get("routeros_version"),
            "hardware_model": export.metadata.get("hardware_model"),
            "management_ip": None,
        },
        "findings": findings,
        "controls": controls,
        "warnings": export.warnings,
        "summary": {
            "score": score, "coverage": round(evaluated * 100 / total),
            "total_controls": total, "evaluated_controls": evaluated,
            "not_evaluated_controls": total - evaluated,
            "passed_controls": passed, "failed_controls": failed,
            "severity": {key: severity.get(key, 0) for key in ("critical", "high", "medium", "low", "informational")},
            "scoring_method": "100 minus failed-control penalties (critical 25, high 15, medium 8, low 3), floored at 0. Missing data is not scored as a pass.",
        },
    }

