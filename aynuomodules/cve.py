"""NVD-backed RouterOS CVE assessment shared by CLI and dashboard."""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone

from app.core.config import NVD_API_KEY
from aynuomodules.report import cve_table, cve_unanalyzed

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ROUTEROS_CPE = "cpe:2.3:o:mikrotik:routeros"
STAGE_RANK = {"beta": 0, "rc": 1, "": 2}
CVSS_VERSIONS = (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0"))


class CVEAssessmentError(Exception):
    pass


def parse_version(text):
    if not text:
        return None
    text = str(text).split()[0]
    match = re.fullmatch(r"(\d+)\.(\d+)(?:\.(\d+))?(?:(beta|rc)(\d+))?", text)
    if not match:
        return None
    major, minor, patch, stage, stage_number = match.groups()
    return int(major), int(minor), int(patch or 0), STAGE_RANK[stage or ""], int(stage_number or 0)


def fetch(params):
    url = NVD_URL + "?" + urllib.parse.urlencode(params, safe=":")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.netloc != "services.nvd.nist.gov":
        raise CVEAssessmentError("Refusing to query an unexpected vulnerability data source.")
    headers = {"User-Agent": "AYNUO/3.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:  # nosec B310 - fixed HTTPS origin above
            data = json.load(response)
    except urllib.error.HTTPError as exc:
        raise CVEAssessmentError(f"NVD request failed with HTTP {exc.code}; retry later or configure NVD_API_KEY.") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise CVEAssessmentError("NVD vulnerability data is unavailable; applicability is unknown.") from exc
    return [item["cve"] for item in data.get("vulnerabilities", []) if item.get("cve")]


def cvss(record):
    metrics = record.get("metrics", {})
    for key, label in CVSS_VERSIONS:
        if not metrics.get(key):
            continue
        metric = metrics[key][0]
        data = metric.get("cvssData", {})
        severity = str(data.get("baseSeverity") or metric.get("baseSeverity") or "unknown").lower()
        if severity not in {"critical", "high", "medium", "low"}:
            severity = "unknown"
        return label, data.get("baseScore"), severity, str(data.get("vectorString") or "")
    return None, None, "unknown", ""


def routeros_ranges(record):
    matches = []
    for configuration in record.get("configurations", []):
        for node in configuration.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") and ":mikrotik:routeros:" in match.get("criteria", ""):
                    matches.append(match)
    return matches


def exact_version(match):
    parts = match.get("criteria", "").split(":")
    if len(parts) < 7 or parts[5] in {"*", "-"}:
        return None
    return parts[5] + (parts[6] if parts[6] not in {"*", "-"} else "")


def is_affected(version, match):
    exact = exact_version(match)
    if exact:
        return parse_version(exact) == version
    fields = ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")
    if not any(match.get(field) for field in fields):
        # A wildcard CPE without version bounds identifies the product, not a
        # confirmed affected release. Keep it in manual-review results.
        return False
    if any(match.get(field) and parse_version(match[field]) is None for field in fields):
        return False
    start_i = parse_version(match.get("versionStartIncluding"))
    start_e = parse_version(match.get("versionStartExcluding"))
    end_i = parse_version(match.get("versionEndIncluding"))
    end_e = parse_version(match.get("versionEndExcluding"))
    return not ((start_i and version < start_i) or (start_e and version <= start_e)
                or (end_i and version > end_i) or (end_e and version >= end_e))


def _description(record):
    descriptions = record.get("descriptions", [])
    return next((item.get("value", "") for item in descriptions if item.get("lang") == "en"), "Description unavailable.")


def _range_text(match):
    exact = exact_version(match)
    if exact:
        return exact
    parts = []
    labels = (("versionStartIncluding", ">="), ("versionStartExcluding", ">"),
              ("versionEndIncluding", "<="), ("versionEndExcluding", "<"))
    for field, operator in labels:
        if match.get(field):
            parts.append(f"{operator} {match[field]}")
    return ", ".join(parts) or "All versions listed by the RouterOS CPE match"


def _references(record):
    return [item.get("url") for item in record.get("references", []) if item.get("url")][:20]


def _exploit(record):
    for item in record.get("references", []):
        tags = {str(tag).lower() for tag in item.get("tags", [])}
        url = str(item.get("url", "")).lower()
        if "exploit" in tags or "exploit-db.com" in url:
            return {"status": "verified", "reference": item.get("url")}
    return {"status": "unknown", "reference": None}


def assess(version_text: str, *, source: str = "OFFLINE", device: dict | None = None, progress=None) -> dict:
    version = parse_version(version_text)
    if version is None:
        raise CVEAssessmentError(f"Cannot parse RouterOS version: {version_text}")
    progress = progress or (lambda stage: None)
    progress("querying_vulnerability_data")
    analyzed = fetch({"virtualMatchString": ROUTEROS_CPE, "resultsPerPage": 2000})
    findings = []
    ambiguous = []
    for record in analyzed:
        match = next((candidate for candidate in routeros_ranges(record) if is_affected(version, candidate)), None)
        if not match:
            if any(not exact_version(candidate) and not any(candidate.get(field) for field in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")) for candidate in routeros_ranges(record)):
                ambiguous.append(record)
            continue
        cvss_version, score, severity, vector = cvss(record)
        findings.append({
            "id": record.get("id"), "title": record.get("id"), "severity": severity,
            "cvss_score": score, "cvss_version": cvss_version, "cvss_vector": vector,
            "description": _description(record), "affected_range": _range_text(match),
            "fixed_version": match.get("versionEndExcluding"),
            "published": str(record.get("published", ""))[:10],
            "last_modified": str(record.get("lastModified", ""))[:10],
            "references": _references(record), "exploit": _exploit(record),
            "applicability": "confirmed", "status": "affected",
            "remediation": (f"Upgrade RouterOS to {match['versionEndExcluding']} or later and verify the MikroTik advisory."
                            if match.get("versionEndExcluding") else
                            "Review the linked vendor/NVD references and upgrade to a vendor-confirmed non-affected release."),
        })
    findings.sort(key=lambda row: (row["cvss_score"] is not None, row["cvss_score"] or 0), reverse=True)

    analyzed_ids = {record.get("id") for record in analyzed}
    potential = []
    potential_ids = set()
    progress("checking_unresolved_vulnerabilities")
    keyword_records = fetch({"keywordSearch": "routeros", "resultsPerPage": 2000})
    for record in ambiguous + keyword_records:
        if record.get("id") in potential_ids:
            continue
        if record.get("id") in analyzed_ids or record.get("vulnStatus") == "Rejected" or record.get("configurations"):
            if record not in ambiguous:
                continue
        cvss_version, score, severity, vector = cvss(record)
        potential.append({
            "id": record.get("id"), "title": record.get("id"), "severity": severity,
            "cvss_score": score, "cvss_version": cvss_version, "cvss_vector": vector,
            "description": _description(record), "affected_range": "Unknown — NVD has no RouterOS version range",
            "fixed_version": None, "published": str(record.get("published", ""))[:10],
            "last_modified": str(record.get("lastModified", ""))[:10], "references": _references(record),
            "exploit": _exploit(record), "applicability": "unknown", "status": "requires_manual_review",
            "remediation": "Review the vendor advisory and MikroTik changelog; applicability cannot be determined automatically.",
        })
        potential_ids.add(record.get("id"))
    potential.sort(key=lambda row: row["published"], reverse=True)
    counts = Counter(row["severity"] for row in findings)
    progress("generating_results")
    return {
        "product": "AYNUO", "assessment_type": "CVE", "source": source,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "device": device or {"identity": None, "routeros_version": version_text, "hardware_model": None, "management_ip": None},
        "routeros_version": version_text, "findings": findings, "potential_findings": potential,
        "summary": {
            "total_cves": len(findings), "potential_cves": len(potential),
            "severity": {key: counts.get(key, 0) for key in ("critical", "high", "medium", "low", "unknown")},
            "data_status": "available", "source": "NVD",
        },
    }


def run(version_text):
    result = assess(version_text)
    rows = [{"id": row["id"], "severity": row["severity"], "score": row["cvss_score"],
             "published": row["published"], "fixed": row["fixed_version"] or "-"} for row in result["findings"]]
    cve_table(version_text, rows)
    if result["potential_findings"]:
        cve_unanalyzed([{"id": row["id"], "status": "Unknown applicability", "published": row["published"]}
                        for row in result["potential_findings"]])
    return result

