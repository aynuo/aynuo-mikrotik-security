import pytest

from aynuomodules import cve


RECORD = {
    "id": "CVE-2026-1234", "published": "2026-01-02T00:00:00", "lastModified": "2026-02-01T00:00:00",
    "descriptions": [{"lang": "en", "value": "RouterOS vulnerability description."}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.8, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N"}}]},
    "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*", "versionStartIncluding": "7.20", "versionEndExcluding": "7.26"}]}]}],
    "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1234"}],
}
UNKNOWN = {"id": "CVE-2026-9999", "published": "2026-03-01T00:00:00", "vulnStatus": "Awaiting Analysis", "descriptions": [{"lang": "en", "value": "Mentions RouterOS."}], "configurations": [], "references": []}


def test_cve_assessment_matches_ranges_and_marks_unknown(monkeypatch):
    monkeypatch.setattr(cve, "fetch", lambda params: [RECORD] if "virtualMatchString" in params else [RECORD, UNKNOWN])
    result = cve.assess("7.25.1")
    assert result["assessment_type"] == "CVE"
    assert result["findings"][0]["id"] == "CVE-2026-1234"
    assert result["findings"][0]["fixed_version"] == "7.26"
    assert result["findings"][0]["applicability"] == "confirmed"
    assert result["potential_findings"][0]["applicability"] == "unknown"
    assert result["summary"]["total_cves"] == 1 and result["summary"]["potential_cves"] == 1


def test_cve_invalid_version_and_data_failure_are_explicit(monkeypatch):
    with pytest.raises(cve.CVEAssessmentError, match="Cannot parse"):
        cve.assess("not-version")
    monkeypatch.setattr(cve, "fetch", lambda params: (_ for _ in ()).throw(cve.CVEAssessmentError("NVD unavailable")))
    with pytest.raises(cve.CVEAssessmentError, match="unavailable"):
        cve.assess("7.25.1")


@pytest.mark.parametrize("version,expected", [("7.25.1", True), ("7.26", False), ("7.19.9", False)])
def test_version_range_boundaries(version, expected):
    assert cve.is_affected(cve.parse_version(version), cve.routeros_ranges(RECORD)[0]) is expected

