import json
import os

import pytest


pytestmark = pytest.mark.skipif(
    not os.environ.get("AYNUO_E2E_URL"),
    reason="Set AYNUO_E2E_URL to run browser validation against a live launcher instance.",
)


def test_unified_scan_dashboard_renders_both_result_tabs():
    from playwright.sync_api import expect, sync_playwright

    device = {"identity": "e2e-router", "routeros_version": "7.25.1", "hardware_model": "CHR", "management_ip": "192.168.88.1"}
    result = {
        "product": "AYNUO", "assessment_type": "SCAN", "source": "SSH",
        "created_at": "2026-11-23T00:00:00+00:00", "device": device, "routeros_version": "7.25.1",
        "component_status": {"audit": {"status": "completed", "error": None}, "cve": {"status": "completed", "error": None}},
        "audit": {"device": device, "findings": [{"id": "SSH-001", "title": "Weak SSH settings", "severity": "high", "category": "Management", "description": "Legacy algorithms are enabled.", "evidence": ["strong-crypto=no"], "impact": "Weak negotiation", "remediation": "/ip ssh set strong-crypto=yes", "status": "failed"}], "summary": {"score": 82, "severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "informational": 0}, "scoring_method": "Coverage-aware weighted score"}},
        "cve": {"device": device, "findings": [{"id": "CVE-2026-0001", "severity": "high", "cvss_score": 8.1, "cvss_version": "3.1", "published": "2026-01-01", "affected_range": "< 7.26", "fixed_version": "7.26", "description": "Verified RouterOS vulnerability", "remediation": "Upgrade RouterOS", "applicability": "confirmed", "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-0001"], "exploit": {"status": "unknown"}}], "potential_findings": [], "summary": {"total_cves": 1, "potential_cves": 0, "source": "NVD"}},
        "summary": {"score": 82, "audit_findings": 1, "total_cves": 1, "potential_cves": 0, "scan_status": "completed"},
    }
    console_errors = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chrome", headless=True)
        page = browser.new_page()
        page.on("console", lambda message: console_errors.append(message.text) if message.type == "error" else None)
        page.route("**/api/scans/ssh", lambda route: route.fulfill(status=202, content_type="application/json", body='{"id":"scan-e2e","status":"queued"}'))
        page.route("**/api/assessments/scan-e2e/status", lambda route: route.fulfill(content_type="application/json", body='{"status":"completed","stage":"generating_results","audit_status":"completed","cve_status":"completed"}'))
        page.route("**/api/assessments/scan-e2e/results", lambda route: route.fulfill(content_type="application/json", body=json.dumps(result)))
        page.goto(os.environ["AYNUO_E2E_URL"], wait_until="networkidle")
        expect(page.locator("#scanForm")).to_be_visible()
        expect(page.locator("#scanPassword")).to_have_attribute("type", "password")
        assert "Assessment History" not in page.locator("body").inner_text()
        page.locator("#scanHost").fill("192.168.88.1")
        page.locator("#scanUsername").fill("auditor")
        page.locator("#scanPassword").fill("temporary-secret")
        page.locator("#startScan").click()
        expect(page.locator("#status")).to_have_text("Complete", timeout=5000)
        expect(page.locator("#score")).to_have_text("82", timeout=2000)
        expect(page.locator("#auditList .finding")).to_have_count(1)
        page.locator('[data-result-tab="cve"]').click()
        expect(page.locator("#cveList .cve-card")).to_have_count(1)
        expect(page.locator("#scanPassword")).to_have_value("")
        assert not console_errors
        browser.close()

