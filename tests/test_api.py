import json

from fastapi.testclient import TestClient
import pytest

from app.main import app
import app.main as main_module
from app.services import store
from app.services.engine import assess
from app.services.parser import RouterExport


VALID = b'''/system identity
set name=api-test
/ip ssh
set strong-crypto=no
'''


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(store, "DATABASE", tmp_path / "aynuo.db")
    with TestClient(app, client=("127.0.0.1", 50000)) as test_client:
        yield test_client


def test_health_dashboard_and_static_assets(client):
    health = client.get("/api/health").json()
    assert health["product"] == "AYNUO" and health["version"] == "4.0.0"
    assert "Security Command Center" in client.get("/").text
    assert client.get("/assets/js/app.js").status_code == 200


def test_assessment_lifecycle_and_exports(client):
    response = client.post("/api/assessments", files={"file": ("router.rsc", VALID, "text/plain")})
    assert response.status_code == 202
    aid = response.json()["id"]
    assert client.get(f"/api/assessments/{aid}/status").json()["status"] == "completed"
    result = client.get(f"/api/assessments/{aid}").json()
    assert result["filename"] == "router.rsc"
    assert "PROTO-006" in {item["id"] for item in result["findings"]}
    assert client.get("/api/assessments").status_code == 405
    for kind, prefix in {"json": b"{", "csv": b"\xef\xbb\xbf", "html": b"<!doctype", "pdf": b"%PDF"}.items():
        exported = client.get(f"/api/assessments/{aid}/export/{kind}")
        assert exported.status_code == 200
        assert exported.content.startswith(prefix)
        assert "attachment" in exported.headers["content-disposition"]


@pytest.mark.parametrize("name,body,status", [
    ("config.exe", VALID, 415), ("empty.rsc", b"", 422),
    ("binary.rsc", b"/system identity\x00\nset name=a", 422),
    ("malformed.rsc", b"/system identity\nset name=\"oops", 422),
])
def test_upload_validation(client, name, body, status):
    response = client.post("/api/assessments", files={"file": (name, body, "application/octet-stream")})
    assert response.status_code == status


def test_missing_assessment_and_unsupported_export(client):
    assert client.get("/api/assessments/not-found").status_code == 404
    response = client.post("/api/assessments", files={"file": ("router.rsc", VALID)})
    aid = response.json()["id"]
    assert client.get(f"/api/assessments/{aid}/export/xml").status_code == 400


def test_live_assessment_api_uses_shared_engine_without_leaking_password(client, monkeypatch, caplog):
    def fake_live(target, username, password, **kwargs):
        kwargs["progress"]("retrieving_router_information")
        export = RouterExport()
        export.present_sections.update({"system/resource", "system/identity", "ip/ssh"})
        export.sections["system/resource"] = [{"version": "7.16", "board-name": "CHR"}]
        export.sections["system/identity"] = [{"name": "mock-router"}]
        export.sections["ip/ssh"] = [{"strong-crypto": "no"}]
        export.identity["name"] = "mock-router"
        export.metadata.update({"routeros_version": "7.16", "hardware_model": "CHR"})
        result = assess(export)
        result["source"] = "SSH"
        result["device"]["management_ip"] = target.resolved_ip
        return result

    monkeypatch.setattr(main_module, "run_live_audit", fake_live)
    secret = "never-store-this-7821"
    response = client.post("/api/audits/ssh", json={
        "host": "192.168.88.1", "username": "auditor", "password": secret,
        "port": 22,
    })
    assert response.status_code == 202
    aid = response.json()["id"]
    state = client.get(f"/api/assessments/{aid}/status").json()
    assert state["status"] == "completed" and state["source"] == "SSH"
    result = client.get(f"/api/assessments/{aid}/results").json()
    assert result["source"] == "SSH" and result["device"]["identity"] == "mock-router"
    assert secret not in json.dumps(response.json())
    assert secret not in json.dumps(state)
    assert secret not in json.dumps(result)
    assert secret not in caplog.text
    for kind in ("html", "json", "csv", "pdf"):
        assert secret.encode() not in client.get(f"/api/assessments/{aid}/export/{kind}").content


def test_live_endpoint_rejects_unsafe_targets(client):
    payload = {"host": "8.8.8.8", "username": "a", "password": "b", "port": 22}
    assert client.post("/api/audits/ssh", json=payload).status_code == 422
    payload.update({"host": "192.168.88.1", "port": 0})
    assert client.post("/api/audits/ssh", json=payload).status_code == 422


def test_host_key_inspection_and_explicit_enrollment(client, monkeypatch):
    key = {"host": "192.168.88.1", "port": 22, "key_type": "ssh-ed25519", "fingerprint": "SHA256:abcdefghijklmnopqrstuv", "key_base64": "abc", "trusted": False}
    monkeypatch.setattr(main_module, "inspect_host_key", lambda target, timeout: dict(key))
    monkeypatch.setattr(main_module, "enroll_host_key", lambda target, fingerprint, timeout: {**key, "trusted": True})
    assert client.post("/api/ssh/host-key/inspect", json={"host": "192.168.88.1", "port": 22}).json()["trusted"] is False
    enrolled = client.post("/api/ssh/host-key/enroll", json={"host": "192.168.88.1", "port": 22, "fingerprint": key["fingerprint"]})
    assert enrolled.status_code == 200 and enrolled.json()["trusted"] is True


def test_offline_cve_endpoint_and_exports(client, monkeypatch):
    def fake_cves(version, **kwargs):
        kwargs["progress"]("generating_results")
        return {"product": "AYNUO", "assessment_type": "CVE", "source": "OFFLINE", "created_at": "2026-11-23T00:00:00+00:00", "routeros_version": version,
                "device": {"identity": None, "routeros_version": version, "hardware_model": None, "management_ip": None},
                "findings": [{"id": "CVE-2026-0001", "severity": "high", "cvss_score": 8.1, "cvss_version": "3.1", "published": "2026-01-01", "affected_range": "< 7.26", "fixed_version": "7.26", "description": "verified", "remediation": "upgrade", "applicability": "confirmed", "references": [], "exploit": {"status": "unknown"}}], "potential_findings": [],
                "summary": {"total_cves": 1, "potential_cves": 0, "severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "unknown": 0}, "data_status": "available", "source": "NVD"}}
    monkeypatch.setattr(main_module, "assess_cves", fake_cves)
    response = client.post("/api/cve/version", json={"version": "7.25.1"})
    assert response.status_code == 202
    aid = response.json()["id"]
    result = client.get(f"/api/assessments/{aid}/results").json()
    assert result["assessment_type"] == "CVE" and result["findings"][0]["id"] == "CVE-2026-0001"
    assert result["routeros_version"] == "7.25.1"
    for kind in ("json", "html", "csv", "pdf"):
        assert client.get(f"/api/assessments/{aid}/export/{kind}").status_code == 200


def test_unified_scan_runs_both_components_and_exports(client, monkeypatch):
    def fake_scan(target, username, password, **kwargs):
        kwargs["progress"]("running_assessments")
        kwargs["component_progress"]("audit", "completed")
        kwargs["component_progress"]("cve", "completed")
        device = {"identity": "router", "routeros_version": "7.25.1", "hardware_model": "CHR", "management_ip": target.resolved_ip}
        audit = assess(RouterExport(identity={"name": "router"}, metadata={"routeros_version": "7.25.1", "hardware_model": "CHR"}))
        audit["device"].update(device)
        cve = {"assessment_type": "CVE", "source": "SSH", "device": device, "routeros_version": "7.25.1", "findings": [], "potential_findings": [], "summary": {"total_cves": 0, "potential_cves": 0, "severity": {}, "source": "NVD"}}
        return {"product": "AYNUO", "assessment_type": "SCAN", "source": "SSH", "created_at": "2026-11-23T00:00:00+00:00", "device": device, "routeros_version": "7.25.1", "component_status": {"audit": {"status": "completed", "error": None}, "cve": {"status": "completed", "error": None}}, "audit": audit, "cve": cve, "summary": {"score": audit["summary"]["score"], "audit_findings": 0, "total_cves": 0, "potential_cves": 0, "scan_status": "completed"}}
    monkeypatch.setattr(main_module, "run_unified_scan", fake_scan)
    response = client.post("/api/scans/ssh", json={"host": "192.168.88.1", "port": 22, "username": "audit", "password": "secret"})
    assert response.status_code == 202
    aid = response.json()["id"]
    state = client.get(f"/api/assessments/{aid}/status").json()
    assert state["audit_status"] == state["cve_status"] == "completed"
    result = client.get(f"/api/assessments/{aid}/results").json()
    assert result["assessment_type"] == "SCAN" and result["audit"] and result["cve"]
    for kind in ("json", "html", "csv", "pdf"):
        assert client.get(f"/api/assessments/{aid}/export/{kind}").status_code == 200

