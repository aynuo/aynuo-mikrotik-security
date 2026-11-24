from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_frontend_is_offline_and_has_no_inline_event_handlers():
    html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    assert "cdn." not in html and "fonts.googleapis" not in html
    assert "onclick=" not in html
    assert "id=\"auditSearch\"" in html and "data-export=\"pdf\"" in html
    assert "Assessment History" not in html and 'href="#history"' not in html


def test_frontend_uses_unified_scan_api():
    javascript = (ROOT / "frontend" / "js" / "app.js").read_text(encoding="utf-8")
    assert "'/api/scans/ssh'" in javascript
    assert "/status`" in javascript
    assert "catch{}" not in javascript and "catch {}" not in javascript
    assert "escapeHtml" in javascript


def test_live_form_is_secure_and_connected_to_api():
    html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    javascript = (ROOT / "frontend" / "js" / "app.js").read_text(encoding="utf-8")
    assert 'id="scanPassword"' in html and 'type="password"' in html
    assert "'/api/scans/ssh'" in javascript
    assert "/api/ssh/host-key/inspect" in javascript and "/api/ssh/host-key/enroll" in javascript
    assert "password.value=''" in javascript
    assert "localStorage" not in javascript and "sessionStorage" not in javascript

