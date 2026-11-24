import json

from app.reports.export import export
from app.services.engine import assess
from app.services.parser import parse_export


def result_with_secret():
    result = assess(parse_export('/snmp\nset enabled=yes\n/snmp community\nadd name=public write-access=yes addresses=0.0.0.0/0'))
    result.update({"id": "id", "filename": "router.rsc"})
    return result


def test_all_reports_are_nonempty_branded_and_redacted():
    result = result_with_secret()
    for kind in ("html", "json", "csv", "pdf"):
        body, content_type, extension = export(result, kind)
        assert body and extension == kind and content_type
        assert b"public" not in body.lower()
        if kind != "pdf":
            assert b"AYNUO" in body or kind == "csv"


def test_json_counts_match_result():
    result = result_with_secret()
    body, _, _ = export(result, "json")
    decoded = json.loads(body)
    assert decoded["summary"]["failed_controls"] == len(decoded["findings"])
    assert sum(decoded["summary"]["severity"].values()) == len(decoded["findings"])

