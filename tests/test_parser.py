import pytest

from app.services.parser import parse_export, redact


def test_normalizes_paths_and_preserves_multiple_set_rows():
    parsed = parse_export('''/ip service
set telnet disabled=no port=23
set [ find name=ssh ] disabled=no address=10.0.0.0/24
''')
    assert parsed.has("ip/service")
    assert [row["name"] for row in parsed.get("ip/service")] == ["telnet", "ssh"]
    assert parsed.get("ip/service")[0]["port"] == 23


def test_joins_continuations_and_extracts_metadata():
    parsed = parse_export('''# 2026-11-23 by RouterOS 7.20.4
# model = CCR2004-1G-12S+2XS
/system identity
set name="branch \\
router"
''')
    assert parsed.identity["name"] == "branch router"
    assert parsed.metadata == {"routeros_version": "7.20.4", "hardware_model": "CCR2004-1G-12S+2XS"}


@pytest.mark.parametrize("text", ["", "# only comments", "not a router export", "/system identity\n# no command"])
def test_rejects_empty_or_non_configuration_text(text):
    with pytest.raises(ValueError):
        parse_export(text)


def test_rejects_binary_nul_and_malformed_quotes():
    with pytest.raises(ValueError, match="NUL"):
        parse_export('/system identity\nset name=a\x00b')
    with pytest.raises(ValueError, match="Malformed"):
        parse_export('/system identity\nset name="unterminated')


def test_redacts_secret_bearing_fields():
    redacted = redact('password=hunter2 community="private value" pre-shared-key=abc')
    assert "hunter2" not in redacted and "private value" not in redacted and "abc" not in redacted
    assert redacted.count("[REDACTED]") == 3

