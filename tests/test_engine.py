from concurrent.futures import ThreadPoolExecutor

from app.services.engine import assess
from app.services.parser import parse_export


UNSAFE = '''# 2026-01-01 by RouterOS 7.14.3
# model = RB5009UG+S+
/system identity
set name="edge-1"
/ip service
set telnet disabled=no port=23 address=""
set ftp disabled=no port=21 address=""
set ssh disabled=no port=22 address=""
/ip ssh
set strong-crypto=no
/ip upnp
set enabled=yes
/user
add name=admin group=full address=""
/user settings
set minimum-password-length=0
/ip firewall filter
add chain=forward action=accept
/ip firewall nat
add chain=dstnat action=dst-nat protocol=tcp dst-port=8291 to-addresses=192.0.2.10
/interface pptp-server server
set enabled=yes
/system logging
add topics=info action=memory
'''


def test_real_rules_and_supplementary_controls_execute():
    result = assess(parse_export(UNSAFE))
    ids = {item["id"] for item in result["findings"]}
    assert {"MGMT-001", "MGMT-002", "MGMT-003", "MGMT-004", "PROTO-006", "PROTO-008", "USER-002"} <= ids
    assert {"FW-001", "NAT-001", "VPN-001", "LOG-001"} <= ids
    assert result["device"]["identity"] == "edge-1"
    assert result["device"]["routeros_version"] == "7.14.3"
    assert result["device"]["hardware_model"] == "RB5009UG+S+"
    assert result["summary"]["score"] < 100


def test_missing_sections_are_not_counted_as_passed():
    result = assess(parse_export('/system identity\nset name=edge'))
    assert result["summary"]["evaluated_controls"] == 0
    assert result["summary"]["passed_controls"] == 0
    assert result["summary"]["not_evaluated_controls"] == result["summary"]["total_controls"]
    assert all(control["status"] == "not_evaluated" for control in result["controls"])


def test_present_safe_control_is_passed():
    result = assess(parse_export('/ip ssh\nset strong-crypto=yes'))
    control = next(item for item in result["controls"] if item["id"] == "PROTO-006")
    assert control["status"] == "passed"
    assert "PROTO-006" not in {item["id"] for item in result["findings"]}


def test_partial_snmp_and_vpn_data_cannot_imply_a_pass():
    result = assess(parse_export('/snmp\nset enabled=yes\n/interface pptp-server server\nset enabled=no'))
    states = {item["id"]: item["status"] for item in result["controls"]}
    assert states["PROTO-011"] == "not_evaluated"
    assert states["PROTO-012"] == "not_evaluated"
    assert states["VPN-001"] == "not_evaluated"


def test_routeros_v6_and_v7_wifi_syntax():
    v6 = assess(parse_export('/interface wireless\nset wlan1 disabled=no wps-mode=push-button'))
    v7 = assess(parse_export('/interface wifi security\nadd name=secure disable-pmkid=no wps=push-button'))
    assert "WIFI-002" in {item["id"] for item in v6["findings"]}
    assert {"WIFI-001", "WIFI-002"} <= {item["id"] for item in v7["findings"]}


def test_concurrent_assessments_do_not_share_reporters():
    unsafe = parse_export('/ip ssh\nset strong-crypto=no')
    safe = parse_export('/ip ssh\nset strong-crypto=yes')
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(assess, [unsafe, safe] * 25))
    for index, result in enumerate(results):
        ids = {item["id"] for item in result["findings"]}
        assert ("PROTO-006" in ids) is (index % 2 == 0)

