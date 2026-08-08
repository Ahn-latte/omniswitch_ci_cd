from pathlib import Path

import switchtest.services.validation_service as validation_service_module
from switchtest.domain.enums import ResultStatus, ValidationType
from switchtest.domain.testcase import ValidationStep
from switchtest.services.validation_service import ValidationService


class StubDriver:
    def run_show(self, command: str, timeout: int = 30, reauth: bool = False) -> str:
        if command == "show vlan":
            return "VLAN 100 CI_TEST_VLAN100"
        return "Version 1.0"


def test_contains_validator_passes() -> None:
    service = ValidationService()
    result = service.run_validation(
        StubDriver(),
        ValidationStep(
            name="contains",
            type=ValidationType.CONTAINS,
            command="show vlan",
            expected="CI_TEST_VLAN100",
        ),
    )
    assert result.status == ResultStatus.PASS


def test_equals_validator_fails() -> None:
    service = ValidationService()
    result = service.run_validation(
        StubDriver(),
        ValidationStep(
            name="equals",
            type=ValidationType.EQUALS,
            command="show version",
            expected="Different",
        ),
    )
    assert result.status == ResultStatus.FAIL


def test_port_closed_validator_passes_when_nmap_reports_closed(monkeypatch) -> None:
    monkeypatch.setattr(
        validation_service_module,
        "scan_port",
        lambda target, port, timeout, protocol: ("closed", "23/tcp closed telnet"),
    )
    service = ValidationService()
    result = service.run_validation(
        StubDriver(),
        ValidationStep(name="telnet closed", type=ValidationType.PORT_CLOSED, target="192.0.2.1", port=23),
    )
    assert result.status == ResultStatus.PASS


def test_port_closed_validator_scans_udp_when_asked(monkeypatch) -> None:
    # SNMP listens on UDP, so the scan protocol has to reach nmap.
    seen: dict[str, str] = {}

    def fake_scan(target, port, timeout, protocol):
        seen["protocol"] = protocol
        return "open|filtered", "161/udp open|filtered snmp"

    monkeypatch.setattr(validation_service_module, "scan_port", fake_scan)
    result = ValidationService().run_validation(
        StubDriver(),
        ValidationStep(
            name="snmp closed",
            type=ValidationType.PORT_CLOSED,
            target="192.0.2.1",
            port=161,
            protocol="udp",
        ),
    )

    assert seen["protocol"] == "udp"
    # A silent UDP port reads as open|filtered, which is "not open".
    assert result.status == ResultStatus.PASS


def test_port_closed_validator_fails_when_nmap_reports_open(monkeypatch) -> None:
    monkeypatch.setattr(
        validation_service_module,
        "scan_port",
        lambda target, port, timeout, protocol: ("open", "23/tcp open telnet"),
    )
    service = ValidationService()
    result = service.run_validation(
        StubDriver(),
        ValidationStep(name="telnet closed", type=ValidationType.PORT_CLOSED, target="192.0.2.1", port=23),
    )
    assert result.status == ResultStatus.FAIL


def test_web_unreachable_validator_passes_when_navigation_fails(monkeypatch) -> None:
    monkeypatch.setattr(
        validation_service_module,
        "check_web_unreachable",
        lambda target, port, timeout: (True, "net::ERR_CONNECTION_REFUSED"),
    )
    service = ValidationService()
    result = service.run_validation(
        StubDriver(),
        ValidationStep(name="https unreachable", type=ValidationType.WEB_UNREACHABLE, target="192.0.2.1", port=443),
    )
    assert result.status == ResultStatus.PASS


def test_web_unreachable_validator_fails_when_page_loads(monkeypatch) -> None:
    monkeypatch.setattr(
        validation_service_module,
        "check_web_unreachable",
        lambda target, port, timeout: (False, "navigation succeeded"),
    )
    service = ValidationService()
    result = service.run_validation(
        StubDriver(),
        ValidationStep(name="https unreachable", type=ValidationType.WEB_UNREACHABLE, target="192.0.2.1", port=443),
    )
    assert result.status == ResultStatus.FAIL


def test_tls_version_validator_passes_when_capture_matches_expected(monkeypatch) -> None:
    monkeypatch.setattr(
        validation_service_module,
        "capture_tls_version",
        lambda interface, target, port, duration: ("TLS 1.2", "0x0303", Path("reports/captures/fake.pcapng")),
    )
    service = ValidationService()
    result = service.run_validation(
        StubDriver(),
        ValidationStep(
            name="tls version",
            type=ValidationType.TLS_VERSION,
            target="192.0.2.1",
            port=443,
            expected="TLS 1.2",
        ),
    )
    assert result.status == ResultStatus.PASS


def test_tls_version_validator_fails_when_capture_differs(monkeypatch) -> None:
    monkeypatch.setattr(
        validation_service_module,
        "capture_tls_version",
        lambda interface, target, port, duration: ("TLS 1.0", "0x0301", Path("reports/captures/fake.pcapng")),
    )
    service = ValidationService()
    result = service.run_validation(
        StubDriver(),
        ValidationStep(
            name="tls version",
            type=ValidationType.TLS_VERSION,
            target="192.0.2.1",
            port=443,
            expected="TLS 1.2",
        ),
    )
    assert result.status == ResultStatus.FAIL


def test_tcp_blocked_validator_passes_when_connection_is_dropped(monkeypatch) -> None:
    monkeypatch.setattr(
        validation_service_module,
        "probe_tcp",
        lambda target, port, timeout: (True, "connection to 192.0.2.1:22 timed out after 20s (dropped)"),
    )
    service = ValidationService()
    result = service.run_validation(
        StubDriver(),
        ValidationStep(name="ssh blocked", type=ValidationType.TCP_BLOCKED, target="192.0.2.1", port=22),
    )
    assert result.status == ResultStatus.PASS


def test_tcp_blocked_validator_fails_when_connection_succeeds(monkeypatch) -> None:
    monkeypatch.setattr(
        validation_service_module,
        "probe_tcp",
        lambda target, port, timeout: (False, "connection to 192.0.2.1:22 succeeded in 0.01s"),
    )
    service = ValidationService()
    result = service.run_validation(
        StubDriver(),
        ValidationStep(name="ssh blocked", type=ValidationType.TCP_BLOCKED, target="192.0.2.1", port=22),
    )
    assert result.status == ResultStatus.FAIL


def test_port_scan_closed_passes_when_nothing_is_open(monkeypatch) -> None:
    monkeypatch.setattr(
        validation_service_module,
        "scan_top_ports",
        lambda target, top_ports, timeout, on_progress: (
            [],
            "All 200 scanned ports on 192.0.2.1 are closed",
        ),
    )

    result = ValidationService().run_validation(
        StubDriver(),
        ValidationStep(
            name="top 100 closed", type=ValidationType.PORT_SCAN_CLOSED, target="192.0.2.1"
        ),
    )

    assert result.status == ResultStatus.PASS


def test_port_scan_closed_names_the_ports_still_open(monkeypatch) -> None:
    monkeypatch.setattr(
        validation_service_module,
        "scan_top_ports",
        lambda target, top_ports, timeout, on_progress: (["22/tcp open (ssh)"], "22/tcp open ssh"),
    )

    result = ValidationService().run_validation(
        StubDriver(),
        ValidationStep(
            name="top 100 closed", type=ValidationType.PORT_SCAN_CLOSED, target="192.0.2.1"
        ),
    )

    assert result.status == ResultStatus.FAIL
    assert "22/tcp open (ssh)" in result.message


def test_api_unreachable_passes_when_the_request_fails(monkeypatch) -> None:
    monkeypatch.setattr(
        validation_service_module,
        "check_api_unreachable",
        lambda target, port, path, timeout: (True, "GET https://192.0.2.1:443/ timed out after 20s"),
    )

    result = ValidationService().run_validation(
        StubDriver(),
        ValidationStep(
            name="api unreachable",
            type=ValidationType.API_UNREACHABLE,
            target="192.0.2.1",
            port=443,
        ),
    )

    assert result.status == ResultStatus.PASS


def test_api_unreachable_fails_when_the_switch_answers(monkeypatch) -> None:
    # Any answer means the listener is up -- a 401 is still "reachable".
    monkeypatch.setattr(
        validation_service_module,
        "check_api_unreachable",
        lambda target, port, path, timeout: (False, "GET ... answered HTTP 401 Unauthorized"),
    )

    result = ValidationService().run_validation(
        StubDriver(),
        ValidationStep(
            name="api unreachable",
            type=ValidationType.API_UNREACHABLE,
            target="192.0.2.1",
            port=443,
        ),
    )

    assert result.status == ResultStatus.FAIL
