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
        lambda target, port, timeout: ("closed", "23/tcp closed telnet"),
    )
    service = ValidationService()
    result = service.run_validation(
        StubDriver(),
        ValidationStep(name="telnet closed", type=ValidationType.PORT_CLOSED, target="192.0.2.1", port=23),
    )
    assert result.status == ResultStatus.PASS


def test_port_closed_validator_fails_when_nmap_reports_open(monkeypatch) -> None:
    monkeypatch.setattr(
        validation_service_module,
        "scan_port",
        lambda target, port, timeout: ("open", "23/tcp open telnet"),
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
        lambda interface, target, port, duration: ("TLS 1.2", "0x0303"),
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
        lambda interface, target, port, duration: ("TLS 1.0", "0x0301"),
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
