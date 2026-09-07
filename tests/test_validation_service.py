from pathlib import Path

import pytest

import switchtest.services.validation_service as validation_service_module
from switchtest.domain.enums import ResultStatus, ValidationType
from switchtest.domain.testcase import SnmpCredentials, ValidationStep
from switchtest.exceptions import ValidationExecutionError
from switchtest.infrastructure.trap_listener import ReceivedTrap
from switchtest.services.validation_service import ValidationService


class StubDriver:
    def __init__(self, events: list | None = None) -> None:
        # Shared with a FakeTrapListener in the snmp_trap_received tests, so a
        # test can assert the trigger command really ran *between* the
        # listener binding and it waiting -- not before the socket was ready,
        # and not after the wait had already given up.
        self._events = events
        self.applied_commands: list[list[str]] = []

    def run_show(self, command: str, timeout: int = 30, reauth: bool = False) -> str:
        if command == "show vlan":
            return "VLAN 100 CI_TEST_VLAN100"
        return "Version 1.0"

    def apply_config(self, commands, timeout: int = 30, ignore_errors: bool = False):
        self.applied_commands.append(list(commands))
        if self._events is not None:
            self._events.append("triggered")
        return list(commands)


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
        lambda target, top_ports, all_ports, timeout, on_progress: (
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
        lambda target, top_ports, all_ports, timeout, on_progress: (
            ["22/tcp open (ssh)"],
            "22/tcp open ssh",
        ),
    )

    result = ValidationService().run_validation(
        StubDriver(),
        ValidationStep(
            name="top 100 closed", type=ValidationType.PORT_SCAN_CLOSED, target="192.0.2.1"
        ),
    )

    assert result.status == ResultStatus.FAIL
    assert "22/tcp open (ssh)" in result.message


def test_port_scan_closed_passes_all_ports_through_to_the_scan(monkeypatch) -> None:
    """`all_ports: true` on the ValidationStep must reach scan_top_ports --
    otherwise a testcase that asks for a full 1-65535 sweep silently gets the
    --top-ports sample instead, and no test failure ever points at that."""
    seen: dict = {}

    def fake_scan(target, top_ports, all_ports, timeout, on_progress):
        seen["all_ports"] = all_ports
        return [], "All 131070 scanned ports on 192.0.2.1 are closed"

    monkeypatch.setattr(validation_service_module, "scan_top_ports", fake_scan)

    result = ValidationService().run_validation(
        StubDriver(),
        ValidationStep(
            name="all ports closed",
            type=ValidationType.PORT_SCAN_CLOSED,
            target="192.0.2.1",
            all_ports=True,
        ),
    )

    assert seen["all_ports"] is True
    assert result.status == ResultStatus.PASS


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


# -- snmp_trap_received -------------------------------------------------------
#
# Config-and-audit checks (TC-SM-42's swlog assertions) prove the CLI command
# that creates a trap station succeeded -- they say nothing about whether the
# switch ever actually puts a trap packet on the wire. This validation type
# is the one that listens for it.


class FakeTrapListener:
    """Stands in for TrapListener: records "bound"/"closed" against the same
    shared `events` list a StubDriver records "triggered" into, so a test can
    assert the real ordering (bind, then trigger, then wait) rather than just
    that all three happened somewhere."""

    def __init__(self, events: list, trap) -> None:
        self._events = events
        self._trap = trap

    def __enter__(self) -> "FakeTrapListener":
        self._events.append("bound")
        return self

    def __exit__(self, *exc_info) -> None:
        self._events.append("closed")

    def wait_for(self, timeout, expected_source=None):
        self._events.append("waited")
        return self._trap


def _install_fake_trap_listener(monkeypatch, events: list, trap):
    monkeypatch.setattr(
        validation_service_module,
        "TrapListener",
        lambda port: FakeTrapListener(events, trap),
    )


def test_trap_received_passes_and_binds_before_triggering_before_waiting(monkeypatch) -> None:
    events: list = []
    trap = ReceivedTrap(
        source_ip="192.0.2.1", payload=b"\x30\x00", version="v3", username="snmpv3"
    )
    _install_fake_trap_listener(monkeypatch, events, trap)
    driver = StubDriver(events=events)

    result = ValidationService().run_validation(
        driver,
        ValidationStep(
            name="trap received",
            type=ValidationType.SNMP_TRAP_RECEIVED,
            target="192.0.2.1",
            trap_port=162,
            trigger_commands=["interface port 1/1/1 admin-state disable"],
            timeout=30,
        ),
    )

    assert result.status == ResultStatus.PASS
    assert "192.0.2.1" in result.observed
    # Order matters: triggering before the socket is bound would let the
    # switch's trap race ahead of this process listening for it. The socket
    # closing last, after the wait is done, is just the `with` block ending.
    assert events == ["bound", "triggered", "waited", "closed"]
    assert driver.applied_commands == [["interface port 1/1/1 admin-state disable"]]


def test_trap_not_received_fails(monkeypatch) -> None:
    events: list = []
    _install_fake_trap_listener(monkeypatch, events, None)

    result = ValidationService().run_validation(
        StubDriver(events=events),
        ValidationStep(
            name="trap received",
            type=ValidationType.SNMP_TRAP_RECEIVED,
            target="192.0.2.1",
            timeout=5,
        ),
    )

    assert result.status == ResultStatus.FAIL
    assert "No trap arrived" in result.message


def test_trap_received_from_the_wrong_user_fails(monkeypatch) -> None:
    """The station could be reachable and even sending traps, but with the
    wrong SNMPv3 identity -- e.g. a stale user from a previous run. That is
    also not "the configured account's trap arrived" and must not pass."""
    events: list = []
    trap = ReceivedTrap(
        source_ip="192.0.2.1", payload=b"\x30\x00", version="v3", username="someone-else"
    )
    _install_fake_trap_listener(monkeypatch, events, trap)

    result = ValidationService().run_validation(
        StubDriver(events=events),
        ValidationStep(
            name="trap received",
            type=ValidationType.SNMP_TRAP_RECEIVED,
            target="192.0.2.1",
            timeout=5,
            snmp=SnmpCredentials(user="snmpv3", auth_password="x"),
        ),
    )

    assert result.status == ResultStatus.FAIL
    assert "someone-else" in result.message
    assert "snmpv3" in result.message


def test_trap_received_without_an_expected_user_does_not_check_identity(monkeypatch) -> None:
    """No `snmp:` block on the validation means the test only cares that
    *something* arrived from the target -- identity is opt-in."""
    events: list = []
    trap = ReceivedTrap(
        source_ip="192.0.2.1", payload=b"\x30\x00", version="v3", username="whoever-sent-it"
    )
    _install_fake_trap_listener(monkeypatch, events, trap)

    result = ValidationService().run_validation(
        StubDriver(events=events),
        ValidationStep(
            name="trap received",
            type=ValidationType.SNMP_TRAP_RECEIVED,
            target="192.0.2.1",
            timeout=5,
        ),
    )

    assert result.status == ResultStatus.PASS


def test_trap_received_requires_a_target() -> None:
    with pytest.raises(ValidationExecutionError, match="target"):
        ValidationService().run_validation(
            StubDriver(),
            ValidationStep(name="trap received", type=ValidationType.SNMP_TRAP_RECEIVED),
        )


# -- snmp_trap_received triggered by an SNMP SET, not a CLI command ---------
#
# TC-SM-43's SET check proves the value took; folding a trap check into that
# same SET (rather than a second, CLI-triggered testcase like TC-SM-42's
# admin-disable) answers "does a plain SNMP write also cause a trap" without
# a second live device round trip.


def _fake_snmp_result(ok: bool, value: str | None = None, detail: str = "") -> object:
    from switchtest.infrastructure.snmp import SnmpResult

    return SnmpResult(ok=ok, value=value, detail=detail)


def test_trap_received_via_snmp_set_restores_the_original_value(monkeypatch) -> None:
    events: list = []
    trap = ReceivedTrap(source_ip="192.0.2.1", payload=b"\x30\x00", version="v3", username="snmpv3")
    _install_fake_trap_listener(monkeypatch, events, trap)

    get_calls: list = []
    set_calls: list = []
    monkeypatch.setattr(
        validation_service_module,
        "snmp_get",
        lambda target, port, oid, params, timeout: (
            get_calls.append((target, port, oid)) or _fake_snmp_result(True, "OS6900")
        ),
    )
    monkeypatch.setattr(
        validation_service_module,
        "snmp_set",
        lambda target, port, oid, value, params, value_type, timeout: (
            set_calls.append((oid, value)) or _fake_snmp_result(True, value)
        ),
    )

    result = ValidationService().run_validation(
        StubDriver(events=events),
        ValidationStep(
            name="set triggers a trap",
            type=ValidationType.SNMP_TRAP_RECEIVED,
            target="192.0.2.1",
            oid="sysName.0",
            value="OS6900-SNMPTEST",
            timeout=5,
            snmp=SnmpCredentials(user="snmpv3", auth_password="x"),
        ),
    )

    assert result.status == ResultStatus.PASS
    # The SET happened before the wait (it's the trigger), and the restore
    # -- a second SET back to the original -- happened after: reading the
    # original once, writing it twice (the real value, then back).
    assert [oid for oid, _value in set_calls] == ["sysName.0", "sysName.0"]
    assert set_calls[0] == ("sysName.0", "OS6900-SNMPTEST")
    assert set_calls[1] == ("sysName.0", "OS6900")  # restored to what snmp_get read


def test_trap_received_via_snmp_set_restores_even_when_no_trap_arrives(monkeypatch) -> None:
    """The SET is real and changes the device even when the trap never shows
    up -- restoration must not depend on the trap check having passed."""
    events: list = []
    _install_fake_trap_listener(monkeypatch, events, None)

    set_calls: list = []
    monkeypatch.setattr(
        validation_service_module,
        "snmp_get",
        lambda target, port, oid, params, timeout: _fake_snmp_result(True, "OS6900"),
    )
    monkeypatch.setattr(
        validation_service_module,
        "snmp_set",
        lambda target, port, oid, value, params, value_type, timeout: (
            set_calls.append(value) or _fake_snmp_result(True, value)
        ),
    )

    result = ValidationService().run_validation(
        StubDriver(events=events),
        ValidationStep(
            name="set triggers a trap",
            type=ValidationType.SNMP_TRAP_RECEIVED,
            target="192.0.2.1",
            oid="sysName.0",
            value="OS6900-SNMPTEST",
            timeout=5,
            snmp=SnmpCredentials(user="snmpv3", auth_password="x"),
        ),
    )

    assert result.status == ResultStatus.FAIL
    assert "No trap arrived" in result.message
    assert "SET of sysName.0 itself succeeded" in result.observed
    assert set_calls == ["OS6900-SNMPTEST", "OS6900"]  # still restored


def test_trap_received_via_snmp_set_failure_skips_the_wait(monkeypatch) -> None:
    """A rejected SET is a different, more fundamental problem than "no
    trap" -- it should be reported as such, and there is no point waiting
    out the full timeout for a trap that a failed write was never going to
    cause."""
    events: list = []
    _install_fake_trap_listener(monkeypatch, events, None)

    monkeypatch.setattr(
        validation_service_module,
        "snmp_get",
        lambda target, port, oid, params, timeout: _fake_snmp_result(True, "OS6900"),
    )
    monkeypatch.setattr(
        validation_service_module,
        "snmp_set",
        lambda target, port, oid, value, params, value_type, timeout: _fake_snmp_result(
            False, None, "notWritable"
        ),
    )

    result = ValidationService().run_validation(
        StubDriver(events=events),
        ValidationStep(
            name="set triggers a trap",
            type=ValidationType.SNMP_TRAP_RECEIVED,
            target="192.0.2.1",
            oid="sysName.0",
            value="OS6900-SNMPTEST",
            timeout=5,
            snmp=SnmpCredentials(user="snmpv3", auth_password="x"),
        ),
    )

    assert result.status == ResultStatus.FAIL
    assert "no trap was even attempted" in result.message
    # wait_for was never reached -- FakeTrapListener only records "waited" if
    # it was actually called.
    assert "waited" not in events
