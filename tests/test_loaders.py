from pathlib import Path

import pytest

from switchtest.domain.device import DeviceDefinition
from switchtest.domain.enums import TransportType, ValidationType
from switchtest.infrastructure.loaders.lab import load_lab
from switchtest.infrastructure.loaders.suites import load_suite_testcases
from switchtest.infrastructure.loaders.testcases import load_testcase
from switchtest.utils.templating import render_template

LAB_FILE = Path("tests/fixtures/lab.yaml")


def test_accounts_become_devices() -> None:
    devices = load_lab(LAB_FILE).devices()
    assert devices["admin"].platform == "aos"
    assert devices["admin"].username == "admin1"
    # The role name is the device name, so `--device admin` and the lab file's
    # `accounts.admin` are visibly the same thing.
    assert devices["admin"].name == "admin"


def test_devices_default_to_ssh_transport() -> None:
    assert load_lab(LAB_FILE).devices()["admin"].transport == TransportType.SSH


def test_an_account_without_a_transport_is_not_a_device() -> None:
    # `readonly` is only ever logged into by the WebView browser tests, so
    # switchtest must not try to open a session for it.
    devices = load_lab(LAB_FILE).devices()
    assert "readonly" not in devices
    assert load_lab(LAB_FILE).account("readonly").username == "readonlyy"


def test_secureadmin_is_attached_over_the_serial_console() -> None:
    # TC-IA-134 bans this machine's IP, so the audit session must be
    # out-of-band or it dies with every other network path.
    device = load_lab(LAB_FILE).devices()["secureadmin"]
    assert device.transport == TransportType.SERIAL
    assert device.serial_port == "COM9"
    # host/port still describe the SSH service the failed logins are sent to.
    assert device.host and device.port == 22


def test_lab_variables_cover_what_testcases_substitute() -> None:
    variables = load_lab(LAB_FILE).variables()
    assert variables["host"] == "192.0.2.1"
    assert variables["station_ip"] == "192.0.2.50"
    assert variables["system_name"] == "OS6900"
    assert variables["lowpriv_user"] == "user1"
    assert variables["baseline_ip_lockout_threshold"] == "6"
    # Real account passwords are never exposed to testcase templating; only the
    # password for accounts a testcase creates itself.
    assert variables["test_password"] == "12#qweASD"
    assert not any("not-a-real-password" == value for value in variables.values())


def test_serial_device_requires_a_serial_port() -> None:
    with pytest.raises(ValueError, match="serial_port"):
        DeviceDefinition(
            name="console-no-port",
            host="192.168.1.1",
            username="secureadmin",
            password="x",
            platform="aos",
            transport=TransportType.SERIAL,
        )


def test_a_device_needs_a_password_from_somewhere() -> None:
    with pytest.raises(ValueError, match="password"):
        DeviceDefinition(name="nopw", host="192.168.1.1", username="admin1", platform="aos")


def test_load_testcase() -> None:
    testcase = load_testcase(Path("testcases/vlan/vlan_create.yaml"))
    assert testcase.id == "TC-VLAN-001"
    assert len(testcase.validations) == 2


def test_load_snmp_testcase_credentials() -> None:
    testcase = load_testcase(Path("testcases/secfunc/check_snmpv3_get_set_permissions.yaml"))
    get_check = testcase.validations[0]
    assert get_check.type == ValidationType.SNMP_GET
    assert get_check.oid == "sysName.0"
    assert get_check.snmp is not None
    assert get_check.snmp.auth_protocol == "SHA-256"
    assert get_check.snmp.priv_protocol == "AES"
    # The read-only account's write attempt must be the denial check, not a set.
    denial = testcase.validations[-1]
    assert denial.type == ValidationType.SNMP_DENIED
    assert denial.snmp.user.endswith("ro")


def test_service_disable_testcase_scans_the_top_ports() -> None:
    testcase = load_testcase(Path("testcases/secfunc/check_ip_service_disabled_enforcement.yaml"))
    scan = next(v for v in testcase.validations if v.type == ValidationType.PORT_SCAN_CLOSED)
    assert scan.top_ports == 100
    # One nmap run covers both protocols, so the per-port checks are gone.
    assert not any(v.type == ValidationType.PORT_CLOSED for v in testcase.validations)
    # UDP scanning is slow enough that the default 30s timeout would never do.
    assert scan.timeout >= 300
    # Cleanup must not silently swallow failures -- only the leftover-clearing
    # setup steps may.
    assert not any(step.ignore_errors for step in testcase.cleanup)


def test_load_suite_testcases() -> None:
    suite, tests = load_suite_testcases(Path("suites/smoke.yaml"))
    assert suite.name == "smoke"
    assert len(tests) >= 1


def test_snmp_testcase_reads_sysname_and_os_version() -> None:
    testcase = load_testcase(Path("testcases/secfunc/check_snmpv3_get_set_permissions.yaml"))
    oids = [v.oid for v in testcase.validations if v.oid]
    assert "sysName.0" in oids
    assert "sysDescr.0" in oids
    version_check = next(v for v in testcase.validations if v.oid == "sysDescr.0")
    # The version comes from the device entry, never hardcoded in the testcase.
    assert version_check.pattern == "$expected_firmware"


def test_variables_are_substituted_everywhere_not_just_in_validations() -> None:
    """A `$name` in a cleanup command or an SNMP credential used to be passed to
    the switch as those literal characters -- nothing rejects that, the command
    just does the wrong thing. Every string in a testcase must be substituted."""
    variables = load_lab(LAB_FILE).variables()
    testcase = load_testcase(
        Path("testcases/secfunc/check_snmpv3_get_set_permissions.yaml"), variables=variables
    )
    creation = [c for step in testcase.setup for c in (step.commands or [])]
    assert any("12#qweASD" in command for command in creation), creation
    assert testcase.validations[0].snmp.auth_password == "12#qweASD"
    assert testcase.cleanup[0].commands[0] == "system name OS6900"


def test_no_testcase_is_left_holding_an_unsubstituted_variable() -> None:
    variables = load_lab(LAB_FILE).variables()
    for path in sorted(Path("testcases").rglob("*.yaml")):
        testcase = load_testcase(path, variables=variables)
        for step in list(testcase.setup) + list(testcase.cleanup):
            for command in step.commands or []:
                assert "$" not in command, f"{path}: {command}"
        for validation in testcase.validations:
            assert "$" not in (validation.command or ""), f"{path}: {validation.command}"


def test_an_unknown_variable_survives_instead_of_becoming_empty() -> None:
    # An empty `pattern: "$expected_firmware"` matches anything -- a firmware
    # check that silently passes. Leaving the placeholder makes it fail loudly.
    assert render_template("$expected_firmware", {"host": "192.0.2.1"}) == "$expected_firmware"


def test_a_bare_dollar_is_not_treated_as_a_variable() -> None:
    # Regex end anchors live in `pattern` fields and must survive substitution.
    assert render_template(r"Threshold:\s*3$", {"host": "x"}) == r"Threshold:\s*3$"


def test_the_lab_declares_expected_firmware() -> None:
    # Without it, `$expected_firmware` stays unsubstituted and the sysDescr
    # check fails rather than passing vacuously -- but the point is for it to
    # actually check the version.
    assert load_lab(LAB_FILE).devices()["secureadmin"].expected_firmware


def test_service_disable_testcase_probes_every_management_path() -> None:
    testcase = load_testcase(Path("testcases/secfunc/check_ip_service_disabled_enforcement.yaml"))
    types = [v.type for v in testcase.validations]
    assert ValidationType.TCP_BLOCKED in types      # SSH socket
    assert ValidationType.API_UNREACHABLE in types  # HTTP request
    assert ValidationType.WEB_UNREACHABLE in types  # browser navigation
    api_check = next(v for v in testcase.validations if v.type == ValidationType.API_UNREACHABLE)
    # Probing the auth endpoint would burn the account's lockout budget.
    assert api_check.path == "/"
