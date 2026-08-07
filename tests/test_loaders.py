from pathlib import Path

import pytest

from switchtest.domain.device import DeviceDefinition
from switchtest.domain.enums import TransportType, ValidationType
from switchtest.infrastructure.loaders.devices import load_devices
from switchtest.infrastructure.loaders.suites import load_suite_testcases
from switchtest.infrastructure.loaders.testcases import load_testcase


def test_load_devices() -> None:
    devices = load_devices(Path("configs/devices.yaml"))
    assert "ACSSW01" in devices
    assert devices["ACSSW01"].platform == "aos"


def test_devices_default_to_ssh_transport() -> None:
    devices = load_devices(Path("configs/devices.yaml"))
    assert devices["ACSSW01"].transport == TransportType.SSH


def test_secureadmin_is_attached_over_the_serial_console() -> None:
    # TC-IA-134 bans this machine's IP, so the audit session must be
    # out-of-band or it dies with every other network path.
    device = load_devices(Path("configs/devices.yaml"))["secureadmin"]
    assert device.transport == TransportType.SERIAL
    assert device.serial_port
    # host/port still describe the SSH service the failed logins are sent to.
    assert device.host and device.port == 22


def test_serial_device_requires_a_serial_port() -> None:
    with pytest.raises(ValueError, match="serial_port"):
        DeviceDefinition(
            name="console-no-port",
            host="192.168.1.1",
            username="secureadmin",
            password_env="SWITCH_SECUREADMIN_PASSWORD",
            platform="aos",
            transport=TransportType.SERIAL,
        )


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


def test_secureadmin_declares_expected_firmware() -> None:
    # Without it, `$expected_firmware` would stay unsubstituted and the
    # sysDescr check would fail rather than pass vacuously -- but the point is
    # for it to actually check the version.
    device = load_devices(Path("configs/devices.yaml"))["secureadmin"]
    assert device.expected_firmware
