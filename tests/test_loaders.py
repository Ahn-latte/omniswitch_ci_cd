from pathlib import Path

import pytest

from switchtest.domain.device import DeviceDefinition
from switchtest.domain.enums import TransportType
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


def test_load_suite_testcases() -> None:
    suite, tests = load_suite_testcases(Path("suites/smoke.yaml"))
    assert suite.name == "smoke"
    assert len(tests) >= 1
