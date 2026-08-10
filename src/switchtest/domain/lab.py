"""The one file an operator edits: which switch, which accounts, what the
switch's baseline settings are.

Everything a testcase would otherwise hardcode lives here, for two reasons.
The obvious one is that a lab move used to mean editing a dozen YAML files.
The subtler one is correctness: a cleanup that restores `session cli timeout 4`
is asserting what this switch's baseline *is*, and when that number is written
into eight testcases independently, nothing keeps them agreeing with each
other or with the device.
"""

from typing import Optional

from pydantic import BaseModel, Field, model_validator

from switchtest.domain.device import DeviceDefinition
from switchtest.domain.enums import TransportType


class ProvisionSpec(BaseModel):
    """An account the test run creates and deletes rather than expecting to
    already exist. `privileges` is the tail of AOS's `user <name> password
    <password> <privileges>`, e.g. `read-only all`."""

    privileges: str


class LabAccount(BaseModel):
    username: str
    password: Optional[str] = None
    password_env: Optional[str] = None
    enable_password: Optional[str] = None
    enable_password_env: Optional[str] = None
    # Omit for an account that is only ever logged into by something other than
    # switchtest -- the WebView browser tests, say -- so no device is built for it.
    transport: Optional[TransportType] = None
    provision: Optional[ProvisionSpec] = None

    @model_validator(mode="after")
    def _needs_a_password(self) -> "LabAccount":
        if not self.password and not self.password_env:
            raise ValueError(
                f"account '{self.username}' needs 'password' or 'password_env'"
            )
        return self


class LabSwitch(BaseModel):
    host: str
    ssh_port: int = 22
    # `system name` on the device. TC-SM-43 writes sysName over SNMP and puts
    # this back afterwards.
    system_name: str = "OS6900"
    expected_firmware: Optional[str] = None
    expected_prompt: str = "->"
    strict_host_key: bool = False
    connection_timeout: int = 15
    command_timeout: int = 30


class LabConsole(BaseModel):
    port: str = "COM4"
    baudrate: int = 115200


class LabBaseline(BaseModel):
    """What every cleanup restores the switch to.

    These are claims about this particular switch, not AOS defaults. Check them
    against `show` output before a first run: a wrong value here is worse than
    no value, because cleanups will confidently set it.
    """

    ip_lockout_threshold: int = 6
    lockout_duration: int = 0
    password_size_min: int = 9
    # `user password-history`: how many recent passwords the switch refuses to
    # reuse. TC-IA-124 pins this to the baseline before asserting reuse is
    # refused; it never changes the value, so there is nothing to restore.
    password_history: int = 3
    session_timeout: int = 4
    swlog_flash_file_size: int = 1250
    swlog_size_trap_threshold: int = 90
    swlog_appid_level: str = "info"


class LabConfig(BaseModel):
    switch: LabSwitch
    console: LabConsole = Field(default_factory=LabConsole)
    accounts: dict[str, LabAccount]
    # This machine's address, as the switch sees it: SNMP trap receiver in
    # TC-SM-42, and the source IP that the IP-ban testcases get banned.
    station_ip: str
    # Given to every account a testcase creates. Must satisfy the switch's own
    # password policy, which TC-IA-121/122/123 are busy testing.
    test_password: str = "12#qweASD"
    baseline: LabBaseline = Field(default_factory=LabBaseline)
    # Interface name or index that `tshark -D` reports, for the one testcase
    # that captures the switch's TLS ServerHello (TC-DP-713). Machine-specific,
    # so it lives here rather than in the testcase; without it that testcase
    # errors rather than passing vacuously.
    capture_interface: Optional[str] = None
    # Where the API/WebView companion repo lives, for the integrated run.
    # Relative paths resolve against the lab file's own directory.
    api_poc_path: Optional[str] = None

    def account(self, role: str) -> LabAccount:
        try:
            return self.accounts[role]
        except KeyError:
            raise KeyError(
                f"lab config has no '{role}' account (has: {', '.join(sorted(self.accounts))})"
            ) from None

    def devices(self) -> dict[str, DeviceDefinition]:
        """One switchtest device per account that declares a transport. The
        role name is the device name, so `--device secureadmin` and the lab
        file's `accounts.secureadmin` are visibly the same thing."""
        devices: dict[str, DeviceDefinition] = {}
        for role, account in self.accounts.items():
            if account.transport is None:
                continue
            serial = account.transport == TransportType.SERIAL
            devices[role] = DeviceDefinition(
                name=role,
                host=self.switch.host,
                port=self.switch.ssh_port,
                username=account.username,
                password=account.password,
                password_env=account.password_env,
                enable_password=account.enable_password,
                enable_password_env=account.enable_password_env,
                platform="aos",
                transport=account.transport,
                serial_port=self.console.port if serial else None,
                serial_baudrate=self.console.baudrate,
                expected_prompt=self.switch.expected_prompt,
                expected_firmware=self.switch.expected_firmware,
                tags=[role],
                connection_timeout=self.switch.connection_timeout,
                command_timeout=self.switch.command_timeout,
                strict_host_key=self.switch.strict_host_key,
            )
        return devices

    def variables(self) -> dict[str, str]:
        """Values testcases substitute with `$name`. Passwords are deliberately
        not among them: `$test_password` is the one credential a testcase may
        need, and it belongs to accounts the run creates and destroys."""
        variables = {
            "host": self.switch.host,
            "system_name": self.switch.system_name,
            "station_ip": self.station_ip,
            "test_password": self.test_password,
        }
        if self.switch.expected_firmware:
            # Left unsubstituted when unset: an empty `pattern: "$expected_firmware"`
            # matches anything, i.e. a firmware check that silently passes.
            variables["expected_firmware"] = self.switch.expected_firmware
        for role, account in self.accounts.items():
            variables[f"{role}_user"] = account.username
        for name, value in self.baseline.model_dump().items():
            variables[f"baseline_{name}"] = str(value)
        return variables
