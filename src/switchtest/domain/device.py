from typing import Optional

from pydantic import BaseModel, Field, model_validator

from switchtest.domain.enums import TransportType


class DeviceDefinition(BaseModel):
    name: str
    host: str
    port: int = 22
    username: str
    # A password comes either straight from the (gitignored) lab config or from
    # the environment. Both are offered because the two have different
    # failure modes: a file is one place to edit and easy to get wrong once,
    # an env var is easy to forget and easy to keep out of a file entirely.
    password: Optional[str] = None
    password_env: Optional[str] = None
    enable_password: Optional[str] = None
    enable_password_env: Optional[str] = None
    platform: str
    # How the driver holds its own session. `host`/`port` stay meaningful for
    # serial devices: they are still the device's SSH service, used by network
    # probes (`$host`, tcp_blocked) and by trigger_failed_logins, which must
    # originate from this machine over the network no matter how the driver's
    # own session is attached.
    transport: TransportType = TransportType.SSH
    serial_port: Optional[str] = None
    serial_baudrate: int = 9600
    baseline_strategy: str = "load_config"
    baseline_source: Optional[str] = None
    expected_prompt: Optional[str] = None
    expected_firmware: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    connection_timeout: int = 15
    command_timeout: int = 30
    strict_host_key: bool = False

    @model_validator(mode="after")
    def _check_transport_fields(self) -> "DeviceDefinition":
        if self.transport == TransportType.SERIAL and not self.serial_port:
            raise ValueError(
                f"device '{self.name}' uses transport 'serial' and must set 'serial_port' "
                "(e.g. COM3 on Windows, /dev/ttyUSB0 on Linux)"
            )
        if not self.password and not self.password_env:
            raise ValueError(
                f"device '{self.name}' needs a password: set it in the lab config, or name "
                "the environment variable holding it with 'password_env'"
            )
        return self


class DeviceInventory(BaseModel):
    devices: list[DeviceDefinition] = Field(default_factory=list)
