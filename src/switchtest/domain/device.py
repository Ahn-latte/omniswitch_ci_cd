from typing import Optional

from pydantic import BaseModel, Field


class DeviceDefinition(BaseModel):
    name: str
    host: str
    port: int = 22
    username: str
    password_env: str
    enable_password_env: Optional[str] = None
    platform: str
    baseline_strategy: str = "load_config"
    baseline_source: Optional[str] = None
    expected_prompt: Optional[str] = None
    expected_firmware: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    connection_timeout: int = 15
    command_timeout: int = 30
    strict_host_key: bool = False


class DeviceInventory(BaseModel):
    devices: list[DeviceDefinition] = Field(default_factory=list)
