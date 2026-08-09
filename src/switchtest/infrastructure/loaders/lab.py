from pathlib import Path

from switchtest.domain.device import DeviceDefinition
from switchtest.domain.lab import LabConfig
from switchtest.exceptions import LoaderError
from switchtest.infrastructure.loaders.common import load_yaml_file


def load_lab(path: Path) -> LabConfig:
    if not path.exists():
        raise LoaderError(
            f"Lab config not found: {path}. Copy configs/lab.example.yaml to {path} "
            f"and fill in the switch address and account passwords."
        )
    payload = load_yaml_file(path)
    try:
        return LabConfig.model_validate(payload)
    except Exception as exc:
        raise LoaderError(f"Invalid lab config {path}: {exc}") from exc


def load_device_by_name(path: Path, device_name: str) -> DeviceDefinition:
    devices = load_lab(path).devices()
    try:
        return devices[device_name]
    except KeyError:
        raise LoaderError(
            f"Unknown device '{device_name}' in {path}. Devices come from the accounts "
            f"that declare a transport: {', '.join(sorted(devices)) or '(none)'}"
        ) from None
