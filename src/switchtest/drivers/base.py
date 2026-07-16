from abc import ABC, abstractmethod


class BaseSwitchDriver(ABC):
    @abstractmethod
    def connect(self) -> None: ...

    @abstractmethod
    def disconnect(self) -> None: ...

    @abstractmethod
    def enter_enable_mode(self) -> None: ...

    @abstractmethod
    def enter_config_mode(self) -> None: ...

    @abstractmethod
    def exit_config_mode(self) -> None: ...

    @abstractmethod
    def run_show(self, command: str, timeout: int = 30, reauth: bool = False) -> str: ...

    @abstractmethod
    def apply_config(self, commands: list[str], timeout: int = 30) -> list[str]: ...

    @abstractmethod
    def restore_baseline(self, source: str | None = None) -> None: ...

    @abstractmethod
    def get_metadata(self) -> dict[str, str | None]: ...
