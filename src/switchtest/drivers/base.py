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
    def apply_config(
        self, commands: list[str], timeout: int = 30, ignore_errors: bool = False
    ) -> list[str]:
        """Send configuration commands. Raises unless `ignore_errors`, which is
        for commands whose failure is acceptable (clearing leftovers that may
        or may not exist)."""
        ...

    @abstractmethod
    def restore_baseline(self, source: str | None = None) -> None: ...

    @abstractmethod
    def get_metadata(self) -> dict[str, str | None]: ...

    @abstractmethod
    def set_super_user_password(self, password: str, entries: int = 2, timeout: int = 30) -> str:
        """Drive the interactive `super-user-password set` dialogue, which is
        what gives `su` a password to ask for in the first place. Raises
        CommandExecutionError if the device rejects the new password."""
        ...

    @abstractmethod
    def reset_super_user_password(self, old_password: str, timeout: int = 30) -> str:
        """Remove the super-user password altogether (`super-user-password
        reset`), which asks for the current one first. Raises
        CommandExecutionError if the device refuses -- including when there is
        no password set to remove."""
        ...

    @abstractmethod
    def run_in_su_shell(
        self,
        commands: list[str],
        su_password: str | None = None,
        shell_prompt: str = "#->",
        timeout: int = 30,
    ) -> str:
        """Run commands in the device's `su` shell and return their combined
        output, always leaving the shell again afterwards.

        A separate method rather than `run_show` because the shell's prompt is
        not the CLI's, so each step has to be driven as an interaction against
        the shell prompt instead of the usual send-and-wait-for-`->`."""
        ...

    @abstractmethod
    def attempt_login(self, username: str, password: str, timeout: int = 15) -> bool:
        """Open a fresh, separate session with the given credentials (not the
        driver's own session) and immediately close it. Returns True if
        authentication succeeded, False if it was rejected. Used to trigger
        failed-login attempts against an account other than the one the
        driver is already authenticated as, e.g. for lockout-enforcement
        testcases."""
        ...
