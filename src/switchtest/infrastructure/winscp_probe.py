"""Attempt an SFTP file download with WinSCP's own scripting console.

Uses WinSCP's console mode (winscp.com /script=...) rather than driving its
GUI: WinSCP ships this specifically so automation does not have to click
through dialogs, and it reports success/failure as a real process exit code
instead of a UI state that would have to be screen-scraped.
"""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from switchtest.exceptions import ValidationExecutionError

WINSCP_EXECUTABLE = "winscp.com"

# The installer doesn't add itself to PATH, so `shutil.which` alone misses a
# perfectly normal install. Checked in order, first match wins.
_DEFAULT_INSTALL_DIRS = (
    r"%ProgramFiles%\WinSCP",
    r"%ProgramFiles(x86)%\WinSCP",
    r"%LOCALAPPDATA%\Programs\WinSCP",
)


def _find_winscp() -> str | None:
    on_path = shutil.which(WINSCP_EXECUTABLE)
    if on_path:
        return on_path
    for template in _DEFAULT_INSTALL_DIRS:
        candidate = Path(os.path.expandvars(template)) / WINSCP_EXECUTABLE
        if candidate.is_file():
            return str(candidate)
    return None


def check_sftp_download_blocked(
    host: str,
    port: int,
    username: str,
    password: str,
    remote_path: str,
    timeout: int = 30,
) -> tuple[bool, str]:
    """Try to GET `remote_path` over SFTP as `username`, and report whether
    the switch actually refused it.

    Looks for winscp.com on PATH first, then WinSCP's own default install
    directories (Program Files, Program Files (x86), the per-user
    LOCALAPPDATA install) -- the installer does not add itself to PATH, so a
    perfectly normal install is otherwise invisible to `shutil.which`.

    Credentials go into a throwaway script file (deleted afterward with the
    rest of its temp directory), not the command line -- winscp.com's argv
    would otherwise put the password in every process listing on this
    machine for the run's duration. `-hostkey="*"` accepts whatever host key
    the switch presents without pinning it first, matching this project's
    non-strict default elsewhere (`strict_host_key`).

    Returns (blocked, detail). True means the download did not go through --
    a non-zero exit and no file landed locally, which is what "even this
    authenticated account cannot pull this file" looks like. False means the
    file was actually retrieved (or the result was too ambiguous to call
    blocked, which must not be mistaken for the switch actually refusing).
    """
    if not host:
        raise ValidationExecutionError("SFTP download-blocked validation requires a target")
    if not username:
        raise ValidationExecutionError("SFTP download-blocked validation requires a username")
    if not remote_path:
        raise ValidationExecutionError("SFTP download-blocked validation requires a remote path")
    executable = _find_winscp()
    if executable is None:
        raise ValidationExecutionError(
            f"{WINSCP_EXECUTABLE} not found on PATH or in its default install directories "
            f"-- install WinSCP (https://winscp.net)"
        )

    with tempfile.TemporaryDirectory(prefix="switchtest-winscp-") as tmp:
        tmp_dir = Path(tmp)
        local_target = tmp_dir / Path(remote_path).name
        script_path = tmp_dir / "session.txt"
        log_path = tmp_dir / "winscp.log"
        # -username/-password rather than embedding them in the sftp:// URL:
        # a password containing characters like '#' or '@' would otherwise
        # need URL-escaping to not be misparsed as part of the URL itself.
        script_path.write_text(
            "option batch abort\n"
            "option confirm off\n"
            f'open sftp://{host}:{port} -hostkey="*" -username="{username}" '
            f'-password="{password}" -timeout={timeout}\n'
            f'get "{remote_path}" "{local_target}"\n'
            "exit\n",
            encoding="utf-8",
        )
        try:
            result = subprocess.run(
                [executable, f"/script={script_path}", f"/log={log_path}", "/ini=nul"],
                capture_output=True,
                text=True,
                timeout=timeout + 15,
            )
        except subprocess.TimeoutExpired as exc:
            raise ValidationExecutionError(
                f"{WINSCP_EXECUTABLE} did not finish within {timeout + 15}s: {exc}"
            ) from exc

        downloaded = local_target.exists() and local_target.stat().st_size > 0
        output = f"{result.stdout or ''}{result.stderr or ''}"
        detail_tail = _last_meaningful_line(output)

        if downloaded:
            return False, (
                f"downloaded {local_target.stat().st_size} bytes of '{remote_path}' as "
                f"'{username}' -- the file was retrievable"
            )
        if result.returncode != 0:
            return True, (
                f"{WINSCP_EXECUTABLE} exited {result.returncode}, no file retrieved: {detail_tail}"
            )
        # Exit code 0 but nothing landed locally -- inconclusive, not a
        # confirmed refusal, so this must not read as the check having passed.
        return False, f"{WINSCP_EXECUTABLE} exited 0 but wrote no file -- inconclusive: {detail_tail}"


def _last_meaningful_line(text: str) -> str:
    for line in reversed(text.splitlines()):
        if line.strip():
            return line.strip()
    return ""
