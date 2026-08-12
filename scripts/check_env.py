"""Check that this machine can actually run the suites, and say what to fix.

    venv\\Scripts\\python.exe scripts\\check_env.py

Most of what this looks at is machine-specific and lives outside the repo, so
it cannot be pinned by a requirements file: which COM port the console cable
landed on, whether nmap and tshark are on PATH, whether the shell is elevated,
which tshark interface number faces the switch. Every one of those has a
failure mode that looks like a switch problem rather than a setup problem --
a port scan that cannot determine state, a TLS capture that never sees a
handshake, a console that times out -- so they are worth checking up front
rather than discovering three phases into a run.

Exit code is 0 when nothing is missing that would stop a full run, 1
otherwise. WARN items do not fail: they disable a specific testcase without
invalidating the rest.
"""

from __future__ import annotations

import ctypes
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"

# Where the Windows installers put these by default, so the fix hint can name a
# real path rather than telling the reader to go find it.
DEFAULT_TOOL_PATHS = {
    "nmap": r"C:\Program Files (x86)\Nmap",
    "tshark": r"C:\Program Files\Wireshark",
}


class Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str, str]] = []

    def add(self, status: str, name: str, detail: str, fix: str = "") -> None:
        self.rows.append((status, name, detail, fix))

    def print(self) -> None:
        width = max(len(name) for _s, name, _d, _f in self.rows)
        for status, name, detail, fix in self.rows:
            print(f"  [{status}] {name:<{width}}  {detail}")
            if fix and status != PASS:
                for line in fix.split("\n"):
                    print(f"         -> {line}")

    @property
    def failed(self) -> bool:
        return any(status == FAIL for status, *_rest in self.rows)


def check_python(report: Report) -> None:
    version = ".".join(str(part) for part in sys.version_info[:3])
    in_venv = sys.prefix != sys.base_prefix
    report.add(
        PASS if in_venv else WARN,
        "python",
        f"{version} ({'venv' if in_venv else 'NOT a venv'})",
        "Run this with venv\\Scripts\\python.exe so it checks the same "
        "interpreter the suites use.",
    )


def check_switchtest(report: Report) -> None:
    try:
        import switchtest  # noqa: F401

        report.add(PASS, "switchtest", "importable")
    except Exception as exc:  # noqa: BLE001
        report.add(
            FAIL,
            "switchtest",
            f"not importable ({exc})",
            "venv\\Scripts\\python.exe -m pip install -e .[dev,web]",
        )


def check_tool(report: Report, tool: str, status_when_missing: str, why: str) -> str | None:
    found = shutil.which(tool)
    if found:
        report.add(PASS, tool, found)
        return found
    default = DEFAULT_TOOL_PATHS.get(tool)
    hint = f"{why}\nInstall it, then add its folder to PATH"
    if default and Path(default).exists():
        hint = (
            f"{why}\nInstalled at {default} but NOT on PATH. In an admin cmd:\n"
            f'setx /M PATH "%PATH%;{default}"   (then open a new cmd)'
        )
    elif default:
        hint = f"{why}\nInstall it (default location {default}), then add that folder to PATH"
    report.add(status_when_missing, tool, "not on PATH", hint)
    return None


def check_elevation(report: Report) -> None:
    if platform.system().lower() != "windows":
        report.add(PASS, "privileges", f"{os.getuid() == 0 and 'root' or 'not root'}")
        return
    try:
        elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        elevated = False
    report.add(
        PASS if elevated else WARN,
        "elevated shell",
        "yes" if elevated else "no",
        "nmap's -sS/-sU need raw sockets. Without an elevated cmd, TC-SM-41B "
        "and the commissioning port scan error out instead of passing.",
    )


def check_playwright(report: Report) -> None:
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # noqa: BLE001
        report.add(
            FAIL,
            "playwright",
            f"not installed ({exc})",
            "venv\\Scripts\\python.exe -m pip install -e .[web]",
        )
        return
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            browser.close()
        report.add(PASS, "chromium", "launches")
    except Exception as exc:  # noqa: BLE001
        report.add(
            FAIL,
            "chromium",
            f"cannot launch ({str(exc).splitlines()[0]})",
            "venv\\Scripts\\python.exe -m playwright install chromium",
        )


def check_serial_ports(report: Report, configured: str | None) -> None:
    try:
        from serial.tools import list_ports
    except Exception as exc:  # noqa: BLE001
        report.add(FAIL, "pyserial", f"not installed ({exc})", "pip install -e .[dev,web]")
        return
    available = [port.device for port in list_ports.comports()]
    listing = ", ".join(available) if available else "none detected"
    if configured is None:
        report.add(WARN, "serial ports", listing, "No lab file to compare against.")
        return
    if configured in available:
        report.add(PASS, "console port", f"{configured} present (available: {listing})")
    else:
        report.add(
            FAIL,
            "console port",
            f"{configured} NOT present (available: {listing})",
            "Plug in the console cable, or set console.port in lab.yaml to one "
            "of the ports above. Every console phase needs it.",
        )


def check_lab(report: Report, lab_path: Path):
    from switchtest.exceptions import LoaderError
    from switchtest.infrastructure.loaders.lab import load_lab

    if not lab_path.exists():
        report.add(
            FAIL,
            "lab.yaml",
            f"missing ({lab_path})",
            "copy configs\\lab.example.yaml configs\\lab.yaml   (then fill it in)",
        )
        return None
    try:
        lab = load_lab(lab_path)
    except LoaderError as exc:
        report.add(FAIL, "lab.yaml", f"invalid ({exc})")
        return None
    report.add(PASS, "lab.yaml", f"{lab_path} -> switch {lab.switch.host}")

    placeholders = [
        role
        for role, account in lab.accounts.items()
        if account.password and "CHANGE-ME" in account.password
    ]
    if placeholders:
        report.add(
            FAIL,
            "account passwords",
            f"still CHANGE-ME: {', '.join(sorted(placeholders))}",
            "Fill in the real passwords in lab.yaml.",
        )
    else:
        report.add(PASS, "account passwords", "filled in")

    if lab.capture_interface:
        report.add(PASS, "capture_interface", lab.capture_interface)
    else:
        report.add(
            WARN,
            "capture_interface",
            "unset",
            "TC-DP-713 (WebView TLS capture) errors without it -- by design, so "
            "it cannot pass vacuously.\nRun `tshark -D`, then set "
            "capture_interface in lab.yaml to the number facing the switch.",
        )
    return lab


def check_api_repo(report: Report, lab) -> None:
    if lab is None:
        return
    if not lab.api_poc_path:
        report.add(
            FAIL,
            "api_poc_path",
            "unset",
            "Set api_poc_path in lab.yaml; the API/WebView phases have nothing "
            "to run without it.",
        )
        return
    repo = (Path(lab.api_poc_path) if Path(lab.api_poc_path).is_absolute() else (REPO_ROOT / "configs" / lab.api_poc_path)).resolve()
    if not repo.exists():
        report.add(FAIL, "api repo", f"not found at {repo}", "Check api_poc_path in lab.yaml.")
        return
    python = repo / "venv" / "Scripts" / "python.exe"
    if not python.exists():
        python = repo / "venv" / "bin" / "python"
    if not python.exists():
        report.add(
            FAIL,
            "api repo venv",
            f"no virtualenv in {repo}",
            "cd " + str(repo) + "\npython -m venv venv\n"
            "venv\\Scripts\\python.exe -m pip install -e .[dev,web,ssh,serial]\n"
            "venv\\Scripts\\python.exe -m playwright install chromium",
        )
        return
    probe = subprocess.run(
        [str(python), "-c", "import aos_api_poc, httpx, playwright, paramiko, serial"],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode == 0:
        report.add(PASS, "api repo venv", str(python))
    else:
        report.add(
            FAIL,
            "api repo venv",
            f"missing dependencies ({probe.stderr.strip().splitlines()[-1] if probe.stderr.strip() else 'unknown'})",
            f'"{python}" -m pip install -e .[dev,web,ssh,serial]',
        )


def main() -> int:
    lab_path = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO_ROOT / "configs" / "lab.yaml"
    report = Report()

    check_python(report)
    check_switchtest(report)
    lab = check_lab(report, lab_path)
    check_serial_ports(report, lab.console.port if lab else None)
    check_tool(
        report,
        "nmap",
        FAIL,
        "Needed by TC-SM-41B's port scan and by commissioning.",
    )
    check_tool(
        report,
        "tshark",
        WARN,
        "Needed only by TC-DP-713 (WebView TLS capture).",
    )
    check_elevation(report)
    check_playwright(report)
    check_api_repo(report, lab)

    print(f"Environment check ({platform.system()}, lab file {lab_path})\n")
    report.print()
    print()
    if report.failed:
        print("FAIL: fix the items above before running the suites.")
        return 1
    print("Ready. WARN items only disable the testcase named next to them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
