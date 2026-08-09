"""Run every security-functional check across both repos from one command.

Three things make this more than a shell script that calls two tools in a row.

*Accounts.* Two of the checks need low-privilege accounts to log in as, and an
account cannot create itself. They are provisioned here before the phases that
need them and removed afterwards, so the switch does not have to carry test
accounts between runs.

*Order.* Several checks deliberately break the switch: one turns off every
network service, one bans this machine's IP. Anything reachable only over the
network has to have finished before those run, or it fails for reasons that
have nothing to do with what it was testing. The password-change check runs the
same policy over all four transports one at a time (console, SSH, API, browser)
because they all change the same account's password and would collide if
overlapped.

*The console.* One serial cable, and both repos want it. Steps that use it are
never concurrent, which is also why nothing here runs in parallel.

    python scripts/run_secfunc.py --lab configs/lab.yaml
    python scripts/run_secfunc.py --phase password-change   # just one phase
    python scripts/run_secfunc.py --skip-console            # no cable attached
    python scripts/run_secfunc.py --list                    # what would run
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from switchtest.domain.lab import LabConfig  # noqa: E402
from switchtest.exceptions import LoaderError  # noqa: E402
from switchtest.infrastructure.loaders.lab import load_lab  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent

# A step that could not run at all, as distinct from one that ran and passed.
# Reporting "did not run" as PASS is how a green summary starts meaning nothing.
SKIPPED = -1


@dataclass
class Step:
    """One unit of work: either a switchtest suite on a device, or a pytest run
    in the API/WebView repo. `label` is the transport name shown in progress."""

    label: str
    device: str | None = None
    suite: str | None = None
    pytest_files: list[str] = field(default_factory=list)
    needs_console: bool = False
    needs_api_repo: bool = False

    @property
    def is_switch(self) -> bool:
        return self.suite is not None


@dataclass
class Phase:
    name: str
    title: str
    steps: list[Step]
    note: str = ""


# Ordered by how much damage a phase does, least first. Everything that talks to
# the switch over the network finishes before `switch-console` starts turning
# services off and banning this host.
PHASES: list[Phase] = [
    Phase(
        "password-change",
        "Password change policy (console -> SSH -> API -> WebView)",
        steps=[
            Step("console", device="secureadmin", suite="suites/password_change_policy.yaml", needs_console=True),
            Step("ssh", device="admin", suite="suites/password_change_policy.yaml"),
            Step("api", pytest_files=["tests/test_password_policy.py"], needs_api_repo=True),
            Step("webview", pytest_files=["tests/test_password_policy_webview.py"], needs_api_repo=True),
        ],
        note="same policy refused over all four transports; all-invalid, so no password actually changes",
    ),
    Phase(
        "switch-ssh",
        "Switch checks over SSH (admin)",
        steps=[Step("ssh", device="admin", suite="suites/secfunc_all_ssh.yaml")],
        note="25 testcases: password/lockout config, boot/self-test, audit, crypto, ACL/VLAN",
    ),
    Phase(
        "switch-lowpriv",
        "Audit access restriction (low-privilege account)",
        steps=[Step("ssh", device="lowpriv", suite="suites/secfunc_lowpriv.yaml")],
        note="proves a restricted account is refused the audit log",
    ),
    Phase(
        "api-network",
        "API and WebView checks (network only)",
        steps=[
            Step(
                "api+web",
                pytest_files=[
                    "tests/test_lockout_enforcement_api.py",
                    "tests/test_lockout_enforcement_webview.py",
                    "tests/test_webview_menu_visibility.py",
                ],
                needs_api_repo=True,
            )
        ],
        note="needs WebView up, so it runs before anything that switches services off",
    ),
    Phase(
        "api-console",
        "IP ban over API and WebView",
        steps=[
            Step(
                "api+web",
                pytest_files=[
                    "tests/test_ip_ban_enforcement_api.py",
                    "tests/test_ip_ban_enforcement_webview.py",
                ],
                needs_api_repo=True,
                needs_console=True,
            )
        ],
        note="bans this machine's IP, then releases it over the serial console",
    ),
    Phase(
        "switch-console",
        "Switch checks over the serial console (secureadmin)",
        steps=[Step("console", device="secureadmin", suite="suites/secfunc_console.yaml", needs_console=True)],
        note="password history, SNMPv3, lockout, service disable, IP ban -- each cuts this host off the network",
    ),
]


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--lab", type=Path, default=Path("configs/lab.yaml"))
    parser.add_argument("--report-dir", type=Path, default=Path("reports"))
    parser.add_argument(
        "--phase",
        action="append",
        default=[],
        choices=[phase.name for phase in PHASES],
        help="run only these phases (repeatable); default is all of them, in order",
    )
    parser.add_argument("--skip-console", action="store_true", help="skip steps needing the serial cable")
    parser.add_argument("--list", action="store_true", help="print the plan and exit")
    parser.add_argument(
        "--keep-accounts",
        action="store_true",
        help="leave provisioned accounts on the switch (for debugging a failed run)",
    )
    return parser.parse_args()


def selected_phases(arguments: argparse.Namespace) -> list[Phase]:
    """Phases (and steps) that survive the --phase and --skip-console filters.
    A step needing the cable is dropped by --skip-console; a phase with no
    steps left is dropped entirely."""
    phases: list[Phase] = []
    for phase in PHASES:
        if arguments.phase and phase.name not in arguments.phase:
            continue
        steps = [s for s in phase.steps if not (arguments.skip_console and s.needs_console)]
        if steps:
            phases.append(Phase(phase.name, phase.title, steps, phase.note))
    return phases


def api_repo_path(lab: LabConfig, lab_file: Path) -> Path | None:
    if not lab.api_poc_path:
        return None
    path = Path(lab.api_poc_path)
    return path if path.is_absolute() else (lab_file.resolve().parent / path).resolve()


def api_python(repo: Path) -> Path | None:
    """The API repo has its own virtualenv -- httpx, playwright and paramiko
    are not in this one, so its tests cannot run under our interpreter."""
    for candidate in (repo / "venv" / "Scripts" / "python.exe", repo / "venv" / "bin" / "python"):
        if candidate.exists():
            return candidate
    return None


def api_environment(lab: LabConfig) -> dict[str, str]:
    """The lab config, handed to the API repo as the environment variables it
    already reads. One file to edit; no `set` before every run."""
    secureadmin = lab.account("secureadmin")
    readonly = lab.accounts.get("readonly")
    admin = lab.account("admin")
    environment = dict(os.environ)
    environment.update(
        {
            "SWITCH_HOST": lab.switch.host,
            # The API tests observe and clean up as secureadmin, never as the
            # account whose logins they are deliberately failing.
            "SWITCH_API_USERNAME": secureadmin.username,
            "SWITCH_API_PASSWORD": secureadmin.password or "",
            "SWITCH_SSH_PASSWORD": secureadmin.password or "",
            "SWITCH_CONSOLE_PASSWORD": secureadmin.password or "",
            "SWITCH_CONSOLE_PORT": lab.console.port,
            "SWITCH_CONSOLE_BAUDRATE": str(lab.console.baudrate),
            "SWITCH_LOCKOUT_USERNAME": admin.username,
            "SWITCH_IP_LOCKOUT_THRESHOLD": str(lab.baseline.ip_lockout_threshold),
        }
    )
    if readonly:
        environment["SWITCH_LOWPRIV_USERNAME"] = readonly.username
        environment["SWITCH_LOWPRIV_PASSWORD"] = readonly.password or ""
    return environment


def switch_environment(lab: LabConfig) -> dict[str, str]:
    """The machine-specific bits switchtest reads from the environment, sourced
    from the lab config so there is still only one file to edit."""
    environment = dict(os.environ)
    if lab.capture_interface:
        environment["SWITCHTEST_CAPTURE_INTERFACE"] = lab.capture_interface
    return environment


def provisioned_accounts(lab: LabConfig) -> list[tuple[str, str, str]]:
    """(username, password, privileges) for accounts the run creates itself."""
    return [
        (account.username, account.password or "", account.provision.privileges)
        for account in lab.accounts.values()
        if account.provision
    ]


def manage_accounts(lab: LabConfig, create: bool) -> None:
    """Create or delete the provisioned accounts over SSH as the admin account.

    SSH rather than the console on purpose: this runs before and after every
    phase, and requiring the serial cable to provision would mean --skip-console
    could not skip anything.
    """
    accounts = provisioned_accounts(lab)
    if not accounts:
        return
    from switchtest.drivers.aos import AOSSwitchDriver

    driver = AOSSwitchDriver(lab.devices()["admin"])
    driver.connect()
    try:
        for username, password, privileges in accounts:
            if create:
                # Delete first: creating an account that exists is an error, and
                # a previous run that died before its teardown leaves one behind.
                driver.apply_config([f"no user {username}"], ignore_errors=True)
                driver.apply_config([f"user {username} password {password} {privileges}"])
                print(f"  + {username} ({privileges})")
            else:
                driver.apply_config([f"no user {username}"], ignore_errors=True)
                print(f"  - {username}")
    finally:
        driver.disconnect()


def run_switch_step(step: Step, lab: LabConfig, arguments: argparse.Namespace, report: Path) -> int:
    command = [
        sys.executable, "-m", "switchtest.cli", "run",
        "--device", step.device or "",
        "--suite", str(REPO_ROOT / (step.suite or "")),
        "--lab", str(arguments.lab),
        "--report-dir", str(arguments.report_dir),
        "--json", str(report),
    ]
    return subprocess.run(command, cwd=REPO_ROOT, env=switch_environment(lab), check=False).returncode


def run_api_step(step: Step, lab: LabConfig, repo: Path, report: Path) -> int:
    python = api_python(repo)
    if python is None:
        print(
            f"  no virtualenv in {repo}\n"
            f"  (python -m venv venv && venv\\Scripts\\python -m pip install -e .[dev,web,ssh,serial])"
        )
        return SKIPPED
    command = [
        str(python), "-m", "pytest", *step.pytest_files, "-v",
        f"--junit-xml={(REPO_ROOT / report).resolve()}",
    ]
    return subprocess.run(command, cwd=repo, env=api_environment(lab), check=False).returncode


def report_path(arguments: argparse.Namespace, phase: Phase, step: Step) -> Path:
    suffix = "json" if step.is_switch else "xml"
    stem = phase.name if len(phase.steps) == 1 else f"{phase.name}.{step.label}"
    return arguments.report_dir / f"{stem}.{suffix}"


def describe_switch_report(report: Path) -> list[str]:
    try:
        payload = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [
        f"{test['status'].upper():<7} {test['test_id']:<11} {test['test_name']}"
        for test in payload.get("tests", [])
        if test.get("status") != "pass"
    ]


# -- progress visualization ------------------------------------------------


def target_of(step: Step, lab: LabConfig) -> str:
    """What the banner says this step is talking to, so a run is readable while
    it happens rather than only in the summary."""
    if step.is_switch:
        account = lab.accounts.get(step.device or "")
        return f"{step.device} ({account.username})" if account else str(step.device)
    browser = any("webview" in name for name in step.pytest_files)
    api = any("webview" not in name for name in step.pytest_files)
    parts = [name for name, used in (("HTTPS API", api), ("Chromium", browser)) if used]
    return f"{' + '.join(parts)} @ {lab.switch.host}"


def print_plan(phases: list[Phase]) -> None:
    total = sum(len(phase.steps) for phase in phases)
    print(f"\n{total} steps across {len(phases)} phases:\n")
    index = 0
    for phase in phases:
        print(f"  {phase.name}")
        print(f"    {phase.note}")
        for step in phase.steps:
            index += 1
            marks = " ".join(
                filter(None, ["console" if step.needs_console else "", "api-repo" if step.needs_api_repo else ""])
            )
            what = step.suite.split("/")[-1] if step.is_switch else " ".join(f.split("/")[-1] for f in step.pytest_files)
            print(f"      [{index:>2}] {step.label:<8} {what}  {f'({marks})' if marks else ''}")


def bar(done: int, total: int, width: int = 28) -> str:
    filled = round(width * done / total) if total else 0
    return "#" * filled + "-" * (width - filled)


def print_step_banner(overall: tuple[int, int], phase: Phase, step: Step, lab: LabConfig) -> None:
    done, total = overall
    print(f"\n{'=' * 78}")
    print(f"  [{done + 1:>2}/{total}] {bar(done, total)}")
    print(f"  {phase.title}")
    print(f"  transport: {step.label:<8} -> {target_of(step, lab)}")
    print(f"{'=' * 78}")


def verdict_of(code: int) -> str:
    if code == SKIPPED:
        return "SKIPPED"
    return "PASS" if code == 0 else f"FAIL ({code})"


def print_step_result(step: Step, code: int, seconds: float) -> None:
    print(f"-> {step.label}: {verdict_of(code)} ({seconds:.1f}s)")


def summarize(results: list[tuple[Phase, Step, int, Path]]) -> None:
    passed = sum(1 for _, _, code, _ in results if code == 0)
    skipped = sum(1 for _, _, code, _ in results if code == SKIPPED)
    failed = [f"{phase.name}/{step.label}" for phase, step, code, _ in results if code > 0]
    total = len(results)
    tally = f"{passed}/{total} steps passed"
    if skipped:
        tally += f", {skipped} skipped"
    print(f"\n{'=' * 78}\nSUMMARY   {tally}   [{bar(passed, total)}]\n{'=' * 78}")
    current = None
    for phase, step, code, report in results:
        if phase.name != current:
            print(f"\n  {phase.title}")
            current = phase.name
        print(f"    [{verdict_of(code):<10}] {step.label}")
        if step.is_switch:
            for line in describe_switch_report(report):
                print(f"          {line}")
    print()
    if failed:
        print(f"FAILED: {', '.join(failed)}")
    elif skipped:
        print(f"No failures, but {skipped} step(s) never ran -- this is not a clean run.")
    else:
        print("All steps passed.")


def main() -> int:
    arguments = parse_arguments()
    phases = selected_phases(arguments)

    if arguments.list:
        print_plan(phases)
        return 0

    try:
        lab = load_lab(arguments.lab)
    except LoaderError as exc:
        # A missing or malformed lab file is the most common first-run problem;
        # a traceback buries the one line that says how to fix it.
        print(exc, file=sys.stderr)
        return 2
    arguments.report_dir.mkdir(parents=True, exist_ok=True)
    repo = api_repo_path(lab, arguments.lab)

    if any(step.needs_api_repo for phase in phases for step in phase.steps) and repo is None:
        print("Set api_poc_path in the lab config to include the API/WebView steps.", file=sys.stderr)
        return 2

    total_steps = sum(len(phase.steps) for phase in phases)
    print(f"Switch {lab.switch.host}  |  console {lab.console.port}@{lab.console.baudrate}")
    print(f"{total_steps} steps: {', '.join(phase.name for phase in phases)}\n")

    print("Provisioning accounts")
    manage_accounts(lab, create=True)

    results: list[tuple[Phase, Step, int, Path]] = []
    try:
        done = 0
        for phase in phases:
            for step in phase.steps:
                print_step_banner((done, total_steps), phase, step, lab)
                report = report_path(arguments, phase, step)
                started = time.monotonic()
                if step.is_switch:
                    code = run_switch_step(step, lab, arguments, report)
                else:
                    assert repo is not None
                    code = run_api_step(step, lab, repo, report)
                print_step_result(step, code, time.monotonic() - started)
                results.append((phase, step, code, report))
                done += 1
    finally:
        # Always, including after a crash: a leftover test account is a real
        # account on a real switch.
        if not arguments.keep_accounts:
            print("\nRemoving provisioned accounts")
            try:
                manage_accounts(lab, create=False)
            except Exception as exc:  # noqa: BLE001 - never mask the run's own failure
                print(f"  could not remove accounts ({exc}); remove them by hand", file=sys.stderr)

    summarize(results)
    # A skipped step is not a pass: exit non-zero so CI does not read a run that
    # never happened as a green one.
    return 0 if all(code == 0 for _, _, code, _ in results) else 1


if __name__ == "__main__":
    sys.exit(main())
