"""Bring a factory-reset OmniSwitch up to the state the test suites assume,
over the serial console alone, verifying what can only be verified here.

Run this once, immediately after a factory reset:

    venv\\Scripts\\python.exe scripts\\commission.py

Why a separate script rather than a suite: this is not idempotent and cannot
be. The factory password works exactly once -- the switch forces a
policy-compliant change before it grants any session -- so a second run finds
a switch that no longer matches its own starting assumptions. Everything in
`suites/` is written to be re-runnable; this deliberately is not.

Why console-only: at factory reset the switch has no IP address and every IP
service is disabled, so there is no network path to it at all. The console is
the only way in, and it stays the only way in until this script gives the
switch an address.

Three things are verified rather than merely configured, because this is the
only moment they are observable:

1. The password policy is enforced *during the forced first change*. A switch
   that accepts a weak password here is one whose policy does not cover the
   path an installer actually walks on day one. Every rejected candidate is
   recorded with the switch's own reason.
2. The station is reachable from the switch once addressing is up (ping).
3. Nothing is listening before services are switched on. This runs after
   addressing but *before* `aaa authentication default local`, because that
   command turns SNMP on -- scanning afterwards would find UDP/161 open and
   report a false finding.

Then it creates the fixed accounts the suites log in as (the `provision:`
ones are created and destroyed per-run by run_secfunc.py, so they are not
made here) and saves the configuration.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from switchtest.domain.lab import LabConfig  # noqa: E402
from switchtest.exceptions import LoaderError  # noqa: E402
from switchtest.infrastructure.console.client import SerialConsoleTransport  # noqa: E402
from switchtest.infrastructure.loaders.lab import load_lab  # noqa: E402
from switchtest.infrastructure.nmap import scan_top_ports  # noqa: E402
from switchtest.utils.time import utcnow  # noqa: E402

DEFAULT_LAB_FILE = REPO_ROOT / "configs" / "lab.yaml"

# Candidates the forced change dialogue is fed before the real password, each
# violating exactly one rule, with the message the switch is expected to answer
# with. Deliberately no "!" anywhere: the AOS CLI expands it like a shell would
# and the command never reaches the password checker (see TC-IA-122).
REJECTED_CANDIDATES: list[tuple[str, str, str]] = [
    ("length_too_short", "12#qweA", "at least 9 characters"),
    ("missing_special", "123qweASD", "non-alphanumeric"),
    ("missing_uppercase", "12#qweasd", "uppercase"),
    ("missing_lowercase", "12#QWEASD", "lowercase"),
    ("missing_digit", "Qet++-ASD", "digit"),
    ("sequential_characters", "12#qwerASD", "consecutive characters"),
    ("repeated_characters", "12#qqqASD", "consecutive identical characters"),
]


@dataclass
class Check:
    name: str
    passed: bool
    observed: str
    expected: str


@dataclass
class Stage:
    name: str
    checks: list[Check] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and all(check.passed for check in self.checks)


def open_console(lab: LabConfig) -> SerialConsoleTransport:
    transport = SerialConsoleTransport(
        serial_port=lab.console.port,
        auth_username=lab.commissioning.factory_username,
        # Placeholder: connect() is never called on this transport, because the
        # factory switch cannot complete a normal login. The dialogue below
        # supplies passwords explicitly.
        auth_password=lab.commissioning.factory_password,
        baudrate=lab.console.baudrate,
        prompt=lab.switch.expected_prompt,
    )
    transport.open_port_only()
    return transport


def stage_first_login(transport: SerialConsoleTransport, lab: LabConfig) -> Stage:
    """First login: the switch demands a password change, and every rule of the
    policy is probed inside that dialogue before the real password is set."""
    stage = Stage("첫 로그인 및 비밀번호 정책 검증 (강제 변경 대화)")
    settings = lab.commissioning
    transport.await_login_prompt(timeout=30)
    response = transport.submit_login(
        settings.factory_username, settings.factory_password, timeout=30
    )

    forced = "password policy mismatch" in response.lower() or "enter current password" in response.lower()
    stage.checks.append(
        Check(
            name="공장 초기화 직후 비밀번호 변경 강제",
            passed=forced,
            observed=_condense(response),
            expected="Password policy mismatch, please change password.",
        )
    )
    if not forced:
        stage.error = (
            "The switch did not force a password change. Either it is not "
            "factory-reset, or commissioning.factory_password is wrong."
        )
        return stage

    for case_id, candidate, expected_fragment in REJECTED_CANDIDATES:
        accepted, message = transport.change_password_at_login(
            settings.factory_password, candidate, timeout=30
        )
        stage.checks.append(
            Check(
                name=f"정책 위반 비밀번호 거부 ({case_id})",
                # Rejection is the pass condition: an accepted weak password
                # would also leave the switch holding it, which is why the
                # message is reported verbatim.
                passed=(not accepted) and expected_fragment.lower() in message.lower(),
                observed=_condense(message),
                expected=f"rejected, mentioning '{expected_fragment}'",
            )
        )
        if accepted:
            stage.error = (
                f"The switch ACCEPTED a policy-violating password ({candidate!r}), so it is "
                f"now the live password for {settings.factory_username} -- set a compliant one "
                f"by hand from the console before doing anything else. "
                f"(The switch said: {_condense(message)})"
            )
            return stage
        if expected_fragment.lower() not in message.lower():
            # Refused, but not for the reason this candidate was built to
            # provoke. The account is untouched -- the dialogue is still open
            # at "Enter current password:" -- so this is a testing problem
            # (wrong expected wording, or a candidate that violates two rules
            # and trips the other one first), not a switch state problem.
            stage.error = (
                f"{candidate!r} was refused, but not for the expected reason "
                f"({expected_fragment!r}). Nothing on the switch changed. "
                f"The switch said: {_condense(message)}"
            )
            return stage

    accepted, message = transport.change_password_at_login(
        settings.factory_password, settings.initial_password, timeout=30
    )
    stage.checks.append(
        Check(
            name="정책을 만족하는 비밀번호로 변경 성공",
            passed=accepted,
            observed=_condense(message),
            expected="accepted (session returns to the login prompt)",
        )
    )
    if not accepted:
        stage.error = f"The switch refused {settings.initial_password!r}: {message}"
        return stage

    transport.await_login_prompt(timeout=30)
    signed_in = transport.submit_login(
        settings.factory_username, settings.initial_password, timeout=30
    )
    at_prompt = lab.switch.expected_prompt in signed_in
    stage.checks.append(
        Check(
            name="새 비밀번호로 재로그인",
            passed=at_prompt,
            observed=_condense(signed_in),
            expected=f"CLI prompt '{lab.switch.expected_prompt}'",
        )
    )
    if not at_prompt:
        stage.error = "Could not log in with the new password after changing it."
    return stage


def stage_addressing(transport: SerialConsoleTransport, lab: LabConfig) -> Stage:
    """Give the switch its management address and bring the links up. No IP
    service is switched on here -- the port scan that follows depends on the
    switch still being silent."""
    stage = Stage("관리 IP 설정 및 포트 활성화")
    settings = lab.commissioning
    commands = [
        f"ip interface {settings.mgmt_interface} address {settings.mgmt_address} vlan {settings.mgmt_vlan}",
        # The disable is required, not redundant: the ports must be bounced --
        # taken down and brought back up -- for the links to come up after
        # addressing. Issuing only the `enable` leaves ports that are already
        # nominally enabled untouched, and no link ever comes up. Do not
        # "simplify" this pair into one command.
        f"interface port {settings.mgmt_ports} admin-state disable",
        f"interface port {settings.mgmt_ports} admin-state enable",
    ]
    for command in commands:
        output = transport.send_command(command, timeout=30)
        stage.commands.append(command)
        if "error" in output.lower():
            stage.error = f"'{command}' was rejected: {output.strip()}"
            return stage

    interfaces = transport.send_command("show ip interface", timeout=30)
    stage.checks.append(
        Check(
            name="관리 IP 반영",
            passed=lab.switch.host in interfaces,
            observed=_condense(interfaces, lines=6),
            expected=lab.switch.host,
        )
    )
    return stage


def stage_reachability(transport: SerialConsoleTransport, lab: LabConfig) -> Stage:
    """Ping the station from the switch. Done from the switch rather than from
    this PC because it is the switch's own forwarding path being commissioned,
    and because the console is still the only session we have."""
    stage = Stage(f"스위치 -> PC({lab.station_ip}) 통신 확인")
    # `-c 3` keeps AOS's ping bounded; an unbounded one runs until Ctrl-C and
    # would never return to the prompt this read waits for.
    output = transport.send_command(f"ping {lab.station_ip} count 3", timeout=60)
    lost_everything = "100% packet loss" in output or "0 received" in output
    stage.checks.append(
        Check(
            name="스위치에서 PC로 ping 성공",
            passed=("bytes from" in output or "0% packet loss" in output) and not lost_everything,
            observed=_condense(output, lines=6),
            expected=f"ICMP replies from {lab.station_ip}",
        )
    )
    return stage


def stage_port_scan(lab: LabConfig, arguments: argparse.Namespace) -> Stage:
    """Every port shut before any service is enabled.

    Runs from this PC, and deliberately before `aaa authentication default
    local`: on this firmware that command switches SNMP on, so a scan after it
    finds UDP/161 open and the "factory switch is silent" claim would be
    reported as broken when it is not.
    """
    stage = Stage("서비스 활성화 전 포트스캔 (전부 닫힘)")
    if arguments.skip_scan:
        stage.checks.append(
            Check(
                name=f"상위 {arguments.top_ports}개 tcp/udp 포트 중 열린 것 없음",
                passed=True,
                observed="skipped (--skip-scan)",
                expected="no open ports",
            )
        )
        return stage
    try:
        open_ports, summary = scan_top_ports(
            lab.switch.host,
            top_ports=arguments.top_ports,
            on_progress=lambda line: print(f"  {line}", end="\r"),
        )
    except Exception as exc:  # noqa: BLE001 - reported, not raised: later stages still matter
        stage.error = f"port scan could not run ({exc}); nmap needs an elevated shell"
        return stage
    print()
    stage.checks.append(
        Check(
            name=f"상위 {arguments.top_ports}개 tcp/udp 포트 중 열린 것 없음",
            passed=not open_ports,
            observed=summary,
            expected=f"no open ports on {lab.switch.host}",
        )
    )
    return stage


def stage_services_and_accounts(transport: SerialConsoleTransport, lab: LabConfig) -> Stage:
    """Switch on the management services the suites need, then create the
    accounts they log in as.

    Only accounts without `provision:` are created here. The provisioned ones
    are made and removed by run_secfunc.py on every run, so creating them now
    would just be something for that run to delete.
    """
    stage = Stage("인증 설정, 서비스 활성화, 고정 계정 생성")
    commands = [
        "aaa authentication default local",
        "ip service ssh admin-state enable",
        "ip service http admin-state enable",
    ]
    for role, account in lab.accounts.items():
        if account.provision or account.username == lab.commissioning.factory_username:
            continue
        privileges = "read-write all"
        commands.append(f"user {account.username} password {account.password} {privileges}")

    for command in commands:
        output = transport.send_command(command, timeout=30)
        stage.commands.append(_redact(command))
        if "error" in output.lower():
            stage.error = f"'{_redact(command)}' was rejected: {output.strip()}"
            return stage

    users = transport.send_command("show user", timeout=30)
    for role, account in lab.accounts.items():
        if account.provision or account.username == lab.commissioning.factory_username:
            continue
        stage.checks.append(
            Check(
                name=f"계정 생성 확인 ({role}: {account.username})",
                passed=account.username in users,
                observed=_condense(users, lines=4),
                expected=account.username,
            )
        )

    services = transport.send_command("show ip service", timeout=30)
    for service in ("ssh", "http"):
        stage.checks.append(
            Check(
                name=f"{service} 활성화",
                passed=_service_enabled(services, service),
                observed=_condense(services, lines=8),
                expected=f"{service} enabled",
            )
        )
    return stage


def stage_save(transport: SerialConsoleTransport) -> Stage:
    """Persist it. Unlike a testcase -- which never saves, so a half-finished
    run cannot outlive itself -- commissioning is exactly the case where the
    configuration must survive a reboot."""
    stage = Stage("설정 저장")
    output = transport.send_command("write memory", timeout=60)
    stage.commands.append("write memory")
    stage.checks.append(
        Check(
            name="running-config 저장",
            passed="error" not in output.lower(),
            observed=_condense(output, lines=4) or "(no output)",
            expected="no error",
        )
    )
    return stage


def _service_enabled(output: str, service: str) -> bool:
    for line in output.split("\n"):
        fields = line.split()
        if fields and fields[0] == service:
            return "enabled" in line
    return False


def _redact(command: str) -> str:
    if " password " not in command:
        return command
    head, _, tail = command.partition(" password ")
    parts = tail.split(" ", 1)
    return f"{head} password ******{(' ' + parts[1]) if len(parts) > 1 else ''}"


def _condense(text: str, lines: int = 3) -> str:
    kept = [line.strip() for line in text.split("\n") if line.strip()]
    return " / ".join(kept[-lines:]) if kept else "(no output)"


def print_stage(index: int, total: int, stage: Stage) -> None:
    print(f"\n{'=' * 74}\n  [{index}/{total}] {stage.name}\n{'=' * 74}")
    for command in stage.commands:
        print(f"  CLI  {command}")
    for check in stage.checks:
        print(f"  [{'PASS' if check.passed else 'FAIL'}] {check.name}")
        if not check.passed:
            print(f"         expected: {check.expected}")
            print(f"         observed: {check.observed}")
    if stage.error:
        print(f"  ERROR  {stage.error}")


def write_report(path: Path, stages: list[Stage], started: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "started_at": started,
        "ended_at": utcnow().isoformat(),
        "status": "pass" if all(stage.ok for stage in stages) else "fail",
        "stages": [
            {
                "name": stage.name,
                "status": "pass" if stage.ok else "fail",
                "error": stage.error,
                "commands": stage.commands,
                "checks": [
                    {
                        "name": check.name,
                        "status": "pass" if check.passed else "fail",
                        "observed": check.observed,
                        "expected": check.expected,
                    }
                    for check in stage.checks
                ],
            }
            for stage in stages
        ],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--lab", type=Path, default=DEFAULT_LAB_FILE)
    parser.add_argument("--report", type=Path, default=REPO_ROOT / "reports" / "commission.json")
    parser.add_argument("--top-ports", type=int, default=100)
    parser.add_argument(
        "--skip-scan",
        action="store_true",
        help="skip the port scan (it needs nmap and an elevated shell)",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        lab = load_lab(arguments.lab)
    except LoaderError as exc:
        print(exc, file=sys.stderr)
        return 2

    started = utcnow().isoformat()
    print(
        f"Commissioning {lab.switch.host} over console {lab.console.port}@{lab.console.baudrate}\n"
        f"  factory account: {lab.commissioning.factory_username}\n"
        f"  new password:    {lab.commissioning.initial_password}\n"
        "\nThis is a one-time, non-idempotent run: the factory password works only once."
    )

    transport = open_console(lab)
    stages: list[Stage] = []
    try:
        for step in (
            lambda: stage_first_login(transport, lab),
            lambda: stage_addressing(transport, lab),
            lambda: stage_reachability(transport, lab),
            lambda: stage_port_scan(lab, arguments),
            lambda: stage_services_and_accounts(transport, lab),
            lambda: stage_save(transport),
        ):
            stage = step()
            stages.append(stage)
            print_stage(len(stages), 6, stage)
            if not stage.ok:
                print("\nStopping: later stages assume this one succeeded.", file=sys.stderr)
                break
    finally:
        transport.close()
        write_report(arguments.report, stages, started)

    passed = sum(1 for stage in stages if stage.ok)
    print(f"\n{'=' * 74}\nSUMMARY   {passed}/{len(stages)} stages passed   report: {arguments.report}\n{'=' * 74}")
    return 0 if stages and all(stage.ok for stage in stages) else 1


if __name__ == "__main__":
    sys.exit(main())
