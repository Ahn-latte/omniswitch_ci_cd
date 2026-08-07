"""Drive the switch's SNMP agent through net-snmp's command-line tools.

This is the automatable replacement for clicking through a MIB browser: the
same SNMPv3 USM parameters a browser asks for in a dialog (user, auth
protocol + password, privacy protocol + password, security level) become
`snmpget`/`snmpset` arguments, so an SNMP check can live in a testcase YAML
next to every other validation.

Requires net-snmp on PATH (`snmpget`, `snmpset`) -- on Windows the usual
source is the Net-SNMP installer; on Linux the `snmp` package.

Everything here goes over the network to UDP/161, which is the point: the
SNMPv3 account under test must work (or be refused) exactly as a real
management station would experience it.
"""

from dataclasses import dataclass
import re
import subprocess

from switchtest.exceptions import ValidationExecutionError

# `SNMPv2-MIB::sysName.0 = STRING: OS6900` -- the type prefix varies by object
# (STRING/INTEGER/Gauge32/...), so it is captured rather than assumed.
VALUE_PATTERN = re.compile(r"^\S+\s+=\s+(?:([A-Za-z0-9]+):\s*)?(.*)$", re.MULTILINE)
# net-snmp reports an agent-side refusal as `Reason: notWritable`/`noAccess`
# and a USM failure as an authentication error. All of them mean "the agent
# said no", as opposed to "nothing answered".
DENIAL_PATTERN = re.compile(
    r"(?i)(notwritable|noaccess|noSuchName|authorizationError|not writable|"
    r"authentication failure|unknown user name|wrong digest|decryption error)"
)
NO_RESPONSE_PATTERN = re.compile(r"(?i)(timeout: no response|no response from)")


@dataclass(frozen=True)
class SnmpV3Params:
    user: str
    auth_password: str
    priv_password: str
    level: str = "authPriv"
    auth_protocol: str = "SHA-256"
    priv_protocol: str = "AES"


@dataclass(frozen=True)
class SnmpResult:
    ok: bool
    value: str | None
    detail: str

    @property
    def denied(self) -> bool:
        """The agent answered and refused, rather than not answering at all."""
        return not self.ok and bool(DENIAL_PATTERN.search(self.detail))

    @property
    def unanswered(self) -> bool:
        return not self.ok and bool(NO_RESPONSE_PATTERN.search(self.detail))


def snmp_get(target: str, port: int, oid: str, params: SnmpV3Params, timeout: int = 30) -> SnmpResult:
    return _run("snmpget", target, port, params, [oid], timeout)


def snmp_set(
    target: str,
    port: int,
    oid: str,
    value: str,
    params: SnmpV3Params,
    value_type: str = "s",
    timeout: int = 30,
) -> SnmpResult:
    """Write one object. `value_type` is net-snmp's type letter (`s` string,
    `i` integer, `u` unsigned, `a` IP address, ...)."""
    return _run("snmpset", target, port, params, [oid, value_type, value], timeout)


def _run(
    tool: str,
    target: str,
    port: int,
    params: SnmpV3Params,
    arguments: list[str],
    timeout: int,
) -> SnmpResult:
    if not target:
        raise ValidationExecutionError(f"{tool} validation requires a target")
    if not port:
        raise ValidationExecutionError(f"{tool} validation requires a port")
    command = [tool, "-v3", "-l", params.level, "-u", params.user]
    if params.level in {"authNoPriv", "authPriv"}:
        command += ["-a", params.auth_protocol, "-A", params.auth_password]
    if params.level == "authPriv":
        command += ["-x", params.priv_protocol, "-X", params.priv_password]
    # -r 0: no retries. A retried request would count as several attempts at
    # the agent and, for the denial checks, make the failure slower without
    # making it any more certain.
    command += ["-t", str(timeout), "-r", "0", f"{target}:{port}"] + arguments
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout + 10,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ValidationExecutionError(
            f"{tool} is not available -- install net-snmp and make sure it is on PATH"
        ) from exc
    except subprocess.TimeoutExpired:
        return SnmpResult(
            False,
            None,
            f"{tool} was killed after {timeout + 10}s: no response from {target}:{port}",
        )
    output = ((completed.stdout or "") + (completed.stderr or "")).strip()
    if completed.returncode != 0:
        return SnmpResult(False, None, output or f"{tool} exited with {completed.returncode}")
    match = VALUE_PATTERN.search(output)
    if not match:
        return SnmpResult(False, None, output or f"{tool} returned no value")
    return SnmpResult(True, match.group(2).strip().strip('"'), output)


def redact(params: SnmpV3Params, text: str) -> str:
    """Keep SNMP passwords out of reports: net-snmp echoes the full command
    line in some error messages, and validation results are written to disk."""
    for secret in (params.auth_password, params.priv_password):
        if secret:
            text = text.replace(secret, "******")
    return text
