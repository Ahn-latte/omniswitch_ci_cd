from typing import Optional

from pydantic import BaseModel, Field

from switchtest.domain.enums import Severity, TestAction, TransportProtocol, ValidationType


class TestStep(BaseModel):
    action: TestAction
    commands: list[str] = Field(default_factory=list)
    # For `cli` steps whose commands are expected to fail sometimes -- clearing
    # leftovers from an interrupted run, where deleting something that isn't
    # there is an error but not a problem. Off by default: a setup command that
    # silently fails would otherwise leave the testcase checking nothing.
    ignore_errors: bool = False
    seconds: Optional[int] = None
    username: Optional[str] = None
    wrong_password: Optional[str] = None
    attempts: int = 3


class SnmpCredentials(BaseModel):
    """SNMPv3 USM parameters for the SNMP client.

    The switch's SNMPv3 users are ordinary AOS accounts (`user <name> password
    <pw> sha256+aes ...`), so auth and privacy share that one password unless
    the account was set up otherwise -- hence `priv_password` defaulting to the
    auth password. Passwords may be given inline (fine for the throwaway
    accounts a testcase creates and deletes itself) or, for anything longer
    lived, through `*_password_env` so they stay out of the repository.
    """

    user: str
    level: str = "authPriv"
    auth_protocol: str = "SHA-256"
    priv_protocol: str = "AES"
    auth_password: Optional[str] = None
    auth_password_env: Optional[str] = None
    priv_password: Optional[str] = None
    priv_password_env: Optional[str] = None


class ValidationStep(BaseModel):
    name: str
    type: ValidationType
    command: Optional[str] = None
    expected: Optional[str] = None
    pattern: Optional[str] = None
    target: Optional[str] = None
    port: Optional[int] = None
    protocol: TransportProtocol = TransportProtocol.TCP
    # For port_scan_closed: how many of the most common ports to scan, per
    # protocol (so 100 means 100 TCP + 100 UDP). Ignored when all_ports is set.
    top_ports: int = 100
    # For port_scan_closed: scan every TCP/UDP port (1-65535) instead of just
    # the most common `top_ports`. --top-ports is a frequency sample, not a
    # port-range guarantee -- it can and does skip real ports (e.g. 2222/tcp,
    # ssh-pkix on this switch, ranks ~366th and is never included even at
    # --top-ports 100), so a service left listening on one of those is
    # invisible to the sampled scan. Full-range UDP is slow (tens of minutes
    # to hours depending on the target's rate limiting); size `timeout`
    # accordingly.
    all_ports: bool = False
    # For api_unreachable: the HTTP path to request. Keep it credential-free --
    # a request to the auth endpoint would count as a login attempt.
    path: str = "/"
    oid: Optional[str] = None
    value: Optional[str] = None
    value_type: str = "s"
    snmp: Optional[SnmpCredentials] = None
    timeout: int = 30
    reauth: bool = False
    # For snmp_trap_received: the local UDP port to listen on (this machine is
    # the trap station, so this is our port, not the switch's).
    trap_port: int = 162
    # For snmp_trap_received: CLI commands run over the driver's own session
    # to provoke the trap, issued only after the listener socket is already
    # bound -- see TrapListener's docstring for why that order is mandatory.
    trigger_commands: list[str] = Field(default_factory=list)


class TestCaseDefinition(BaseModel):
    id: str
    name: str
    description: str
    feature: str
    tags: list[str] = Field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    preconditions: list[str] = Field(default_factory=list)
    setup: list[TestStep] = Field(default_factory=list)
    validations: list[ValidationStep] = Field(default_factory=list)
    cleanup: list[TestStep] = Field(default_factory=list)
    continue_on_failure: bool = False
    timeout: int = 300
    restore_baseline_after: bool = True
