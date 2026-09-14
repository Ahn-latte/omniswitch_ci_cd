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
    # For port_scan_closed: floor on nmap's send rate (packets/sec), plus
    # telling it not to react to detected ICMP rate limiting. Without this, a
    # target that is silent by design (TC-SM-41B's `ip service all
    # admin-state disable` answers nothing, not even ICMP unreachable) makes
    # nmap's adaptive timing mistake total silence for network congestion and
    # throttle itself -- an all_ports scan can then run for hours without
    # finishing inside a normal timeout. Lower this if the switch's own CPU
    # starts dropping the replies it should be sending (fewer opens than
    # actually exist is worse than a slow scan).
    min_rate: int = 1000
    # For port_scan_closed: how many times nmap retransmits an unanswered
    # probe before giving up on a port. A silent port -- not a definite
    # `closed` one -- costs the most time, precisely from retrying it; since
    # `open|filtered` already counts as "not open" for this validation (it
    # never needs to resolve ambiguity down to a confident `closed`), there
    # is nothing to gain from the higher retry counts the default timing
    # templates use for accuracy, and every retry avoided is time back
    # across all 131070 probes of an all_ports scan.
    max_retries: int = 1
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
    # For snmp_trap_received: an SNMP GET against `oid` using `snmp.user` but
    # this password instead of the real one -- provokes a USM authentication
    # failure as the trigger for `authenticationFailure` (SNMPv2-MIB), rather
    # than a real SET or a CLI action. Deliberately not the same mechanism as
    # a CLI/SSH login failure: SNMP USM authentication is independent of the
    # AAA lockout-threshold that TC-IA-131/133 test, so unlike failing a
    # console/SSH login on purpose, this never risks locking a real account.
    bad_auth_password: Optional[str] = None
    # For snmp_trap_received: a single, real SSH login attempt as this
    # account with this (deliberately wrong) password -- provokes whatever
    # trap the switch fires for an AAA/CLI authentication failure, as
    # opposed to `bad_auth_password` above (SNMP USM, a separate mechanism).
    # Unlike SNMP USM, this DOES count against the account's lockout
    # threshold like any real failed login, so keep this to one attempt and
    # never point it at an account another testcase is actively bracketing
    # (e.g. admin1 during TC-IA-131/133).
    login_failure_username: Optional[str] = None
    login_failure_password: Optional[str] = None

    # For web_tls_restricted_unreachable: the exact TLS version Firefox is
    # pinned to (min == max) before navigating. A switch that requires TLS
    # 1.2+ should refuse the handshake outright.
    tls_version: str = "1.1"

    # For ssh_legacy_rejected: override the client identification string sent
    # after the version exchange (RFC 4253 4.2). Left unset, the validator's
    # own default (an SSH-1.5 banner) is used.
    ssh_client_banner: Optional[str] = None

    # For ssh_session_expires: credentials for a fresh SSH session -- never
    # the driver's own -- that is left idle to prove the switch's configured
    # inactivity timeout actually disconnects it, not just that `session cli
    # timeout` is set. Use a throwaway account (e.g. one this testcase's own
    # setup creates with `$test_password`), not secureadmin/admin1: AOS
    # allows only one session per account across every transport, and the
    # driver already holds one open as whichever account is running this
    # testcase.
    session_username: Optional[str] = None
    session_password: Optional[str] = None
    # How long to sit idle before trying the session again. Comfortably past
    # the configured timeout (in minutes) rather than equal to it, so a
    # session that survives isn't mistaken for one that expired just outside
    # a race with the switch's own timer.
    idle_seconds: int = 75


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
