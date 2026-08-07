from enum import Enum


class ValidationType(str, Enum):
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    REGEX = "regex"
    EQUALS = "equals"
    PING = "ping"
    PORT_CLOSED = "port_closed"
    PORT_SCAN_CLOSED = "port_scan_closed"
    WEB_UNREACHABLE = "web_unreachable"
    TLS_VERSION = "tls_version"
    TCP_BLOCKED = "tcp_blocked"
    SNMP_GET = "snmp_get"
    SNMP_SET = "snmp_set"
    SNMP_DENIED = "snmp_denied"


class TransportProtocol(str, Enum):
    """Which IP protocol a port-level validation scans.

    SNMP listens on UDP, so `port_closed` has to be able to ask nmap for a
    UDP scan (`-sU`) rather than the default TCP one.
    """

    TCP = "tcp"
    UDP = "udp"


class TransportType(str, Enum):
    """How the framework holds its own management session with the device.

    ``SERIAL`` is a locally attached console port (RS-232 / USB-serial), which
    is out-of-band: it keeps working while the device refuses network logins
    from this machine's IP. Testcases that ban this machine need it.
    """

    SSH = "ssh"
    SERIAL = "serial"


class TestAction(str, Enum):
    CLI = "cli"
    WAIT = "wait"
    SAVE_CONFIG = "save_config"
    RESTORE_BASELINE = "restore_baseline"
    REBOOT = "reboot"
    TRIGGER_FAILED_LOGINS = "trigger_failed_logins"
    ENSURE_UNLOCKED = "ensure_unlocked"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ResultStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    SKIPPED = "skipped"


class SuiteStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"


class DeviceSafetyState(str, Enum):
    SAFE = "safe"
    MODIFIED = "modified"
    RECOVERY_REQUIRED = "recovery_required"
    UNSAFE = "unsafe"
