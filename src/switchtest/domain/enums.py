from enum import Enum


class ValidationType(str, Enum):
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    REGEX = "regex"
    EQUALS = "equals"
    PING = "ping"
    PORT_CLOSED = "port_closed"
    WEB_UNREACHABLE = "web_unreachable"
    TLS_VERSION = "tls_version"


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
