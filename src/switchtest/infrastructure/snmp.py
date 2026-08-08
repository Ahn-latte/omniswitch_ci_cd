"""Drive the switch's SNMP agent over SNMPv3, using pysnmp.

This is the automatable replacement for clicking through a MIB browser: the
same SNMPv3 USM parameters a browser asks for in a dialog (user, auth
protocol + password, privacy protocol + password, security level) become
arguments here, so an SNMP check can live in a testcase YAML next to every
other validation.

pysnmp rather than net-snmp's command-line tools, for two reasons. The
account under test uses SHA-256, which net-snmp only supports from 5.8 --
newer than any official Net-SNMP build for Windows -- and a pip-installable
library is pinned in pyproject.toml instead of being a per-machine install
that has to be found on PATH. It also reports refusals and timeouts as
structured outcomes rather than English text that has to be pattern-matched.

Everything here goes over the network to UDP/161, which is the point: the
SNMPv3 account under test must work (or be refused) exactly as a real
management station would experience it.
"""

import asyncio
from contextlib import contextmanager
from dataclasses import dataclass
import re
import time
from typing import Any, Callable, Iterator

from switchtest.exceptions import ValidationExecutionError

try:
    from pysnmp.hlapi.v3arch.asyncio import (
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        UsmUserData,
        get_cmd,
        set_cmd,
        usm3DESEDEPrivProtocol,
        usmAesCfb128Protocol,
        usmAesCfb192Protocol,
        usmAesCfb256Protocol,
        usmDESPrivProtocol,
        usmHMAC128SHA224AuthProtocol,
        usmHMAC192SHA256AuthProtocol,
        usmHMAC256SHA384AuthProtocol,
        usmHMAC384SHA512AuthProtocol,
        usmHMACMD5AuthProtocol,
        usmHMACSHAAuthProtocol,
        usmNoAuthProtocol,
        usmNoPrivProtocol,
    )
    from pysnmp.proto import rfc1902

    PYSNMP_IMPORT_ERROR: Exception | None = None
except Exception as exc:  # pragma: no cover - exercised only without pysnmp
    PYSNMP_IMPORT_ERROR = exc

# Protocol names as a testcase writes them (and as AOS names them in
# `user ... sha256+aes`), normalised to letters and digits before lookup so
# "SHA-256", "sha256" and "SHA 256" all land in the same place.
_AUTH_PROTOCOLS: dict[str, str] = {
    "MD5": "usmHMACMD5AuthProtocol",
    "SHA": "usmHMACSHAAuthProtocol",
    "SHA1": "usmHMACSHAAuthProtocol",
    "SHA224": "usmHMAC128SHA224AuthProtocol",
    "SHA256": "usmHMAC192SHA256AuthProtocol",
    "SHA384": "usmHMAC256SHA384AuthProtocol",
    "SHA512": "usmHMAC384SHA512AuthProtocol",
    "NONE": "usmNoAuthProtocol",
}
_PRIV_PROTOCOLS: dict[str, str] = {
    "DES": "usmDESPrivProtocol",
    "3DES": "usm3DESEDEPrivProtocol",
    "AES": "usmAesCfb128Protocol",
    "AES128": "usmAesCfb128Protocol",
    "AES192": "usmAesCfb192Protocol",
    "AES256": "usmAesCfb256Protocol",
    "NONE": "usmNoPrivProtocol",
}
# net-snmp's type letters, kept as the testcase-facing spelling so `value_type`
# in a YAML means the same thing it did before and in every net-snmp example.
_VALUE_TYPES: dict[str, str] = {
    "s": "OctetString",
    "i": "Integer32",
    "u": "Unsigned32",
    "a": "IpAddress",
    "t": "TimeTicks",
    "o": "ObjectIdentifier",
}
# An OID a testcase gave as a bare `sysName.0` has to be resolved against some
# MIB; pysnmp will not guess. Everything the switch checks lives in the MIB
# bundled with pysnmp, so that is the assumed module. Write `MODULE::object.0`
# to name a different one.
_DEFAULT_MIB = "SNMPv2-MIB"
_NUMERIC_OID_RE = re.compile(r"^\.?\d+(\.\d+)*$")

# How to read an errorIndication, which is pysnmp's word for "the exchange did
# not produce a value". The distinction that matters is whether the agent
# answered and said no, or never answered at all -- a refusal proves the access
# control worked, silence equally means SNMP is off or the packet was filtered.
# The texts below are pysnmp's own (see pysnmp.proto.errind): everything here is
# a USM/VACM rejection the agent reported back, i.e. an answer.
DENIAL_PATTERN = re.compile(
    r"(?i)("
    r"notwritable|not writable|noaccess|readonly|nosuchname|authorizationerror|"
    r"wrong snmp pdu digest|authenticator mismatched|unknown usm user|"
    r"unknown snmp security name|unsupported snmp security level|windows of trust|"
    r"out of mib view|access to mib node denied|remote snmp engine reported error|"
    r"ciphertext is broken"
    r")"
)
NO_RESPONSE_PATTERN = re.compile(r"(?i)(no snmp response received|empty snmp response|no response)")


@dataclass(frozen=True)
class SnmpV3Params:
    user: str
    auth_password: str
    priv_password: str
    level: str = "authPriv"
    auth_protocol: str = "SHA-256"
    priv_protocol: str = "AES"

    @property
    def profile(self) -> str:
        """One-line description of the security profile, without the secrets --
        safe to print or write to a report."""
        if self.level == "noAuthNoPriv":
            algorithms = ""
        elif self.level == "authNoPriv":
            algorithms = f" {self.auth_protocol}"
        else:
            algorithms = f" {self.auth_protocol}/{self.priv_protocol}"
        return f"v3 {self.level}{algorithms} as '{self.user}'"


@dataclass(frozen=True)
class SnmpResult:
    ok: bool
    value: str | None
    detail: str
    # The agent answered and said no, as opposed to not answering at all.
    refused: bool = False
    timed_out: bool = False

    @property
    def denied(self) -> bool:
        return not self.ok and (self.refused or bool(DENIAL_PATTERN.search(self.detail)))

    @property
    def unanswered(self) -> bool:
        return not self.ok and (self.timed_out or bool(NO_RESPONSE_PATTERN.search(self.detail)))


@dataclass(frozen=True)
class SnmpExchange:
    """One completed request, for anyone watching the run go by. `detail` is
    already redacted, so an observer can print it as-is."""

    operation: str  # "GET" or "SET"
    endpoint: str  # "192.168.1.1:161"
    profile: str  # SnmpV3Params.profile -- never contains a password
    oid: str
    written: str | None  # the value a SET tried to write
    result: SnmpResult
    seconds: float


_observer: Callable[[SnmpExchange], None] | None = None


@contextmanager
def observing(observer: Callable[[SnmpExchange], None] | None) -> Iterator[None]:
    """Report every SNMP exchange made inside this block to `observer`.

    A module-level hook rather than an argument because the calls originate
    from several places -- including the automatic read-back and restore that
    `snmp_set` validations perform -- and those are exactly the steps worth
    showing. Threading is not a concern: validations run one at a time.
    """
    global _observer
    previous = _observer
    _observer = observer
    try:
        yield
    finally:
        _observer = previous


def snmp_get(target: str, port: int, oid: str, params: SnmpV3Params, timeout: int = 30) -> SnmpResult:
    return _run("GET", target, port, oid, params, timeout, value=None, value_type="s")


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
    `i` integer, `u` unsigned, `a` IP address, `t` timeticks, `o` OID)."""
    return _run("SET", target, port, oid, params, timeout, value=value, value_type=value_type)


def _run(
    operation: str,
    target: str,
    port: int,
    oid: str,
    params: SnmpV3Params,
    timeout: int,
    value: str | None,
    value_type: str,
) -> SnmpResult:
    if PYSNMP_IMPORT_ERROR is not None:
        raise ValidationExecutionError(
            f"pysnmp could not be imported ({PYSNMP_IMPORT_ERROR}) -- install it with "
            f"`pip install -e .` from the project root"
        )
    if not target:
        raise ValidationExecutionError(f"SNMP {operation} validation requires a target")
    if not port:
        raise ValidationExecutionError(f"SNMP {operation} validation requires a port")
    if not oid:
        raise ValidationExecutionError(f"SNMP {operation} validation requires an oid")

    binding = ObjectType(_object_identity(oid))
    if operation == "SET":
        binding = ObjectType(_object_identity(oid), _typed_value(value or "", value_type))

    started = time.monotonic()
    # asyncio.run per call: pysnmp 7 is asyncio-only while everything around it
    # here is synchronous. Validations are a handful of requests per run, so a
    # short-lived loop each time costs nothing measurable and keeps the engine's
    # lifetime bounded to the request that owns it.
    result = asyncio.run(_execute(operation, target, port, params, binding, timeout))
    elapsed = time.monotonic() - started

    result = SnmpResult(
        result.ok, result.value, redact(params, result.detail), result.refused, result.timed_out
    )
    if _observer is not None:
        _observer(
            SnmpExchange(
                operation=operation,
                endpoint=f"{target}:{port}",
                profile=params.profile,
                oid=oid,
                written=value,
                result=result,
                seconds=elapsed,
            )
        )
    return result


async def _execute(
    operation: str,
    target: str,
    port: int,
    params: SnmpV3Params,
    binding: Any,
    timeout: int,
) -> SnmpResult:
    engine = SnmpEngine()
    try:
        # retries=0: a retried request counts as several attempts at the agent
        # and, for the denial checks, makes the failure slower without making
        # it any more certain.
        transport = await UdpTransportTarget.create((target, port), timeout=timeout, retries=0)
        command = get_cmd if operation == "GET" else set_cmd
        error_indication, error_status, error_index, var_binds = await command(
            engine, _user_data(params), transport, ContextData(), binding
        )
    except Exception as exc:
        return SnmpResult(False, None, f"SNMP {operation} failed: {exc}")
    finally:
        engine.close_dispatcher()

    if error_indication:
        detail = str(error_indication)
        # No answer at all is a different finding from an answered refusal: it
        # equally means SNMP is switched off or the request was filtered.
        return SnmpResult(
            False,
            None,
            detail,
            refused=bool(DENIAL_PATTERN.search(detail)),
            timed_out=bool(NO_RESPONSE_PATTERN.search(detail)),
        )
    if error_status:
        failed = error_status.prettyPrint()
        at = var_binds[int(error_index) - 1] if error_index and var_binds else None
        location = f" at {at[0].prettyPrint()}" if at else ""
        return SnmpResult(False, None, f"{failed}{location}", refused=True)
    if not var_binds:
        return SnmpResult(False, None, f"SNMP {operation} returned no value")
    return SnmpResult(True, var_binds[0][1].prettyPrint(), " = ".join(
        part.prettyPrint() for part in var_binds[0]
    ))


def _user_data(params: SnmpV3Params) -> Any:
    """Build pysnmp's USM credentials. Security level is expressed by which
    keys are supplied -- pysnmp has no explicit `level` argument -- so
    authNoPriv means passing no privacy key at all, not a null protocol."""
    auth_protocol = _lookup_protocol(params.auth_protocol, _AUTH_PROTOCOLS, "auth")
    if params.level == "noAuthNoPriv":
        return UsmUserData(params.user)
    if params.level == "authNoPriv":
        return UsmUserData(params.user, params.auth_password, authProtocol=auth_protocol)
    if params.level != "authPriv":
        raise ValidationExecutionError(
            f"Unknown SNMP security level '{params.level}' "
            f"(expected noAuthNoPriv, authNoPriv or authPriv)"
        )
    return UsmUserData(
        params.user,
        params.auth_password,
        params.priv_password,
        authProtocol=auth_protocol,
        privProtocol=_lookup_protocol(params.priv_protocol, _PRIV_PROTOCOLS, "privacy"),
    )


def _lookup_protocol(name: str, table: dict[str, str], kind: str) -> Any:
    key = re.sub(r"[^A-Z0-9]", "", (name or "").upper())
    try:
        return globals()[table[key]]
    except KeyError:
        raise ValidationExecutionError(
            f"Unsupported SNMP {kind} protocol '{name}' (known: {', '.join(sorted(table))})"
        ) from None


def _object_identity(oid: str) -> Any:
    """Turn a testcase's OID into something pysnmp can resolve.

    Three spellings are accepted: a numeric OID, `MODULE::object.index`, and a
    bare `object.index` which is assumed to live in SNMPv2-MIB. pysnmp needs
    the module and symbol as separate arguments -- unlike net-snmp it will not
    parse `SNMPv2-MIB::sysName.0` from a single string.
    """
    oid = oid.strip()
    if _NUMERIC_OID_RE.match(oid):
        return ObjectIdentity(oid)
    module, separator, symbol = oid.partition("::")
    if not separator:
        module, symbol = _DEFAULT_MIB, oid
    symbol, _, index = symbol.partition(".")
    if not index:
        return ObjectIdentity(module, symbol)
    return ObjectIdentity(module, symbol, *(int(part) if part.isdigit() else part
                                            for part in index.split(".")))


def _typed_value(value: str, value_type: str) -> Any:
    try:
        constructor = getattr(rfc1902, _VALUE_TYPES[value_type])
    except KeyError:
        raise ValidationExecutionError(
            f"Unsupported SNMP value type '{value_type}' "
            f"(known: {', '.join(sorted(_VALUE_TYPES))})"
        ) from None
    try:
        return constructor(value)
    except Exception as exc:
        raise ValidationExecutionError(
            f"'{value}' is not a valid {_VALUE_TYPES[value_type]}: {exc}"
        ) from exc


def redact(params: SnmpV3Params, text: str) -> str:
    """Keep SNMP passwords out of reports: an error message can quote what it
    was given, and validation results are written to disk."""
    for secret in (params.auth_password, params.priv_password):
        if secret:
            text = text.replace(secret, "******")
    return text
