"""Standalone SNMPv3 GET/SET, independent of switchtest's own code path.

Talks to the switch with nothing but pysnmp directly -- no imports from
`switchtest.*` -- so a pass/fail here tells you something switchtest's own
snmp_get/snmp_set validators using it would not: whether the problem (if
there is one) is in this project's code, or in the account/station/network
path itself.

Usage (from the omniswitch_ci_cd venv):

    venv\\Scripts\\python.exe manual_snmp_check.py get   192.168.1.1 snmpv3 <password>
    venv\\Scripts\\python.exe manual_snmp_check.py set   192.168.1.1 snmpv3 <password> OS6900-MANUALTEST

Assumes SHA-256 auth + AES-128 privacy on sysName.0 (SNMPv2-MIB), matching
the account TC-SM-42/43 create (`sha256+aes`). Auth and privacy share one
password here, same as those testcases -- pass two on the command line if
your manually-created account uses different ones.

Delete this file when you're done with it; it isn't part of the project.
"""

import asyncio
import sys

from pysnmp.hlapi.v3arch.asyncio import (
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    get_cmd,
    set_cmd,
    usmAesCfb128Protocol,
    usmHMAC192SHA256AuthProtocol,
)
from pysnmp.proto.rfc1902 import OctetString


async def main() -> int:
    if len(sys.argv) < 5:
        print(__doc__)
        return 2
    operation, host, user, password, *rest = sys.argv[1:]
    priv_password = password  # sha256+aes accounts use the same password for both

    user_data = UsmUserData(
        user,
        password,
        priv_password,
        authProtocol=usmHMAC192SHA256AuthProtocol,
        privProtocol=usmAesCfb128Protocol,
    )
    transport = await UdpTransportTarget.create((host, 161), timeout=10, retries=0)
    engine = SnmpEngine()
    try:
        if operation == "get":
            binding = ObjectType(ObjectIdentity("SNMPv2-MIB", "sysName", 0))
            command = get_cmd
        elif operation == "set":
            if not rest:
                print("set needs a value: ... set <host> <user> <password> <new-value>")
                return 2
            binding = ObjectType(ObjectIdentity("SNMPv2-MIB", "sysName", 0), OctetString(rest[0]))
            command = set_cmd
        else:
            print(f"unknown operation '{operation}' -- use 'get' or 'set'")
            return 2

        print(f"-> SNMPv3 {operation.upper()} sysName.0 on {host}:161 as '{user}' (SHA-256/AES)")
        error_indication, error_status, error_index, var_binds = await command(
            engine, user_data, transport, ContextData(), binding
        )
    finally:
        engine.close_dispatcher()

    if error_indication:
        print(f"FAILED (no answer or transport error): {error_indication}")
        return 1
    if error_status:
        at = var_binds[int(error_index) - 1] if error_index and var_binds else None
        location = f" at {at[0].prettyPrint()}" if at else ""
        print(f"FAILED (agent refused): {error_status.prettyPrint()}{location}")
        return 1

    for name, value in var_binds:
        print(f"OK: {name.prettyPrint()} = {value.prettyPrint()}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
