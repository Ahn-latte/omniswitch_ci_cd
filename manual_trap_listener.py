"""Standalone trap listener -- binds one UDP port and prints whatever arrives.

Reuses this project's own TrapListener (the same class snmp_trap_received
uses), on purpose: what's in question right now is whether a plain Python
socket on this port can receive what tshark already proved leaves the wire
(a firewall/socket-delivery question), not whether the project's own SNMP
code is correct -- so testing with the real class is the right amount of
independence here, unlike manual_snmp_check.py's SNMP GET/SET, which
deliberately avoids switchtest's own code.

Usage (from the omniswitch_ci_cd venv, in an elevated cmd):

    venv\\Scripts\\python.exe manual_trap_listener.py 161 120

Binds UDP/161 (first argument; matches this project's trap station config)
and waits up to 120s (second argument, default 60) for one datagram, then
prints its source and whatever this project's decoder could read from it.
Trigger the trap from another window while this is waiting, e.g.:

    interface port 1/1/1 admin-state disable

Delete this file when you're done with it; it isn't part of the project.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from switchtest.infrastructure.trap_listener import TrapListener  # noqa: E402


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 161
    timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 60

    print(f"Binding UDP/{port} on this machine, waiting up to {timeout}s ...")
    print("(trigger the trap from another window now)")
    try:
        with TrapListener(port=port) as listener:
            trap = listener.wait_for(timeout=timeout)
    except Exception as exc:  # noqa: BLE001 -- surfaced as plain text, not a traceback
        print(f"FAILED to listen: {exc}")
        return 1

    if trap is None:
        print(f"Nothing arrived on UDP/{port} within {timeout}s.")
        return 1

    print(f"RECEIVED from {trap.source_ip}: {len(trap.payload)} bytes")
    if trap.version:
        print(f"  SNMP version: {trap.version}")
    if trap.username:
        print(f"  USM user:     {trap.username}")
    if not trap.version:
        print("  (could not decode a header -- pyasn1 missing, or not SNMP-shaped)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
