"""Verify that ONE AOSSwitchDriver.attempt_login() call registers as exactly
ONE failed login attempt on the switch.

This is not a given: scrapli/paramiko may negotiate several auth methods
(e.g. keyboard-interactive then password) within a single connection, which
the switch could count as multiple bad attempts -- in which case
`trigger_failed_logins` with attempts=3 would actually burn through the
lockout threshold sooner (or in a different pattern) than intended, and
TC-IA-133 would be testing something other than what it claims.

Method: read admin1's `Password bad attempts` counter as secureadmin, do a
single failed login as admin1, read the counter again, and report the delta.
Expected delta: exactly 1.

Leaves admin1 unlocked on exit (a single attempt shouldn't lock it, but the
unlock runs regardless in case the counter was already near the threshold).

Connects as secureadmin (not admin1) for the same reason TC-IA-133 does: the
account being locked can't be the one holding the observing session, and
reading admin1's state is a secureadmin-level operation.

The secureadmin device entry is attached over the serial console, so this
needs the console cable connected and `serial_port` in configs/devices.yaml
pointing at the right COM port. The failed login itself still goes out over
SSH -- that is the path whose attempts the switch counts.

Usage (cmd), from the omniswitch_ci_cd directory:
    set SWITCH_SECUREADMIN_PASSWORD=...
    venv\\Scripts\\python.exe scripts\\verify_failed_login_counting.py
"""

import re
import sys
from pathlib import Path

from switchtest.drivers.aos import AOSSwitchDriver
from switchtest.infrastructure.loaders.devices import load_device_by_name

TARGET_USER = "admin1"
WRONG_PASSWORD = "definitely-wrong-Passw0rd!1"
DEVICE_NAME = "secureadmin"
DEVICES_FILE = Path("configs/devices.yaml")


def _bad_attempts(driver: AOSSwitchDriver) -> int | None:
    output = driver.run_show(f"show user {TARGET_USER}")
    match = re.search(r"Password bad attempts\s*=\s*(\d+)", output)
    if not match:
        print(f"  could not parse 'Password bad attempts' from:\n{output}")
        return None
    return int(match.group(1))


def main() -> int:
    device = load_device_by_name(DEVICES_FILE, DEVICE_NAME)
    driver = AOSSwitchDriver(device)
    driver.connect()
    try:
        before = _bad_attempts(driver)
        if before is None:
            return 1
        print(f"before: Password bad attempts = {before}")

        succeeded = driver.attempt_login(TARGET_USER, WRONG_PASSWORD)
        print(f"attempt_login returned {succeeded} (expected False)")

        after = _bad_attempts(driver)
        if after is None:
            return 1
        print(f"after:  Password bad attempts = {after}")

        delta = after - before
        print(f"\ndelta = {delta}")
        if delta == 1:
            print("OK: one attempt_login() == one failed attempt on the switch.")
            result = 0
        else:
            print(
                f"MISMATCH: one attempt_login() registered as {delta} failed attempts.\n"
                f"TC-IA-133's attempts=3 would therefore not mean 3 attempts -- "
                f"the setup step needs adjusting."
            )
            result = 1
    finally:
        driver.run_show(f"user {TARGET_USER} unlock")
        print(f"cleanup: ran 'user {TARGET_USER} unlock'")
        driver.disconnect()
    return result


if __name__ == "__main__":
    raise SystemExit(main())
