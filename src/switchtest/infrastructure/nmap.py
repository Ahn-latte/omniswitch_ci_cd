import re
import subprocess

from switchtest.exceptions import ValidationExecutionError

_PORT_STATE_RE = re.compile(r"^(\d+)/tcp\s+(\S+)", re.MULTILINE)


def scan_port(target: str, port: int, timeout: int = 30) -> tuple[str, str]:
    """Run nmap against a single TCP port and return (state, raw_output).

    -Pn skips host discovery: ICMP can be filtered independently of the TCP
    service under test, and a host-discovery failure would otherwise be
    reported as "down" instead of the port's actual state.
    """
    if not target:
        raise ValidationExecutionError("Port scan validation requires a target")
    if not port:
        raise ValidationExecutionError("Port scan validation requires a port")
    command = ["nmap", "-Pn", "-p", str(port), target]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ValidationExecutionError("nmap utility is not available") from exc
    except subprocess.TimeoutExpired as exc:
        raise ValidationExecutionError(f"nmap scan timed out after {timeout} seconds") from exc
    output = (completed.stdout or "") + (completed.stderr or "")
    match = _PORT_STATE_RE.search(output)
    if not match:
        raise ValidationExecutionError(f"Could not parse nmap output for port {port}:\n{output.strip()}")
    return match.group(2), output.strip()
