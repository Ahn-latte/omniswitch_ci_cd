import re
import subprocess
import threading
from typing import Callable

from switchtest.exceptions import ValidationExecutionError

_PORT_STATE_RE = re.compile(r"^(\d+)/(tcp|udp)\s+(\S+)(?:\s+(\S+))?", re.MULTILINE)
# nmap prints this instead of a port table when nothing interesting was found,
# e.g. `All 200 scanned ports on 192.168.1.1 are closed`. Seeing it (or a port
# table) is how we tell a completed scan from a failed invocation.
_ALL_PORTS_RE = re.compile(r"All (\d+) scanned ports on .* are (\S+)")


def scan_port(target: str, port: int, timeout: int = 30, protocol: str = "tcp") -> tuple[str, str]:
    """Run nmap against a single port and return (state, raw_output).

    -Pn skips host discovery: ICMP can be filtered independently of the
    service under test, and a host-discovery failure would otherwise be
    reported as "down" instead of the port's actual state.

    `protocol="udp"` switches to a UDP scan (-sU), which is what SNMP on
    161 needs. Two things differ for UDP: the scan needs raw-socket
    privileges (run as Administrator/root, or nmap reports the port as
    unknown), and a silent port comes back as `open|filtered` rather than
    `closed`, because a UDP service that simply doesn't answer is
    indistinguishable from a filtered one. Callers asserting "not open"
    therefore still get a meaningful answer, but a UDP `open|filtered` is
    weaker evidence than a TCP `closed`.
    """
    if not target:
        raise ValidationExecutionError("Port scan validation requires a target")
    if not port:
        raise ValidationExecutionError("Port scan validation requires a port")
    scan_flag = "-sU" if protocol == "udp" else "-sT"
    command = ["nmap", "-Pn", scan_flag, "-p", str(port), target]
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
        raise ValidationExecutionError(
            f"Could not parse nmap output for {protocol} port {port}:\n{output.strip()}"
        )
    return match.group(3), output.strip()


def scan_top_ports(
    target: str,
    top_ports: int = 100,
    timeout: int = 600,
    timing: str = "T4",
    on_progress: Callable[[str], None] | None = None,
) -> tuple[list[str], str]:
    """Scan the most common TCP and UDP ports at once; return (open_ports, summary).

    Runs `nmap -Pn -sS -sU --top-ports <n> -T4 -v <target>`, i.e. the n most
    frequently used ports *per protocol* (n TCP + n UDP), and reports which of
    them came back `open`. `open|filtered` -- what a silent UDP port looks
    like -- is not counted as open.

    -sS and -sU both need raw sockets, so this must run elevated
    (Administrator on Windows, root on Linux); without that nmap cannot
    determine states and the caller gets an error rather than a false clean
    result.

    -Pn is deliberate and matters more here than for a single-port scan: a
    device with every service switched off may not answer host discovery
    either, and nmap would then report it as down and skip the scan entirely
    -- which would look like "nothing open" for the wrong reason.

    `--top-ports` is a bounded smoke check, not proof about all 65535 ports.
    A service parked on an uncommon port is outside what this can see.

    `on_progress` is called with each line of nmap output as it arrives, for
    callers that want to show the scan advancing rather than a silent wait.
    It does not affect the returned result.
    """
    if not target:
        raise ValidationExecutionError("Port scan validation requires a target")
    command = [
        "nmap",
        "-Pn",
        "-sS",
        "-sU",
        "--top-ports",
        str(top_ports),
        f"-{timing}",
        "-v",
        # Left on regardless of `on_progress`: unprompted, nmap only reports
        # percentages once a phase already looks slow, so a caller watching
        # the output would see nothing for the first stretch of the scan.
        # These lines are filtered back out of the reported summary.
        "--stats-every",
        "2s",
        target,
    ]
    try:
        raw_output = _run_streaming(command, timeout=timeout, on_progress=on_progress)
    except subprocess.TimeoutExpired as exc:
        raise ValidationExecutionError(
            f"nmap top-{top_ports} scan of {target} timed out after {timeout} seconds. "
            f"UDP scanning is bounded by the target's ICMP rate limiting -- raise the "
            f"validation timeout or lower top_ports."
        ) from exc
    output = raw_output.strip()
    port_lines = _PORT_STATE_RE.findall(output)
    summary_line = _ALL_PORTS_RE.search(output)
    if not port_lines and not summary_line:
        raise ValidationExecutionError(
            f"Could not parse nmap top-{top_ports} scan of {target} -- an unprivileged "
            f"shell cannot run -sS/-sU, which looks like this:\n{output}"
        )
    open_ports = [
        f"{port}/{protocol} {state}" + (f" ({service})" if service else "")
        for port, protocol, state, service in port_lines
        if state == "open"
    ]
    return open_ports, _summarize(output, top_ports)


def _run_streaming(
    command: list[str],
    timeout: int,
    on_progress: Callable[[str], None] | None,
) -> str:
    """Run nmap, handing each line to `on_progress` as it is printed, and
    return everything it wrote.

    subprocess.run cannot do this: it only surfaces output once the process
    has exited, which for a UDP scan is the whole point at which progress
    stopped being useful. stderr is merged into stdout so the ordering the
    caller sees matches what nmap actually printed.

    The reader runs on a thread so the timeout is enforced by waiting on the
    process itself; draining the pipe inline would hang past the deadline if
    nmap went quiet.
    """
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError as exc:
        raise ValidationExecutionError("nmap utility is not available") from exc

    lines: list[str] = []

    def _pump() -> None:
        if process.stdout is None:
            return
        for line in process.stdout:
            lines.append(line)
            if on_progress is not None:
                on_progress(line.rstrip("\r\n"))

    reader = threading.Thread(target=_pump, daemon=True)
    reader.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        # Killing the child closes the pipe, which ends the reader's loop.
        process.kill()
        process.wait()
        raise
    finally:
        reader.join(timeout=5)
        if process.stdout is not None:
            process.stdout.close()
    return "".join(lines)


def _summarize(output: str, top_ports: int) -> str:
    """Keep the port table and the counts, drop nmap's verbose progress noise,
    so a passing result stays readable in the report."""
    kept = [
        line.strip()
        for line in output.splitlines()
        if _PORT_STATE_RE.match(line.strip())
        or _ALL_PORTS_RE.search(line)
        or line.startswith(("Not shown:", "PORT", "Nmap scan report", "Nmap done"))
    ]
    return "\n".join(kept) or f"nmap scanned the top {top_ports} tcp and udp ports"
