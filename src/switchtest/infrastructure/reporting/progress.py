import re
import sys
from types import TracebackType
from typing import TYPE_CHECKING, Callable

import typer

if TYPE_CHECKING:  # imported for typing only, so this module stays free of pysnmp
    from switchtest.infrastructure.snmp import SnmpExchange, SnmpResult

# nmap -v announces each scan phase, then reports progress within that phase.
# The percentage is per phase, never for the run as a whole.
_INITIATING_RE = re.compile(r"^Initiating (.+?) at \d")
_TIMING_RE = re.compile(r"^(.+?) Timing: About ([\d.]+)% done(?:.*?\(([\d:]+) remaining\))?")
_COMPLETED_RE = re.compile(r"^Completed (.+?) at \S+, ([\d.]+)s elapsed")


class NmapProgressRenderer:
    """Render nmap's -v chatter as a live progress line on the console.

    Without it a top-ports scan is a silent pause for as long as the whole
    validation timeout allows -- the SYN pass finishes in seconds but the UDP
    one is bounded by the target's ICMP rate limiting and can run for minutes
    with nothing on screen to say the run is still alive.

    The percentage shown is nmap's own per-phase figure rather than a combined
    number, because the two phases are nowhere near equal in length: averaging
    them would park the bar at "50%" for most of the run.

    Use as a context manager -- it prints the header on entry and closes off
    the in-place line on exit, including when the scan raises.
    """

    _BAR_WIDTH = 24
    # Wide enough that a redrawn line always overwrites the previous one; a
    # shorter update would otherwise leave the tail of a longer one behind.
    _LINE_WIDTH = 78

    def __init__(
        self,
        target: str,
        top_ports: int,
        echo: Callable[[str], None] | None = None,
        interactive: bool | None = None,
    ) -> None:
        self._target = target
        self._top_ports = top_ports
        self._echo = echo if echo is not None else _echo_without_newline
        # On a terminal every update overwrites the previous one with \r. When
        # output is redirected (CI logs, `> run.txt`) that collapses into one
        # unreadable line, so there we emit discrete lines and throttle them.
        self._interactive = sys.stdout.isatty() if interactive is None else interactive
        self._phase: str | None = None
        self._open_line = False
        self._last_bucket: tuple[str, int] | None = None

    def __enter__(self) -> "NmapProgressRenderer":
        self._echo(f"  nmap: scanning top {self._top_ports} tcp+udp ports on {self._target}\n")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._open_line:
            self._echo("\n")
            self._open_line = False

    def handle_line(self, line: str) -> None:
        """Feed one line of nmap output. Anything that isn't a phase or
        progress announcement is ignored -- the full output still reaches the
        report, this only decides what is worth showing while it runs."""
        stripped = line.strip()
        initiating = _INITIATING_RE.match(stripped)
        if initiating:
            self._phase = initiating.group(1)
            self._render(0.0, detail="starting")
            return
        timing = _TIMING_RE.match(stripped)
        if timing:
            self._phase = timing.group(1)
            remaining = timing.group(3)
            self._render(float(timing.group(2)), detail=f"ETA {remaining}" if remaining else "")
            return
        completed = _COMPLETED_RE.match(stripped)
        if completed:
            self._phase = completed.group(1)
            self._render(100.0, detail=f"done in {completed.group(2)}s")

    def _render(self, percent: float, detail: str) -> None:
        phase = self._phase or "nmap"
        if not self._interactive and not self._should_log(phase, percent):
            return
        filled = int(self._BAR_WIDTH * percent / 100)
        bar = "#" * filled + "-" * (self._BAR_WIDTH - filled)
        text = f"  {phase} [{bar}] {percent:5.1f}%  {detail}".rstrip()
        if self._interactive:
            self._echo("\r" + text.ljust(self._LINE_WIDTH))
            self._open_line = True
        else:
            self._echo(text + "\n")

    def _should_log(self, phase: str, percent: float) -> bool:
        """Redirected output gets one line per phase per 10% step. nmap's
        --stats-every cadence would otherwise bury the rest of the log."""
        bucket = (phase, int(percent // 10))
        if bucket == self._last_bucket:
            return False
        self._last_bucket = bucket
        return True


def _echo_without_newline(text: str) -> None:
    typer.echo(text, nl=False)


class SnmpTranscriptRenderer:
    """Print each SNMP request as it happens, MIB-browser style.

    Unlike the port scan there is no progress to report -- individual requests
    finish in milliseconds -- so what is worth showing is the *sequence*: which
    account asked for what, and what the agent answered. That makes the parts
    of an `snmp_set` validation that have no other trace visible, namely the
    read of the original value, the read-back after the write, and the restore.

    A header is printed whenever the account or endpoint changes, which is
    what separates the read-write half of a testcase from the read-only half.
    """

    _VALUE_WIDTH = 46

    def __init__(self, echo: Callable[[str], None] | None = None) -> None:
        self._echo = echo if echo is not None else typer.echo
        self._context: tuple[str, str] | None = None

    def handle(self, exchange: "SnmpExchange") -> None:
        context = (exchange.endpoint, exchange.profile)
        if context != self._context:
            self._echo(f"  snmp: {exchange.profile} -> {exchange.endpoint}")
            self._context = context
        request = exchange.oid
        if exchange.written is not None:
            request = f"{request} = {exchange.written}"
        self._echo(
            f"    {exchange.operation:<3} {request:<28} "
            f"{_outcome(exchange.result):<{self._VALUE_WIDTH}} ({exchange.seconds:.2f}s)".rstrip()
        )


def _outcome(result: "SnmpResult") -> str:
    """One-line verdict. A refusal is spelled out because for the read-only
    account it is the expected result, not a problem."""
    if result.ok:
        return _clip(result.value or "(empty)")
    if result.unanswered:
        return "-> no response"
    if result.denied:
        return f"-> refused: {_clip(_first_line(result.detail), 34)}"
    return f"-> error: {_clip(_first_line(result.detail), 36)}"


def _first_line(text: str) -> str:
    return next((line.strip() for line in text.splitlines() if line.strip()), text.strip())


def _clip(text: str, limit: int = 42) -> str:
    # Plain dots rather than an ellipsis character: this lands on a Korean
    # Windows console, whose code page does not reliably carry U+2026.
    return text if len(text) <= limit else text[: limit - 3] + "..."
