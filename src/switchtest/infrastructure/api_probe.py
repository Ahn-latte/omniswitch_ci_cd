"""Attempt a real request against the switch's JSON/WebView HTTP API.

`web_unreachable` proves a *browser* can't load WebView; this proves an *API
client* can't reach it either. They are the same listener on this device, but
the testcase's claim is that every management path is down, and evidence for
each path is worth having separately -- a management script talking to
`/cli/aos` fails differently from a browser, and only one of the two shows up
in a report as "the API timed out".

Uses the standard library's http.client rather than httpx/requests so the
check adds no dependency (omniswitch_api_poc, which exercises the API for
real, is where the full client lives).

The probed path never carries credentials. Hitting the auth endpoint with a
throwaway username would count as a failed login against that account's
lockout threshold, which is exactly what the lockout testcases in this repo
are careful not to spend.
"""

import http.client
import socket
import ssl

from switchtest.exceptions import ValidationExecutionError


def check_api_unreachable(
    target: str, port: int, path: str = "/", timeout: int = 20
) -> tuple[bool, str]:
    """Return (unreachable, detail).

    True means the request could not be completed -- timed out, refused, or
    the TLS handshake never happened -- which is what a disabled service looks
    like to an API client. False means the switch answered, whatever the status
    code: a 401 is still proof the service is up and listening.
    """
    if not target:
        raise ValidationExecutionError("API check validation requires a target")
    if not port:
        raise ValidationExecutionError("API check validation requires a port")
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{target}:{port}{path}"
    connection: http.client.HTTPConnection | None = None
    try:
        if scheme == "https":
            # The switch uses a self-signed certificate; certificate validity
            # is not what this check is about (see the tls_version validation
            # for that), reachability is.
            connection = http.client.HTTPSConnection(
                target, port, timeout=timeout, context=ssl._create_unverified_context()
            )
        else:
            connection = http.client.HTTPConnection(target, port, timeout=timeout)
        connection.request("GET", path, headers={"Accept": "application/json"})
        response = connection.getresponse()
        response.read()
        return False, (
            f"GET {url} answered HTTP {response.status} {response.reason} "
            f"(the API is still reachable)"
        )
    except (TimeoutError, socket.timeout):
        return True, f"GET {url} timed out after {timeout}s (dropped)"
    except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
        return True, f"GET {url} failed as expected: {type(exc).__name__}: {exc}"
    finally:
        if connection is not None:
            connection.close()
