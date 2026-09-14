from switchtest.exceptions import ValidationExecutionError


def check_web_unreachable(target: str, port: int, timeout: int = 30) -> tuple[bool, str]:
    """Navigate a headless Chromium browser to http(s)://target:port/ and report
    whether the connection was refused/timed out (True: unreachable, matches a
    disabled service) or a response was actually received (False: still reachable).

    Scheme is inferred from the port (443 -> https, otherwise http) since the
    services under test are the switch's plain HTTP and WebView HTTPS listeners.

    Imports playwright lazily: it's an optional (`[web]`) dependency, and this
    module is imported unconditionally by validation_service, so a top-level
    import would break every other validation type for anyone who hasn't
    installed the extra.
    """
    if not target:
        raise ValidationExecutionError("Web check validation requires a target")
    if not port:
        raise ValidationExecutionError("Web check validation requires a port")
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise ValidationExecutionError(
            "playwright is not installed (pip install -e .[web] && playwright install chromium)"
        ) from exc
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{target}:{port}/"
    with sync_playwright() as playwright:
        try:
            browser = playwright.chromium.launch()
        except Exception as exc:
            raise ValidationExecutionError(
                f"Could not launch Chromium (run `playwright install chromium`): {exc}"
            ) from exc
        try:
            page = browser.new_page(ignore_https_errors=True)
            try:
                page.goto(url, timeout=timeout * 1000)
            except (PlaywrightError, PlaywrightTimeoutError) as exc:
                return True, f"Navigation to {url} failed as expected: {exc}"
            return False, f"Navigation to {url} succeeded (service is still reachable)"
        finally:
            browser.close()


_FIREFOX_TLS_VERSION_PREF = {"1.0": 1, "1.1": 2, "1.2": 3, "1.3": 4}


def check_tls_restricted_unreachable(
    target: str, port: int, tls_version: str = "1.1", timeout: int = 30
) -> tuple[bool, str]:
    """Navigate Firefox to https://target:port/ with the browser's own TLS
    range pinned to exactly `tls_version` (min == max), and report whether
    the handshake was refused.

    Firefox rather than Chromium: Chromium dropped the ability to force a
    maximum TLS version years ago, so it always negotiates whatever the
    server's highest supported version is regardless of what's asked for --
    silently proving nothing. Firefox still exposes the range as ordinary
    preferences (`security.tls.version.min`/`.max`), settable per-launch via
    `firefox_user_prefs`, so this is the one browser that can actually
    attempt (and fail) a downgraded handshake instead of just ignoring the
    request.

    Returns (unreachable, detail): True means the handshake failed (matches
    a switch that requires TLS 1.2+), False means it succeeded (the switch
    accepted the downgraded version).
    """
    if not target:
        raise ValidationExecutionError("TLS-restricted web check requires a target")
    if not port:
        raise ValidationExecutionError("TLS-restricted web check requires a port")
    if tls_version not in _FIREFOX_TLS_VERSION_PREF:
        raise ValidationExecutionError(
            f"Unsupported tls_version {tls_version!r} "
            f"(expected one of {sorted(_FIREFOX_TLS_VERSION_PREF)})"
        )
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise ValidationExecutionError(
            "playwright is not installed (pip install -e .[web] && playwright install firefox)"
        ) from exc
    pin = _FIREFOX_TLS_VERSION_PREF[tls_version]
    url = f"https://{target}:{port}/"
    with sync_playwright() as playwright:
        try:
            browser = playwright.firefox.launch(
                firefox_user_prefs={
                    "security.tls.version.min": pin,
                    "security.tls.version.max": pin,
                }
            )
        except Exception as exc:
            raise ValidationExecutionError(
                f"Could not launch Firefox (run `playwright install firefox`): {exc}"
            ) from exc
        try:
            page = browser.new_page(ignore_https_errors=True)
            try:
                page.goto(url, timeout=timeout * 1000)
            except (PlaywrightError, PlaywrightTimeoutError) as exc:
                return True, (
                    f"Navigation to {url} pinned to TLS {tls_version} failed as expected: {exc}"
                )
            return False, (
                f"Navigation to {url} pinned to TLS {tls_version} succeeded "
                f"(the switch accepted a downgraded handshake)"
            )
        finally:
            browser.close()
