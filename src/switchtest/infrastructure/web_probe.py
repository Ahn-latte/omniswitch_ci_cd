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

    A control navigation runs first, with Firefox's default TLS range (which
    includes 1.2). Without it, *any* navigation failure would read as "the
    downgraded handshake was refused" -- WebView admin-disabled, port 443
    closed, the host unreachable from this PC -- and the check would pass on
    a switch it never actually reached. If the control can't load the page,
    this raises instead: the TLS restriction was not tested.

    The pinned failure is then accepted whatever its error text, rather than
    only on a TLS-specific code: with the control having just loaded the same
    URL, the TLS range is the only thing that changed, and the exact string
    Playwright surfaces for a Firefox protocol-version failure is not
    something worth betting a false FAIL on. The text is kept in the detail.

    Returns (unreachable, detail): True means the pinned handshake failed
    while the unpinned one worked (a switch that refuses that version),
    False means the pinned one also succeeded (the switch accepted the
    downgraded version).
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
    navigation_errors = (PlaywrightError, PlaywrightTimeoutError)

    def navigate(prefs: dict | None) -> Exception | None:
        """Load `url` in a Firefox launched with `prefs`; the navigation
        error, or None if the page loaded. Prefs are per-launch, hence a
        browser per attempt."""
        try:
            browser = playwright.firefox.launch(firefox_user_prefs=prefs or {})
        except Exception as exc:
            raise ValidationExecutionError(
                f"Could not launch Firefox (run `playwright install firefox`): {exc}"
            ) from exc
        try:
            page = browser.new_page(ignore_https_errors=True)
            try:
                page.goto(url, timeout=timeout * 1000)
            except navigation_errors as exc:
                return exc
            return None
        finally:
            browser.close()

    with sync_playwright() as playwright:
        control_error = navigate(None)
        if control_error is not None:
            raise ValidationExecutionError(
                f"Could not load {url} even with Firefox's default TLS range (which allows "
                f"1.2) -- WebView is down or unreachable from here, so the TLS {tls_version} "
                f"restriction was never tested: {control_error}"
            )
        pinned_error = navigate(
            {"security.tls.version.min": pin, "security.tls.version.max": pin}
        )
    if pinned_error is not None:
        return True, (
            f"{url} loaded with the default TLS range but failed when pinned to TLS "
            f"{tls_version}: {pinned_error}"
        )
    return False, (
        f"Navigation to {url} pinned to TLS {tls_version} succeeded "
        f"(the switch accepted a downgraded handshake)"
    )
