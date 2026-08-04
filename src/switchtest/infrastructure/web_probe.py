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
