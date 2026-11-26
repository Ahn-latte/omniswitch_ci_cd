import sys
import types

import pytest

from switchtest.exceptions import ValidationExecutionError
from switchtest.infrastructure.web_probe import check_tls_restricted_unreachable


class FakePlaywrightError(Exception):
    pass


def _install_fake_playwright(monkeypatch, loads):
    """`loads(prefs)` decides whether a Firefox launched with `prefs` can
    load the page. Records every launch's prefs so tests can check the
    control really ran unpinned."""
    launches: list[dict] = []

    class Page:
        def __init__(self, prefs):
            self._prefs = prefs

        def goto(self, url, timeout):
            if not loads(self._prefs):
                raise FakePlaywrightError("SSL_ERROR_UNSUPPORTED_VERSION")

    class Browser:
        def __init__(self, prefs):
            self._prefs = prefs

        def new_page(self, ignore_https_errors):
            return Page(self._prefs)

        def close(self):
            pass

    class Firefox:
        def launch(self, firefox_user_prefs):
            launches.append(firefox_user_prefs)
            return Browser(firefox_user_prefs)

    class Playwright:
        firefox = Firefox()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    module = types.ModuleType("playwright.sync_api")
    module.Error = FakePlaywrightError
    module.TimeoutError = FakePlaywrightError
    module.sync_playwright = Playwright
    monkeypatch.setitem(sys.modules, "playwright", types.ModuleType("playwright"))
    monkeypatch.setitem(sys.modules, "playwright.sync_api", module)
    return launches


def _pinned(prefs) -> bool:
    return "security.tls.version.max" in prefs


def test_refused_when_pinned_but_loading_unpinned_is_a_pass(monkeypatch) -> None:
    launches = _install_fake_playwright(monkeypatch, loads=lambda prefs: not _pinned(prefs))

    refused, detail = check_tls_restricted_unreachable("192.0.2.1", 443, tls_version="1.1")

    assert refused is True
    assert "SSL_ERROR_UNSUPPORTED_VERSION" in detail
    # Control first, unpinned; then the pinned attempt at exactly 1.1 (pref 2).
    assert launches == [
        {},
        {"security.tls.version.min": 2, "security.tls.version.max": 2},
    ]


def test_an_unreachable_webview_is_an_error_not_a_pass(monkeypatch) -> None:
    """The regression: WebView down / port closed used to read as "the
    downgraded handshake was refused"."""
    launches = _install_fake_playwright(monkeypatch, loads=lambda prefs: False)

    with pytest.raises(ValidationExecutionError, match="never tested"):
        check_tls_restricted_unreachable("192.0.2.1", 443, tls_version="1.0")

    # It stops at the control -- no point attempting the pinned load.
    assert launches == [{}]


def test_loading_even_when_pinned_is_a_fail(monkeypatch) -> None:
    _install_fake_playwright(monkeypatch, loads=lambda prefs: True)

    refused, detail = check_tls_restricted_unreachable("192.0.2.1", 443, tls_version="1.1")

    assert refused is False
    assert "accepted a downgraded handshake" in detail
