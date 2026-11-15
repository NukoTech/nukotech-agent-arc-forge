from __future__ import annotations

import http.cookiejar
import urllib.error
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

import pytest

from hive_protocol.product.api import OperatorAPI
from hive_protocol.product.server import make_server
from hive_protocol.product.shell_service import ShellService
from hive_protocol.product.shell_views import PAGE_DEFINITIONS, render_shell_page
from hive_protocol.product.workspace import HiveWorkspace


class _SemanticParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        self.tags.append((tag, dict(attrs)))


def _request(opener: urllib.request.OpenerDirector, url: str):
    return opener.open(
        urllib.request.Request(url, headers={"Sec-Fetch-Site": "same-origin"}),
        timeout=5,
    )


def test_every_page_has_one_semantic_shell_and_escapes_all_projection_text() -> None:
    attack = '</script><script>alert("owned")</script><style>body{display:none}</style>'
    projection = {
        "project_id": f"HiveMind {attack}",
        "health": "HEALTHY",
        "status": {"label": attack, "state": "BLOCKED"},
        "items": [{"name": attack, "technical_evidence": [attack]}],
        "technical_evidence": [attack],
    }

    for slug, page in PAGE_DEFINITIONS.items():
        rendered = render_shell_page(slug, projection, object_version="a" * 64).decode()
        parser = _SemanticParser()
        parser.feed(rendered)

        assert rendered.startswith("<!doctype html>")
        assert rendered.count("<main ") == 1
        assert rendered.count("<h1") == 1
        assert '<a class="skip-link" href="#main-content">Skip to main content</a>' in rendered
        assert '<nav aria-label="Primary">' in rendered
        assert '<nav aria-label="Breadcrumb">' in rendered
        assert 'id="project-status" role="status"' in rendered
        assert 'id="request-status" role="status" aria-live="polite"' in rendered
        assert 'id="error-summary" role="alert" tabindex="-1" hidden' in rendered
        assert '<details class="technical-evidence">' in rendered
        assert '<label for="global-search">Search this Hive</label>' in rendered
        assert 'aria-describedby="global-search-help"' in rendered
        assert '<div id="global-search-results" aria-live="polite"></div>' in rendered
        assert '<link rel="stylesheet" href="/static/app.css">' in rendered
        assert '<script type="module" src="/static/app.js"></script>' in rendered
        assert rendered.count("<script") == 1
        assert rendered.count("<style") == 0
        assert attack not in rendered
        assert "&lt;/script&gt;&lt;script&gt;" in rendered
        assert page.title in rendered

        main = [attrs for tag, attrs in parser.tags if tag == "main"]
        assert main == [{"id": "main-content", "tabindex": "-1"}]


def test_shell_navigation_exposes_all_read_only_pages_without_javascript(
    tmp_path: Path,
) -> None:
    workspace = HiveWorkspace.create(tmp_path / "hive")
    server = make_server(workspace, "127.0.0.1", 0)
    import threading

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    cookies = http.cookiejar.CookieJar()
    browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
    try:
        with browser.open(
                urllib.request.Request(
                    f"http://127.0.0.1:{port}{server.launch_path}",
                headers={"Sec-Fetch-Site": "none"},
            ),
            timeout=5,
        ):
            pass

        for slug, page in PAGE_DEFINITIONS.items():
            path = "/app" if slug == "home" else f"/app/{slug}"
            with _request(browser, f"http://127.0.0.1:{port}{path}") as response:
                body = response.read().decode("utf-8")
            assert response.status == 200
            assert response.headers["Content-Type"] == "text/html; charset=utf-8"
            assert response.headers["Cache-Control"] == "no-store"
            assert page.title in body
            assert "Technical evidence" in body
            assert "application/json" not in body

        settings = _request(browser, f"http://127.0.0.1:{port}/app/settings")
        settings_body = settings.read().decode("utf-8")
        assert "Provider" in settings_body
        assert "Configured; provider not running" in settings_body
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert not thread.is_alive()


def test_static_assets_are_exact_hashed_packaged_and_browser_ephemeral(
    tmp_path: Path,
) -> None:
    workspace = HiveWorkspace.create(tmp_path / "hive")
    server = make_server(workspace, "127.0.0.1", 0)
    import threading

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    cookies = http.cookiejar.CookieJar()
    browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
    try:
        with browser.open(
                urllib.request.Request(
                    f"http://127.0.0.1:{port}{server.launch_path}",
                headers={"Sec-Fetch-Site": "none"},
            ),
            timeout=5,
        ):
            pass
        for asset, content_type in (
            ("app.css", "text/css; charset=utf-8"),
            ("app.js", "text/javascript; charset=utf-8"),
            ("knowledge.js", "text/javascript; charset=utf-8"),
            ("workflows.js", "text/javascript; charset=utf-8"),
        ):
            with _request(
                browser, f"http://127.0.0.1:{port}/static/{asset}"
            ) as response:
                body = response.read()
                etag = response.headers["ETag"]
                assert response.status == 200
                assert response.headers["Content-Type"] == content_type
                assert response.headers["Cache-Control"] == "public, max-age=31536000, immutable"
                assert etag.startswith('"sha256-') and etag.endswith('"')
                assert body
            conditional = urllib.request.Request(
                f"http://127.0.0.1:{port}/static/{asset}",
                headers={"Sec-Fetch-Site": "same-origin", "If-None-Match": etag},
            )
            with pytest.raises(urllib.error.HTTPError) as unchanged:
                browser.open(conditional, timeout=5)
            assert unchanged.value.code == 304

        script = _request(
            browser, f"http://127.0.0.1:{port}/static/app.js"
        ).read().decode("utf-8")
        for forbidden in (
            "localStorage",
            "sessionStorage",
            "indexedDB",
            "serviceWorker",
            "document.cookie",
        ):
            assert forbidden not in script

        stylesheet = _request(
            browser, f"http://127.0.0.1:{port}/static/app.css"
        ).read().decode("utf-8")
        for required in (
            ":focus-visible",
            "prefers-reduced-motion",
            "min-height: 44px",
            "@media",
        ):
            assert required in stylesheet

        for denied_path in (
            "/static/app.CSS",
            "/static/app.css/",
            "/static/../server.py",
            "/static/%2e%2e/server.py",
            "/static/app.js?alias=1",
            "/static/knowledge.js?alias=1",
            "/static/workflows.js/",
        ):
            with pytest.raises(urllib.error.HTTPError) as denied:
                _request(browser, f"http://127.0.0.1:{port}{denied_path}")
            assert denied.value.code == 404
            assert str(workspace.root) not in denied.value.read().decode("utf-8")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_shell_refuses_ambiguous_project_scope_without_issuing_a_session(
    tmp_path: Path,
) -> None:
    workspace = HiveWorkspace.create(tmp_path / "hive")
    projects = {"HiveMind", "OtherProject"}
    api = OperatorAPI(
        workspace.root,
        ShellService(workspace, tenant_id="local-user", project_ids=projects),
        tenant_id="local-user",
        project_ids=projects,
    )
    server = make_server(workspace, "127.0.0.1", 0, operator_api=api)
    import threading

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{server.server_address[1]}{server.launch_path}",
            headers={"Sec-Fetch-Site": "none"},
        )
        with pytest.raises(urllib.error.HTTPError) as denied:
            urllib.request.urlopen(request, timeout=5)
        assert denied.value.code == 403
        assert denied.value.headers.get("Set-Cookie") is None
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
