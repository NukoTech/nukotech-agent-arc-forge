from __future__ import annotations

import http.cookiejar
import io
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from hive_protocol.core import ProtocolError
from hive_protocol.product.cli import main
from hive_protocol.product.server import make_server
from hive_protocol.product.workspace import HiveWorkspace


class ProductShellTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        source = self.root / "source.md"
        source.write_text("# Alpha\n\nlocal privacy graph\n", encoding="utf-8")
        self.workspace = HiveWorkspace.create(self.root / "hive")
        self.workspace.import_content(source)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_loopback_surface_exposes_status_search_graph_and_receipts(self) -> None:
        with patch.object(
            self.workspace,
            "provider_status",
            return_value={"provider": "none", "available": False, "model": None},
        ):
            server = make_server(self.workspace, "127.0.0.1", 0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                for endpoint in (
                    "/api/status",
                    "/api/search?q=privacy",
                    "/api/graph",
                    "/api/receipts",
                ):
                    request = urllib.request.Request(
                        f"http://127.0.0.1:{port}{endpoint}",
                        headers={
                            "Authorization": (
                                f"Bearer {server.access_token}"  # type: ignore[attr-defined]
                            )
                        },
                    )
                    with urllib.request.urlopen(request, timeout=5) as response:
                        self.assertEqual(response.status, 200)
                        payload = json.loads(response.read().decode("utf-8"))
                        self.assertIsInstance(payload, dict)
                cookies = http.cookiejar.CookieJar()
                browser = urllib.request.build_opener(
                    urllib.request.HTTPCookieProcessor(cookies)
                )
                app_request = urllib.request.Request(
                    f"http://127.0.0.1:{port}{server.launch_path}",  # type: ignore[attr-defined]
                    headers={"Sec-Fetch-Site": "none"},
                )
                with browser.open(app_request, timeout=5) as response:
                    page = response.read().decode("utf-8")
                    self.assertEqual(response.headers["Cache-Control"], "no-store")
                session_cookie = next(iter(cookies))
                self.assertTrue(session_cookie.has_nonstandard_attr("HttpOnly"))
                self.assertEqual(
                    session_cookie.get_nonstandard_attr("SameSite"), "Strict"
                )
                self.assertIn("NukoTech HiveMind", page)
                self.assertIn("<span>Alpha</span>", page)
                self.assertIn("Agents", page)
                self.assertIn("Tasks", page)
                self.assertNotIn(server.access_token, page)  # type: ignore[attr-defined]
                self.assertEqual(page.count("<script"), 1)
                self.assertIn('src="/static/app.js"', page)
                self.assertNotIn("<style", page)

                session_request = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/v1/session",
                    headers={"Sec-Fetch-Site": "same-origin"},
                )
                with browser.open(session_request, timeout=5) as response:
                    session = json.loads(response.read().decode("utf-8"))
                self.assertEqual(
                    session["schema_version"], "hive.operator-response.v1"
                )
                self.assertIn("csrf_proof", session["data"])
                home_request = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/v1/home?project_id=HiveMind",
                    headers={"Sec-Fetch-Site": "same-origin"},
                )
                with browser.open(home_request, timeout=5) as response:
                    home = json.loads(response.read().decode("utf-8"))
                self.assertEqual(home["outcome"], "OK")
                self.assertEqual(home["data"]["project_id"], "HiveMind")
                self.assertEqual(home["changed"], False)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_non_loopback_bind_is_refused(self) -> None:
        for host in ("0.0.0.0", "localhost"):
            with self.subTest(host=host):
                with self.assertRaisesRegex(ProtocolError, "WEB_BIND_DENIED"):
                    make_server(self.workspace, host, 0)

    def test_surface_requires_process_scoped_token(self) -> None:
        server = make_server(self.workspace, "127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with self.assertRaises(urllib.error.HTTPError) as denied:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{server.server_address[1]}/api/status", timeout=5
                )
            self.assertEqual(denied.exception.code, 401)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_browser_session_requires_one_time_launch_handoff(self) -> None:
        server = make_server(self.workspace, "127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        base_url = f"http://127.0.0.1:{port}"
        try:
            forged = urllib.request.Request(
                f"{base_url}/app",
                headers={"Sec-Fetch-Site": "none"},
            )
            with self.assertRaises(urllib.error.HTTPError) as denied:
                urllib.request.urlopen(forged, timeout=5)
            self.assertEqual(denied.exception.code, 401)
            self.assertIsNone(denied.exception.headers.get("Set-Cookie"))

            cookies = http.cookiejar.CookieJar()
            browser = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(cookies)
            )
            launch_path = server.launch_path  # type: ignore[attr-defined]
            launch_url = f"{base_url}{launch_path}"
            with browser.open(
                urllib.request.Request(
                    launch_url,
                    headers={"Sec-Fetch-Site": "none"},
                ),
                timeout=5,
            ) as response:
                page = response.read().decode("utf-8")
                self.assertEqual(response.geturl(), f"{base_url}/app")
            self.assertTrue(cookies)
            self.assertNotIn(launch_path, page)

            replay = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
            )
            with self.assertRaises(urllib.error.HTTPError) as consumed:
                replay.open(
                    urllib.request.Request(
                        launch_url,
                        headers={"Sec-Fetch-Site": "none"},
                    ),
                    timeout=5,
                )
            self.assertEqual(consumed.exception.code, 401)
            self.assertIsNone(consumed.exception.headers.get("Set-Cookie"))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_token_query_cross_site_host_rebinding_and_cors_are_refused(self) -> None:
        server = make_server(self.workspace, "127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            denied_requests = (
                urllib.request.Request(f"http://127.0.0.1:{port}/app"),
                urllib.request.Request(
                    f"http://127.0.0.1:{port}/app?token=forbidden",
                    headers={"Sec-Fetch-Site": "none"},
                ),
                urllib.request.Request(
                    f"http://127.0.0.1:{port}/app",
                    headers={"Sec-Fetch-Site": "cross-site"},
                ),
                urllib.request.Request(
                    f"http://127.0.0.1:{port}/app",
                    headers={"Host": "evil.example", "Sec-Fetch-Site": "none"},
                ),
                urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/v1/session",
                    method="OPTIONS",
                    headers={
                        "Origin": "http://evil.example",
                        "Access-Control-Request-Method": "POST",
                    },
                ),
            )
            for request in denied_requests:
                with self.subTest(url=request.full_url, method=request.get_method()):
                    with self.assertRaises(urllib.error.HTTPError) as denied:
                        urllib.request.urlopen(request, timeout=5)
                    refusal = json.loads(denied.exception.read().decode("utf-8"))
                    self.assertEqual(
                        refusal["schema_version"], "hive.operator-response.v1"
                    )
                    self.assertNotIn(
                        "Access-Control-Allow-Origin", denied.exception.headers
                    )
                    self.assertIn(
                        "frame-ancestors 'none'",
                        denied.exception.headers["Content-Security-Policy"],
                    )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_malformed_browser_capture_is_refused_before_domain_mutation(self) -> None:
        server = make_server(self.workspace, "127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        cookies = http.cookiejar.CookieJar()
        browser = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cookies)
        )
        try:
            with browser.open(
                urllib.request.Request(
                    f"http://127.0.0.1:{port}{server.launch_path}",  # type: ignore[attr-defined]
                    headers={"Sec-Fetch-Site": "none"},
                ),
                timeout=5,
            ):
                pass
            with browser.open(
                urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/v1/session",
                    headers={"Sec-Fetch-Site": "same-origin"},
                ),
                timeout=5,
            ) as response:
                csrf = json.loads(response.read().decode("utf-8"))["data"][
                    "csrf_proof"
                ]

            body = json.dumps(
                {
                    "schema_version": "hive.operator-request.v1",
                    "request_id": "7ac44295-4758-4f1b-a2ce-6e9993e86f10",
                    "tenant_id": "local-user",
                    "project_id": "HiveMind",
                    "action": "capture.preview",
                    "expected_version": "ABSENT",
                    "idempotency_key": "operator-request-0001",
                    "input": {},
                }
            ).encode("utf-8")
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/v1/capture/preview",
                data=body,
                method="POST",
                headers={
                    "Origin": f"http://127.0.0.1:{port}",
                    "Sec-Fetch-Site": "same-origin",
                    "Content-Type": "application/json",
                    "X-Hive-CSRF": csrf,
                    "X-Hive-Idempotency-Key": "operator-request-0001",
                    "If-Match": "ABSENT",
                },
            )
            with self.assertRaises(urllib.error.HTTPError) as pending:
                browser.open(request, timeout=5)
            self.assertEqual(pending.exception.code, 400)
            result = json.loads(pending.exception.read().decode("utf-8"))
            self.assertEqual(
                result["schema_version"], "hive.operator-response.v1"
            )
            self.assertEqual(result["reason_code"], "CAPTURE_UPLOAD_INVALID")
            self.assertEqual(
                list(server.operator_api.ledger_root.glob("*.json")),  # type: ignore[attr-defined]
                [],
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.assertEqual(server.session_store.count, 0)  # type: ignore[attr-defined]
        self.assertFalse(thread.is_alive())
        secret = server.access_token.encode("utf-8")  # type: ignore[attr-defined]
        for path in list(self.workspace.root.rglob("*")):
            if path.is_file() and not path.is_symlink():
                try:
                    self.assertNotIn(secret, path.read_bytes())
                except FileNotFoundError:
                    continue
        self.assertFalse(
            any(
                path.suffix in {".pid", ".service", ".socket"}
                for path in self.workspace.root.rglob("*")
            )
        )

    def test_m31_attended_commands_do_not_start_a_listener_or_service(self) -> None:
        with patch("hive_protocol.product.cli.make_server") as listener:
            result = main(
                [
                    "research-workspace-create",
                    "--vault",
                    str(self.workspace.root),
                    "--workspace-id",
                    "research:process-bounded",
                    "--name",
                    "Process Bounded",
                ]
            )
        self.assertEqual(result, 0)
        listener.assert_not_called()
        forbidden = {
            path
            for path in self.workspace.root.rglob("*")
            if path.suffix in {".pid", ".service", ".socket"}
        }
        self.assertEqual(forbidden, set())

    def test_foreground_commands_emit_and_open_only_a_credential_free_url(self) -> None:
        for command in ("serve", "app"):
            with self.subTest(command=command):
                server = Mock()
                server.server_address = ("127.0.0.1", 4567)
                server.access_token = "process-secret-value-that-must-never-print"
                server.launch_path = "/_hive/launch/launch-secret-value-that-must-never-print"
                server.serve_forever.side_effect = KeyboardInterrupt
                arguments = [
                    command,
                    "--vault",
                    str(self.workspace.root),
                    "--port",
                    "0",
                ]
                if command == "app":
                    arguments.append("--open")
                output = io.StringIO()
                with (
                    patch(
                        "hive_protocol.product.cli.make_server",
                        return_value=server,
                    ),
                    patch("webbrowser.open") as browser_open,
                    redirect_stdout(output),
                ):
                    result = main(arguments)
                self.assertEqual(result, 0)
                emitted = output.getvalue()
                self.assertIn("http://127.0.0.1:4567/app", emitted)
                self.assertNotIn(server.access_token, emitted)
                self.assertNotIn(server.launch_path, emitted)
                self.assertNotIn("?token=", emitted)
                if command == "app":
                    browser_open.assert_called_once_with(
                        f"http://127.0.0.1:4567{server.launch_path}"
                    )
                else:
                    browser_open.assert_not_called()
                server.server_close.assert_called_once_with()

    def test_app_can_handoff_launch_url_only_over_inherited_pipe(self) -> None:
        server = Mock()
        server.server_address = ("127.0.0.1", 4567)
        server.access_token = "process-secret-value-that-must-never-print"
        server.launch_path = "/_hive/launch/launch-secret-value-that-must-never-print"
        server.serve_forever.side_effect = KeyboardInterrupt
        read_fd, write_fd = os.pipe()
        output = io.StringIO()
        try:
            with (
                patch(
                    "hive_protocol.product.cli.make_server",
                    return_value=server,
                ),
                patch("webbrowser.open") as browser_open,
                redirect_stdout(output),
            ):
                result = main(
                    [
                        "app",
                        "--vault",
                        str(self.workspace.root),
                        "--port",
                        "0",
                        "--launch-handoff-fd",
                        str(write_fd),
                    ]
                )
            self.assertEqual(result, 0)
            handoff = os.read(read_fd, 4096).decode("utf-8")
            self.assertEqual(
                handoff,
                f"http://127.0.0.1:4567{server.launch_path}\n",
            )
            self.assertNotIn(server.launch_path, output.getvalue())
            browser_open.assert_not_called()
        finally:
            for descriptor in (read_fd, write_fd):
                try:
                    os.close(descriptor)
                except OSError:
                    pass


if __name__ == "__main__":
    unittest.main()
