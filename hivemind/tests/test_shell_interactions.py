from __future__ import annotations

from pathlib import Path

from hive_protocol.product.shell_views import render_shell_page


def _render(slug: str, projection: dict | None = None) -> str:
    return render_shell_page(
        slug,
        projection or {"project_id": "HiveMind"},
        object_version="a" * 64,
    ).decode("utf-8")


def test_nontechnical_pages_expose_every_primary_lane_without_raw_json() -> None:
    expected_actions = {
        "capture": {"capture.preview", "capture.admit"},
        "research": {
            "research.workspaces.create",
            "research.sources.add",
            "research.sources.remove",
            "research.search",
            "research.ask",
            "research.artifacts.create",
            "research.export",
        },
        "memory": {
            "memory.propose",
            "memory.review",
            "memory.promote",
            "memory.correct",
            "memory.revoke",
            "memory.retention.scan",
            "memory.deletion.preview",
            "memory.deletion.approve",
            "memory.deletion.apply",
        },
        "knowledge": {
            "knowledge.notes.preview",
            "knowledge.notes.approve",
            "knowledge.notes.apply",
            "knowledge.graph.rebuild",
        },
        "workflows": {
            "workflows.definitions.preview",
            "workflows.definitions.publish",
            "workflows.runs.launch",
            "workflows.readiness",
            "workflows.approvals.preview",
            "workflows.approvals.approve",
            "workflows.retries.create",
            "workflows.rollback.preview",
            "workflows.rollback.apply",
            "workflows.runs.complete",
        },
        "agents": {
            "agents.capabilities.authorize",
            "agents.register",
            "agents.tasks.submit",
        },
        "settings": {
            "settings.provider.preview",
            "settings.provider.apply",
            "settings.adapters.plan",
            "settings.adapters.invoke",
            "settings.lifecycle.preview",
            "settings.lifecycle.approve",
            "settings.lifecycle.apply",
            "settings.snapshot",
            "settings.export",
            "settings.reopen",
            "settings.rollback",
        },
    }

    for slug, actions in expected_actions.items():
        rendered = _render(slug)
        for action in actions:
            assert f'data-action="{action}"' in rendered
        assert 'name="json"' not in rendered
        assert 'name="command"' not in rendered
        assert "Paste JSON" not in rendered
        assert "Raw JSON" not in rendered

    receipts = _render("receipts")
    assert 'data-read-route="/api/v1/receipts"' in receipts
    assert "Verification state" in receipts


def test_preview_approval_apply_and_destructive_steps_are_distinct_controls() -> None:
    for slug, stages in {
        "capture": ("capture.preview", "capture.admit"),
        "memory": (
            "memory.deletion.preview",
            "memory.deletion.approve",
            "memory.deletion.apply",
        ),
        "knowledge": (
            "knowledge.notes.preview",
            "knowledge.notes.approve",
            "knowledge.notes.apply",
        ),
        "workflows": (
            "workflows.approvals.preview",
            "workflows.approvals.approve",
            "workflows.rollback.preview",
            "workflows.rollback.apply",
        ),
        "settings": (
            "settings.provider.preview",
            "settings.provider.apply",
            "settings.lifecycle.preview",
            "settings.lifecycle.approve",
            "settings.lifecycle.apply",
            "settings.rollback",
        ),
    }.items():
        rendered = _render(slug)
        positions = [rendered.index(f'data-action="{stage}"') for stage in stages]
        assert len(positions) == len(set(positions))

    for slug in ("memory", "workflows", "settings"):
        rendered = _render(slug)
        assert 'data-typed-confirmation="true"' in rendered
        assert 'name="confirmation"' in rendered


def test_browser_controller_is_ephemeral_replay_safe_and_focus_safe() -> None:
    repository = Path(__file__).parents[1]
    script = (
        repository / "src/hive_protocol/product/static/app.js"
    ).read_text(encoding="utf-8")

    for required in (
        'fetch("/api/v1/session"',
        '"X-Hive-CSRF"',
        '"X-Hive-Idempotency-Key"',
        '"If-Match"',
        "crypto.randomUUID()",
        "pendingForms",
        "button.disabled = true",
        "button.disabled = false",
        "errorSummary.focus()",
        "bindings.clear()",
        "textContent",
        "data-object-version",
    ):
        assert required in script
    for forbidden in (
        "localStorage",
        "sessionStorage",
        "indexedDB",
        "serviceWorker",
        "document.cookie",
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "eval(",
    ):
        assert forbidden not in script


def test_new_graph_modules_and_packaging_inventory_are_exact() -> None:
    repository = Path(__file__).parents[1]
    knowledge = (
        repository / "src/hive_protocol/product/static/knowledge.js"
    ).read_text(encoding="utf-8")
    workflows = (
        repository / "src/hive_protocol/product/static/workflows.js"
    ).read_text(encoding="utf-8")
    server = (repository / "src/hive_protocol/product/shell_views.py").read_text(
        encoding="utf-8"
    )
    build = (repository / "scripts/build-alpha.sh").read_text(encoding="utf-8")
    sanitizer = (
        repository / "scripts/sanitize_product_wheel.py"
    ).read_text(encoding="utf-8")

    for source in (knowledge, workflows):
        assert "createElementNS" in source
        assert 'addEventListener("keydown"' in source
        assert "textContent" in source
        assert "innerHTML" not in source
    for asset in ("knowledge.js", "workflows.js"):
        assert f'"/static/{asset}"' in server
        assert f'"hive_protocol/product/static/{asset}"' in build
        assert f'"hive_protocol/product/static/{asset}"' in sanitizer
