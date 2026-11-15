from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

from hive_protocol.product.shell_views import PAGE_DEFINITIONS, render_shell_page


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.controls: list[tuple[str, dict[str, str | None]]] = []
        self.labels: set[str] = set()
        self.form_count = 0
        self.fieldset_count = 0
        self.legend_count = 0

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        attributes = dict(attrs)
        if tag in {"input", "select", "textarea"}:
            self.controls.append((tag, attributes))
        elif tag == "label" and attributes.get("for"):
            self.labels.add(str(attributes["for"]))
        elif tag == "form":
            self.form_count += 1
        elif tag == "fieldset":
            self.fieldset_count += 1
        elif tag == "legend":
            self.legend_count += 1


def test_every_interactive_control_is_labeled_described_and_grouped() -> None:
    for slug in PAGE_DEFINITIONS:
        rendered = render_shell_page(
            slug,
            {"project_id": "HiveMind"},
            object_version="a" * 64,
        ).decode("utf-8")
        parser = _FormParser()
        parser.feed(rendered)

        for tag, attributes in parser.controls:
            if tag == "input" and attributes.get("type") == "hidden":
                continue
            control_id = attributes.get("id")
            assert control_id, (slug, tag, attributes)
            assert control_id in parser.labels, (slug, control_id)
            assert attributes.get("aria-describedby"), (slug, control_id)
        assert parser.fieldset_count == parser.form_count
        assert parser.legend_count == parser.form_count
        assert not re.search(r'tabindex="[1-9]', rendered)
        assert 'aria-live="polite"' in rendered
        assert 'role="alert"' in rendered


def test_knowledge_and_workflow_visuals_keep_complete_keyboard_tables() -> None:
    knowledge = render_shell_page(
        "knowledge",
        {
            "project_id": "HiveMind",
            "nodes": [
                {
                    "node_id": "node:one",
                    "title": "One",
                    "tags": ["local"],
                    "outgoing_links": ["node:two"],
                },
                {
                    "node_id": "node:two",
                    "title": "Two",
                    "tags": [],
                    "outgoing_links": [],
                },
            ],
        },
        object_version="a" * 64,
    ).decode("utf-8")
    assert 'data-knowledge-table="true"' in knowledge
    assert 'data-knowledge-graph="true"' in knowledge
    assert "Node relationships" in knowledge
    assert "node:one" in knowledge and "node:two" in knowledge

    workflows = render_shell_page(
        "workflows",
        {
            "project_id": "HiveMind",
            "workflows": [
                {
                    "definition": {
                        "workflow_id": "workflow:one",
                        "steps": [
                            {"step_id": "first", "depends_on": []},
                            {"step_id": "second", "depends_on": ["first"]},
                        ],
                    }
                }
            ],
        },
        object_version="b" * 64,
    ).decode("utf-8")
    assert 'data-workflow-table="true"' in workflows
    assert 'data-workflow-graph="true"' in workflows
    assert "Step dependencies" in workflows
    assert "first" in workflows and "second" in workflows


def test_dialog_focus_selection_reflow_and_reduced_motion_contracts() -> None:
    rendered = render_shell_page(
        "settings", {"project_id": "HiveMind"}, object_version="a" * 64
    ).decode("utf-8")
    assert '<dialog id="confirmation-dialog"' in rendered
    assert 'aria-labelledby="confirmation-title"' in rendered
    assert 'data-dialog-cancel="true"' in rendered

    repository = Path(__file__).parents[1]
    css = (repository / "src/hive_protocol/product/static/app.css").read_text(
        encoding="utf-8"
    )
    js = (repository / "src/hive_protocol/product/static/app.js").read_text(
        encoding="utf-8"
    )
    for required in (
        ":focus-visible",
        "[aria-current",
        "[aria-selected",
        "prefers-reduced-motion",
        "min-height: 44px",
        "overflow-wrap",
        "dialog",
    ):
        assert required in css
    for required in (
        "showModal()",
        "returnFocus.focus()",
        'addEventListener("close"',
        'addEventListener("cancel"',
    ):
        assert required in js
