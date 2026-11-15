#!/usr/bin/env python3
"""Reduce the product wheel to neutral runtime modules and remove LAB identity fixtures."""

from __future__ import annotations

import csv
import io
import os
import sys
import zipfile
from pathlib import Path


ALLOWED_RUNTIME = {
    "hive_protocol/__init__.py",
    "hive_protocol/core.py",
    "hive_protocol/storage.py",
}
ALLOWED_PREFIXES = (
    "hive_protocol/capture/",
    "hive_protocol/cognition/",
    "hive_protocol/knowledge/",
    "hive_protocol/loadouts/",
    "hive_protocol/operator/",
    "hive_protocol/product/",
    "hive_protocol/providers/",
    "hive_protocol/receipts/",
    "hive_protocol/research/",
    "hive_protocol/schemas/",
    "hive_protocol/tasks/",
    "hive_protocol/workflows/",
)
ALLOWED_OPTIONAL_MODULES = {
    "hive_protocol/agents.py",
    "hive_protocol/ask.py",
    "hive_protocol/awareness.py",
    "hive_protocol/retrieval.py",
}
ALLOWED_ADAPTER_MODULES = {
    "hive_protocol/adapters/__init__.py",
    "hive_protocol/adapters/authority.py",
    "hive_protocol/adapters/base.py",
    "hive_protocol/adapters/execution.py",
    "hive_protocol/adapters/lifecycle.py",
    "hive_protocol/adapters/lifecycle_state.py",
    "hive_protocol/adapters/manifest.py",
    "hive_protocol/adapters/models.py",
    "hive_protocol/adapters/policy.py",
    "hive_protocol/adapters/registry.py",
    "hive_protocol/adapters/runtime.py",
    "hive_protocol/adapters/security.py",
    "hive_protocol/adapters/capture/__init__.py",
    "hive_protocol/adapters/capture/local.py",
    "hive_protocol/adapters/research/__init__.py",
    "hive_protocol/adapters/research/bounded.py",
    "hive_protocol/adapters/research/notebook.py",
}
ALLOWED_ADAPTER_MANIFESTS = {
    "hive_protocol/adapters/capture/local-capture.manifest.json",
    "hive_protocol/adapters/research/bounded-research.manifest.json",
}
REQUIRED_M31_RUNTIME = {
    "hive_protocol/capture/admission.py",
    "hive_protocol/capture/models.py",
    "hive_protocol/capture/normalizers.py",
    "hive_protocol/capture/security.py",
    "hive_protocol/capture/store.py",
    "hive_protocol/product/agent_adapter.py",
    "hive_protocol/product/cli.py",
    "hive_protocol/research/artifacts.py",
    "hive_protocol/research/models.py",
    "hive_protocol/research/portable.py",
    "hive_protocol/research/query.py",
    "hive_protocol/research/workspace.py",
    "hive_protocol/schemas/capture-envelope.v1.schema.json",
    "hive_protocol/schemas/source-record.v1.schema.json",
    "hive_protocol/schemas/research-workspace.v1.schema.json",
    "hive_protocol/schemas/research-source-set.v1.schema.json",
    "hive_protocol/schemas/research-artifact.v1.schema.json",
}
REQUIRED_M32_RUNTIME = {
    "hive_protocol/cognition/__init__.py",
    "hive_protocol/cognition/authority.py",
    "hive_protocol/cognition/deletion.py",
    "hive_protocol/cognition/extraction.py",
    "hive_protocol/cognition/models.py",
    "hive_protocol/cognition/promotion.py",
    "hive_protocol/cognition/retention.py",
    "hive_protocol/cognition/retrieval.py",
    "hive_protocol/cognition/scoring.py",
    "hive_protocol/cognition/store.py",
    "hive_protocol/knowledge/__init__.py",
    "hive_protocol/knowledge/editor.py",
    "hive_protocol/knowledge/graph.py",
    "hive_protocol/knowledge/models.py",
    "hive_protocol/schemas/cognition-event.v1.schema.json",
    "hive_protocol/schemas/memory-candidate.v1.schema.json",
    "hive_protocol/schemas/memory-review-decision.v1.schema.json",
    "hive_protocol/schemas/knowledge-node.v1.schema.json",
    "hive_protocol/schemas/knowledge-edge.v1.schema.json",
    "hive_protocol/schemas/memory-deletion-plan.v1.schema.json",
}
REQUIRED_M33_RUNTIME = {
    "hive_protocol/product/workflow_adapter.py",
    "hive_protocol/workflows/__init__.py",
    "hive_protocol/workflows/approvals.py",
    "hive_protocol/workflows/conflicts.py",
    "hive_protocol/workflows/definitions.py",
    "hive_protocol/workflows/events.py",
    "hive_protocol/workflows/matching.py",
    "hive_protocol/workflows/models.py",
    "hive_protocol/workflows/replay.py",
    "hive_protocol/workflows/scheduler.py",
    "hive_protocol/workflows/sessions.py",
    "hive_protocol/schemas/agent-session.v1.schema.json",
    "hive_protocol/schemas/workflow-approval.v1.schema.json",
    "hive_protocol/schemas/workflow-definition.v1.schema.json",
    "hive_protocol/schemas/workflow-event.v1.schema.json",
    "hive_protocol/schemas/workflow-run.v1.schema.json",
}
REQUIRED_M4_RUNTIME = {
    "hive_protocol/operator/__init__.py",
    "hive_protocol/operator/lifecycle.py",
    "hive_protocol/operator/projection.py",
    "hive_protocol/receipts/__init__.py",
    "hive_protocol/receipts/core.py",
    "hive_protocol/tasks/__init__.py",
    "hive_protocol/tasks/engine.py",
    "hive_protocol/product/shell_views.py",
    "hive_protocol/product/static/app.css",
    "hive_protocol/product/static/app.js",
    "hive_protocol/product/static/knowledge.js",
    "hive_protocol/product/static/workflows.js",
}


def allowed(name: str) -> bool:
    if not name.startswith("hive_protocol/"):
        return True
    return (
        name in ALLOWED_RUNTIME
        or name in ALLOWED_OPTIONAL_MODULES
        or name in ALLOWED_ADAPTER_MODULES
        or name in ALLOWED_ADAPTER_MANIFESTS
        or name.startswith(ALLOWED_PREFIXES)
    )


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: sanitize_product_wheel.py WHEEL")
    wheel = Path(sys.argv[1]).resolve()
    temporary = wheel.with_suffix(".sanitized.whl")
    with zipfile.ZipFile(wheel, "r") as source:
        names = source.namelist()
        record_name = next(name for name in names if name.endswith(".dist-info/RECORD"))
        retained = [name for name in names if name != record_name and allowed(name)]
        missing_m31 = sorted(REQUIRED_M31_RUNTIME - set(retained))
        if missing_m31:
            raise SystemExit(
                f"M3.1 runtime missing before wheel sanitization: {missing_m31}"
            )
        missing_m32 = sorted(REQUIRED_M32_RUNTIME - set(retained))
        if missing_m32:
            raise SystemExit(
                f"M3.2 runtime missing before wheel sanitization: {missing_m32}"
            )
        missing_m33 = sorted(REQUIRED_M33_RUNTIME - set(retained))
        if missing_m33:
            raise SystemExit(
                f"M3.3 runtime missing before wheel sanitization: {missing_m33}"
            )
        missing_m4 = sorted(REQUIRED_M4_RUNTIME - set(retained))
        if missing_m4:
            raise SystemExit(
                f"M4 runtime missing before wheel sanitization: {missing_m4}"
            )
        removed = sorted(set(names) - set(retained) - {record_name})
        required_absent = {
            "hive_protocol/turn.py",
            "hive_protocol/m003.py",
            "hive_protocol/memory.py",
            "hive_protocol/distribution.py",
            "hive_protocol/observer.py",
            "hive_protocol/cli.py",
        }
        if required_absent.intersection(names).difference(removed):
            raise SystemExit("non-product LAB module survived wheel sanitization")
        if any("reference/" in name for name in retained):
            raise SystemExit("protected reference inventory survived wheel sanitization")
        record_rows = list(csv.reader(io.StringIO(source.read(record_name).decode("utf-8"))))
        retained_set = set(retained)
        filtered_rows = [row for row in record_rows if row and row[0] in retained_set]
        filtered_rows.append([record_name, "", ""])
        output = io.StringIO(newline="")
        csv.writer(output, lineterminator="\n").writerows(filtered_rows)
        # Store canonical entries without DEFLATE so the wheel bytes do not depend on
        # the builder's zlib implementation. The outer artifact still compresses it.
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_STORED) as target:
            for name in sorted(retained):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_STORED
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                target.writestr(info, source.read(name))
            info = zipfile.ZipInfo(record_name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            target.writestr(info, output.getvalue().encode("utf-8"))
    os.replace(temporary, wheel)
    print(f"sanitized {wheel.name}: removed {len(removed)} non-product entries", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
