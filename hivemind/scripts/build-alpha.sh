#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
architecture="$(uname -m)"
bundle_name="nukotech-hive-local-alpha-v0.1.0-linux-${architecture}"
build_root="$(mktemp -d -t nukotech-hive-build.XXXXXX)"
trap 'rm -rf -- "$build_root"' EXIT

mkdir -p "$build_root/$bundle_name/wheelhouse" "$build_root/$bundle_name/verify" "$repo_root/dist"
python3 -m pip wheel --disable-pip-version-check "$repo_root" \
    --wheel-dir "$build_root/$bundle_name/wheelhouse" >&2
product_wheel="$(find "$build_root/$bundle_name/wheelhouse" -maxdepth 1 -type f -name 'nukotech_hive_local-0.1.0-*.whl' -print -quit)"
[[ -n "$product_wheel" ]] || { echo "ERROR: product wheel missing" >&2; exit 2; }
python3 "$repo_root/scripts/sanitize_product_wheel.py" "$product_wheel"
python3 - "$product_wheel" <<'PY'
import sys
import zipfile

required = {
    "hive_protocol/adapters/runtime.py",
    "hive_protocol/adapters/lifecycle.py",
    "hive_protocol/adapters/capture/local.py",
    "hive_protocol/adapters/research/bounded.py",
    "hive_protocol/adapters/capture/local-capture.manifest.json",
    "hive_protocol/adapters/research/bounded-research.manifest.json",
    "hive_protocol/schemas/application-adapter-manifest.v1.schema.json",
    "hive_protocol/schemas/adapter-request.v1.schema.json",
    "hive_protocol/schemas/adapter-plan.v1.schema.json",
    "hive_protocol/schemas/adapter-approval.v1.schema.json",
    "hive_protocol/schemas/adapter-result.v1.schema.json",
    "hive_protocol/schemas/adapter-ownership-manifest.v1.schema.json",
    "hive_protocol/capture/admission.py",
    "hive_protocol/capture/models.py",
    "hive_protocol/capture/normalizers.py",
    "hive_protocol/capture/security.py",
    "hive_protocol/capture/store.py",
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
    "hive_protocol/cognition/authority.py",
    "hive_protocol/cognition/deletion.py",
    "hive_protocol/cognition/extraction.py",
    "hive_protocol/cognition/models.py",
    "hive_protocol/cognition/promotion.py",
    "hive_protocol/cognition/retention.py",
    "hive_protocol/cognition/retrieval.py",
    "hive_protocol/cognition/scoring.py",
    "hive_protocol/cognition/store.py",
    "hive_protocol/knowledge/editor.py",
    "hive_protocol/knowledge/graph.py",
    "hive_protocol/knowledge/models.py",
    "hive_protocol/schemas/cognition-event.v1.schema.json",
    "hive_protocol/schemas/memory-candidate.v1.schema.json",
    "hive_protocol/schemas/memory-review-decision.v1.schema.json",
    "hive_protocol/schemas/knowledge-node.v1.schema.json",
    "hive_protocol/schemas/knowledge-edge.v1.schema.json",
    "hive_protocol/schemas/memory-deletion-plan.v1.schema.json",
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
with zipfile.ZipFile(sys.argv[1]) as archive:
    names = set(archive.namelist())
missing = sorted(required - names)
if missing:
    raise SystemExit(f"product runtime missing from sanitized wheel: {missing}")
PY
cp "$repo_root/installer/install.sh" "$build_root/$bundle_name/install.sh"
cp "$repo_root/installer/uninstall.sh" "$build_root/$bundle_name/uninstall.sh"
cp "$repo_root/installer/ownership.py" "$build_root/$bundle_name/ownership.py"
cp "$repo_root/LICENSE" "$build_root/$bundle_name/LICENSE"
cp "$repo_root/THIRD_PARTY_NOTICES.md" "$build_root/$bundle_name/THIRD_PARTY_NOTICES.md"
cp "$repo_root/packaging/product-readme.md" "$build_root/$bundle_name/README.md"
cp "$repo_root/docs/install/alpha-install.md" "$build_root/$bundle_name/INSTALL.md"
cp "$repo_root/scripts/m4-installed-shell-e2e.py" "$build_root/$bundle_name/verify/m4-installed-shell-e2e.py"
chmod 0755 "$build_root/$bundle_name/install.sh" "$build_root/$bundle_name/uninstall.sh" "$build_root/$bundle_name/ownership.py" "$build_root/$bundle_name/verify/m4-installed-shell-e2e.py"
python3 "$repo_root/scripts/generate_artifact_metadata.py" "$build_root/$bundle_name"

artifact="$repo_root/dist/$bundle_name.tar.gz"
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
    -C "$build_root" -czf "$artifact" "$bundle_name"
sha256sum "$artifact" >"$repo_root/dist/SHA256SUMS"
echo "$artifact"
