#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
artifact="${1:-}"
if [[ -z "$artifact" ]]; then
    artifact="$($repo_root/scripts/build-alpha.sh)"
fi
artifact="$(realpath "$artifact")"
[[ -f "$artifact" ]] || { echo "ERROR: artifact not found: $artifact" >&2; exit 2; }

test_root="$(mktemp -d -t nukotech-hive-fresh.XXXXXX)"
trap 'rm -rf -- "$test_root"' EXIT
tar -xzf "$artifact" -C "$test_root"
bundle_dir="$(find "$test_root" -mindepth 1 -maxdepth 1 -type d -name 'nukotech-hive-local-alpha-*' -print -quit)"
[[ -n "$bundle_dir" ]] || { echo "ERROR: bundle directory missing" >&2; exit 2; }
partial_bundle="$test_root/partial-bundle"
partial_prefix="$test_root/partial-prefix"
mkdir -p "$partial_bundle" "$partial_prefix"
cp -a "$bundle_dir/." "$partial_bundle/"
printf '%s\n' 'preserve-partial-sentinel' >"$partial_prefix/unrelated.sentinel"
product_wheel="$(find "$partial_bundle/wheelhouse" -maxdepth 1 -name 'nukotech_hive_local-*.whl' -print -quit)"
[[ -n "$product_wheel" ]] || { echo "ERROR: product wheel missing before partial-install test" >&2; exit 2; }
python3 -c 'from pathlib import Path; import sys; Path(sys.argv[1]).unlink()' "$product_wheel"
if "$partial_bundle/install.sh" --prefix "$partial_prefix" >/dev/null 2>&1; then
    echo "ERROR: partial-install falsifier unexpectedly succeeded" >&2
    exit 2
fi
[[ "$(<"$partial_prefix/unrelated.sentinel")" == "preserve-partial-sentinel" ]]
[[ ! -e "$partial_prefix/.nukotech-hive-local-owner.json" ]]
[[ ! -e "$partial_prefix/.nukotech-hive-local-manifest.json" ]]
[[ ! -e "$partial_prefix/bin/hive-local" && ! -L "$partial_prefix/bin/hive-local" ]]
[[ -z "$(find "$partial_prefix" -maxdepth 1 -name '.nukotech-hive-local-owned-*' -print -quit)" ]]

install_prefix="$test_root/install-prefix"
mkdir -p "$install_prefix"
printf '%s\n' 'preserve-lifecycle-sentinel' >"$install_prefix/unrelated.sentinel"
"$bundle_dir/install.sh" --prefix "$install_prefix"
first_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["installation_id"])' "$install_prefix/.nukotech-hive-local-owner.json")"
adapter_vault="$test_root/adapter-vault"
"$install_prefix/bin/hive-local" init --vault "$adapter_vault" >/dev/null
"$install_prefix/bin/hive-local" adapter-list --vault "$adapter_vault" >"$test_root/adapter-list.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert [x["adapter_id"] for x in d["adapters"]] == ["nukotech.hive.bounded-research", "nukotech.hive.local-capture"]; assert "credential_references" not in json.dumps(d)' "$test_root/adapter-list.json"

m31_source="$test_root/m31-source.md"
m31_request="$test_root/m31-capture-request.json"
m31_plan="$test_root/m31-capture-plan.json"
m31_capture="$test_root/m31-capture-result.json"
m31_source_set="$test_root/m31-source-set.json"
m31_search="$test_root/m31-search-result.json"
m31_ask="$test_root/m31-ask-result.json"
m31_ask_status="$test_root/m31-ask-status.json"
m31_artifact="$test_root/m31-artifact-result.json"
m31_export_plan="$test_root/m31-export-plan.json"
m31_export_result="$test_root/m31-export-result.json"
m31_bundle="$test_root/m31-research.tar.gz"
m31_reopened="$test_root/m31-reopened"
printf '%s\n' 'The installed launch color is amber.' >"$m31_source"
"$install_prefix/bin/hive-local" capture-plan \
    --vault "$adapter_vault" \
    --channel markdown \
    --source "$m31_source" \
    --title 'Installed M3.1 evidence' \
    --request-output "$m31_request" \
    --plan-output "$m31_plan" >/dev/null
"$install_prefix/bin/hive-local" capture-admit \
    --vault "$adapter_vault" \
    --request "$m31_request" \
    --plan "$m31_plan" \
    --output "$m31_capture" >/dev/null
m31_source_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["evidence_refs"][0]["source_id"])' "$m31_capture")"
"$install_prefix/bin/hive-local" research-workspace-create \
    --vault "$adapter_vault" \
    --workspace-id research:fresh-install \
    --name 'Fresh Install Research' >/dev/null
"$install_prefix/bin/hive-local" research-source-add \
    --vault "$adapter_vault" \
    --workspace-id research:fresh-install \
    --source-id "$m31_source_id" \
    --expected-digest NONE >"$m31_source_set"
m31_source_set_digest="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["source_set_digest"])' "$m31_source_set")"
"$install_prefix/bin/hive-local" research-search \
    --vault "$adapter_vault" \
    --workspace-id research:fresh-install \
    --source-set-digest "$m31_source_set_digest" \
    --query 'launch color' \
    --output "$m31_search" >/dev/null
"$install_prefix/bin/hive-local" research-ask \
    --vault "$adapter_vault" \
    --workspace-id research:fresh-install \
    --source-set-digest "$m31_source_set_digest" \
    --question 'launch color' \
    --output "$m31_ask" >"$m31_ask_status"
"$install_prefix/bin/hive-local" research-artifact \
    --vault "$adapter_vault" \
    --workspace-id research:fresh-install \
    --source-set-digest "$m31_source_set_digest" \
    --artifact-type SOURCE_SUMMARY \
    --title 'Installed evidence summary' \
    --research-result "$m31_ask" \
    --output "$m31_artifact" >/dev/null
"$install_prefix/bin/hive-local" research-export \
    --vault "$adapter_vault" \
    --workspace-id research:fresh-install \
    --source-set-digest "$m31_source_set_digest" \
    --bundle "$m31_bundle" \
    --plan-output "$m31_export_plan" \
    --output "$m31_export_result" >/dev/null
"$install_prefix/bin/hive-local" research-reopen \
    --bundle "$m31_bundle" \
    --target "$m31_reopened" >"$test_root/m31-reopen-result.json"
python3 - "$m31_search" "$m31_ask" "$m31_ask_status" "$m31_artifact" "$m31_export_result" "$test_root/m31-reopen-result.json" "$m31_source_set_digest" <<'PY'
import json
import sys

search, ask, ask_status, artifact, exported, reopened = [
    json.load(open(path, encoding="utf-8")) for path in sys.argv[1:7]
]
digest = sys.argv[7]
assert search["detail"]["status"] == "SEARCH_COMPLETE"
assert ask["detail"]["status"] == "RETRIEVAL_ONLY"
assert ask_status["research_status"] == "RETRIEVAL_ONLY"
assert "download" not in ask_status["message"].lower()
assert artifact["detail"]["status"] == "RETRIEVAL_ONLY"
assert exported["outcome"] == "APPLIED"
assert reopened["source_set_digest"] == digest
PY

m31_source_record="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["evidence_refs"][0]["source_record_path"])' "$m31_capture")"

write_m32_event() {
    python3 - "$1" "$2" "$3" "$4" "$adapter_vault" "$m31_source_record" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

output, action, target, narrative, vault, source_record = sys.argv[1:]
record = json.load(open(Path(vault) / source_record, encoding="utf-8"))
anchor = record["anchors"][0]
claim = {
    "candidate_type": "DECISION" if action == "CREATE" else "CORRECTION",
    "subject_id": "project:HiveMind",
    "key": "installed.memory",
    "value": narrative,
    "narrative": narrative,
    "proposed_action": action,
    "supersedes": target if action == "CORRECT" else None,
    "revokes": target if action == "REVOKE" else None,
}
now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
event = {
    "schema_version": "hive.cognition-event.v1",
    "event_id": str(uuid4()),
    "tenant_id": "local-user",
    "project_id": "HiveMind",
    "event_type": "PROJECT_EVENT",
    "privacy_class": "PROJECT_PRIVATE",
    "experience_scope": {"kind": "DOMAIN", "owner_id": "HiveMind"},
    "title": "Installed M3.2 event",
    "text": "",
    "structured_claims": [claim],
    "evidence": [{
        "source_id": record["source_id"],
        "anchor_id": anchor["anchor_id"],
        "source_sha256": record["original_sha256"],
        "normalized_sha256": record["normalized_sha256"],
    }],
    "source_ref": "installed-event:" + uuid4().hex,
    "source_sha256": record["original_sha256"],
    "occurred_at": now,
    "recorded_at": now,
}
with open(output, "w", encoding="utf-8") as handle:
    json.dump(event, handle, sort_keys=True, separators=(",", ":"))
PY
}

promote_m32_event() {
    local command="$1"
    local event_path="$2"
    local label="$3"
    local proposed="$test_root/$label-proposed.json"
    local reviewed="$test_root/$label-reviewed.json"
    local promoted="$test_root/$label-promoted.json"
    "$install_prefix/bin/hive-local" "$command" \
        --vault "$adapter_vault" --event "$event_path" >"$proposed"
    local candidate_id
    candidate_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["candidates"][0]["candidate_id"])' "$proposed")"
    "$install_prefix/bin/hive-local" memory-review \
        --vault "$adapter_vault" --candidate-id "$candidate_id" \
        --outcome APPROVED --actor-id Owner \
        --authorization-ref attended:fresh-install >"$reviewed"
    "$install_prefix/bin/hive-local" memory-promote \
        --vault "$adapter_vault" --candidate-id "$candidate_id" >"$promoted"
    python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["node"]["node_id"])' "$promoted"
}

m32_event="$test_root/m32-event.json"
write_m32_event "$m32_event" CREATE NONE 'Installed memory is reviewed.'
m32_original_node="$(promote_m32_event memory-propose-event "$m32_event" m32-original)"
m32_correction="$test_root/m32-correction.json"
write_m32_event "$m32_correction" CORRECT "$m32_original_node" 'Installed memory is reviewed and portable.'
m32_corrected_node="$(promote_m32_event memory-correct "$m32_correction" m32-corrected)"
m32_revocation="$test_root/m32-revocation.json"
write_m32_event "$m32_revocation" REVOKE "$m32_corrected_node" 'The corrected installed claim is revoked.'
m32_revocation_node="$(promote_m32_event memory-revoke "$m32_revocation" m32-revoked)"

"$install_prefix/bin/hive-local" memory-candidates \
    --vault "$adapter_vault" >"$test_root/m32-candidates.json"
"$install_prefix/bin/hive-local" memory-retention-scan \
    --vault "$adapter_vault" --project-id HiveMind >"$test_root/m32-retention.json"

m32_note="$test_root/m32-note.md"
printf '%s\n' '# Installed Note' '' '#attended' '' '- supports [[Installed Note]]' >"$m32_note"
"$install_prefix/bin/hive-local" knowledge-note-preview \
    --vault "$adapter_vault" --project-id HiveMind \
    --relative-path 'Installed Note.md' --content "$m32_note" >"$test_root/m32-note-preview.json"
m32_preview_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["preview_id"])' "$test_root/m32-note-preview.json")"
"$install_prefix/bin/hive-local" knowledge-note-apply \
    --vault "$adapter_vault" --preview-id "$m32_preview_id" \
    --content "$m32_note" --idempotency-key "$(printf 'c%.0s' {1..64})" >"$test_root/m32-note-applied.json"
m32_note_sha="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sha256"])' "$test_root/m32-note-applied.json")"
printf '%s\n' '# Installed Note' '' '#attended #updated' '' '- supports [[Installed Note]]' >"$m32_note"
"$install_prefix/bin/hive-local" knowledge-note-preview \
    --vault "$adapter_vault" --project-id HiveMind \
    --relative-path 'Installed Note.md' --content "$m32_note" \
    --expected-sha256 "$m32_note_sha" >"$test_root/m32-note-update-preview.json"
m32_update_preview="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["preview_id"])' "$test_root/m32-note-update-preview.json")"
"$install_prefix/bin/hive-local" knowledge-note-approve \
    --vault "$adapter_vault" --preview-id "$m32_update_preview" \
    --actor-id Owner --authorization-ref attended:fresh-install-edit \
    --output "$test_root/m32-note-approval.json" >/dev/null
"$install_prefix/bin/hive-local" knowledge-note-apply \
    --vault "$adapter_vault" --preview-id "$m32_update_preview" \
    --content "$m32_note" --idempotency-key "$(printf 'd%.0s' {1..64})" \
    --approval "$test_root/m32-note-approval.json" >"$test_root/m32-note-updated.json"
"$install_prefix/bin/hive-local" knowledge-graph \
    --vault "$adapter_vault" >"$test_root/m32-graph.json"
python3 - "$test_root/m32-candidates.json" "$test_root/m32-retention.json" "$test_root/m32-graph.json" "$m32_original_node" "$m32_corrected_node" "$m32_revocation_node" <<'PY'
import json
import sys

candidates, retention, graph = [json.load(open(path, encoding="utf-8")) for path in sys.argv[1:4]]
original, corrected, revocation = sys.argv[4:7]
assert len(candidates["candidates"]) == 3
assert retention == {"outcome": "SCANNED", "requests": []}
states = {node["id"]: node["lifecycle_state"] for node in graph["nodes"]}
assert states[original] == "SUPERSEDED"
assert states[corrected] == "REVOKED"
assert states[revocation] == "AUDIT"
assert any(node["title"] == "Installed Note" and "updated" in node["tags"] for node in graph["nodes"])
PY

m32_bundle="$test_root/m32-hive.tar.gz"
m32_reopened="$test_root/m32-reopened"
"$install_prefix/bin/hive-local" export \
    --vault "$adapter_vault" --output "$m32_bundle" >"$test_root/m32-export.json"
"$install_prefix/bin/hive-local" reopen \
    --bundle "$m32_bundle" --target "$m32_reopened" >"$test_root/m32-reopen.json"
"$install_prefix/bin/hive-local" knowledge-graph \
    --vault "$m32_reopened" >"$test_root/m32-reopened-graph.json"
"$install_prefix/bin/hive-local" memory-candidates \
    --vault "$m32_reopened" >"$test_root/m32-reopened-candidates.json"
python3 - "$test_root/m32-graph.json" "$test_root/m32-reopened-graph.json" "$test_root/m32-reopened-candidates.json" <<'PY'
import json
import sys

before, after, candidates = [json.load(open(path, encoding="utf-8")) for path in sys.argv[1:4]]
assert before["nodes"] == after["nodes"]
assert before["edges"] == after["edges"]
assert before["backlinks"] == after["backlinks"]
assert len(candidates["candidates"]) == 3
PY

"$install_prefix/bin/hive-local" memory-deletion-plan \
    --vault "$adapter_vault" --node-id "$m32_original_node" >"$test_root/m32-delete-plan.json"
m32_delete_plan="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["plan_id"])' "$test_root/m32-delete-plan.json")"
"$install_prefix/bin/hive-local" memory-deletion-approve \
    --vault "$adapter_vault" --plan-id "$m32_delete_plan" \
    --actor-id Owner --authorization-ref attended:fresh-install-delete \
    --confirmation "DELETE $m32_original_node" --output "$test_root/m32-delete-approval.json" >/dev/null
"$install_prefix/bin/hive-local" memory-deletion-apply \
    --vault "$adapter_vault" --plan-id "$m32_delete_plan" \
    --approval "$test_root/m32-delete-approval.json" >"$test_root/m32-deleted.json"
m32_delete_checkpoint="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["checkpoint"])' "$test_root/m32-deleted.json")"
"$install_prefix/bin/hive-local" rollback \
    --vault "$adapter_vault" --commit "$m32_delete_checkpoint" >"$test_root/m32-delete-rollback.json"
"$install_prefix/bin/hive-local" knowledge-graph \
    --vault "$adapter_vault" --lifecycle-state SUPERSEDED >"$test_root/m32-restored.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert any(n["id"] == sys.argv[2] for n in d["nodes"])' "$test_root/m32-restored.json" "$m32_original_node"

adapter_request="$test_root/installed-adapter-request.json"
adapter_plan="$test_root/installed-adapter-plan.json"
adapter_result="$test_root/installed-adapter-result.json"
rollback_plan="$test_root/installed-rollback-plan.json"
rollback_approval="$test_root/installed-rollback-approval.json"
rollback_result="$test_root/installed-rollback-result.json"
"$install_prefix/bin/hive-local" adapter-plan \
    --vault "$adapter_vault" \
    --adapter nukotech.hive.local-capture \
    --capability capture.text \
    --input 'installed attended lifecycle evidence' \
    --request-output "$adapter_request" \
    --output "$adapter_plan" >/dev/null
"$install_prefix/bin/hive-local" adapter-invoke \
    --vault "$adapter_vault" \
    --request "$adapter_request" \
    --plan "$adapter_plan" \
    --output "$adapter_result" >/dev/null
"$install_prefix/bin/hive-local" adapter-lifecycle-plan \
    --vault "$adapter_vault" \
    --adapter nukotech.hive.local-capture \
    --operation rollback \
    --input "$adapter_result" \
    --output "$rollback_plan" >/dev/null
"$install_prefix/bin/hive-local" adapter-approve \
    --vault "$adapter_vault" \
    --plan "$rollback_plan" \
    --output "$rollback_approval" >/dev/null
"$install_prefix/bin/hive-local" adapter-rollback \
    --vault "$adapter_vault" \
    --result "$adapter_result" \
    --plan "$rollback_plan" \
    --approval "$rollback_approval" >"$rollback_result"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["outcome"] == "APPLIED"' "$rollback_result"
if "$install_prefix/bin/hive-local" adapter-rollback \
    --vault "$adapter_vault" \
    --result "$adapter_result" \
    --plan "$rollback_plan" \
    --approval "$rollback_approval" >"$test_root/installed-replay.json"; then
    echo "ERROR: installed attended lifecycle replay unexpectedly succeeded" >&2
    exit 2
fi
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["reason_code"] == "REPLAY_MESSAGE_ID"' "$test_root/installed-replay.json"

m33_definition="$test_root/m33-definition.json"
m33_launch="$test_root/m33-launch.json"
m33_run_id="$test_root/m33-run-id.txt"
python3 - "$m33_definition" "$m33_launch" "$m33_run_id" <<'PY'
import json
import sys
from datetime import datetime, timezone
from uuid import uuid4

definition_path, launch_path, run_id_path = sys.argv[1:]
step = {
    "step_id": "observe",
    "kind": "TASK",
    "dependencies": [],
    "inputs": [],
    "outputs": [{"name": "result", "type": "application/json"}],
    "required_capabilities": ["workflow:observe"],
    "required_trust": "ATTENDED",
    "target": {"project_id": "HiveMind", "machine_id": None, "surface_id": None},
    "approval": {"required": False, "risk_class": "LOW"},
    "retry": {"max_attempts": 1, "timeout_seconds": 300},
    "resources": {"max_tokens": 100, "max_cost_microunits": 1000, "max_memory_mb": 64},
    "ownership": {"branches": ["workflows/installed"], "files": ["research/installed.json"]},
    "rollback": {"mode": "GIT_CHECKPOINT", "compensation_step_id": None},
}
definition = {
    "schema_version": "hive.workflow-definition.v1",
    "workflow_id": "workflow:installed-m33",
    "version": 1,
    "tenant_id": "local-user",
    "project_id": "HiveMind",
    "title": "Installed M3.3 workflow",
    "description": "Prove sanitized installed workflow capability.",
    "parent_digest": None,
    "steps": [step],
    "metadata": {"tags": ["fresh-install"]},
}
run_id = str(uuid4())
now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
launch = {
    "workflow_id": "workflow:installed-m33",
    "version": 1,
    "run_id": run_id,
    "source_commit": "a" * 64,
    "input_manifest_sha256": "b" * 64,
    "event_id": str(uuid4()),
    "idempotency_key": "launch-installed-m33",
    "now": now,
}
for path, document in ((definition_path, definition), (launch_path, launch)):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, sort_keys=True, separators=(",", ":"))
with open(run_id_path, "w", encoding="utf-8") as handle:
    handle.write(run_id)
PY
"$install_prefix/bin/hive-local" workflow-definition-preview \
    --vault "$adapter_vault" --definition "$m33_definition" >"$test_root/m33-preview.json"
"$install_prefix/bin/hive-local" workflow-definition-publish \
    --vault "$adapter_vault" --definition "$m33_definition" \
    --idempotency-key publish-installed-m33 >"$test_root/m33-publish.json"
"$install_prefix/bin/hive-local" workflow-definition-list \
    --vault "$adapter_vault" --workflow-id workflow:installed-m33 >"$test_root/m33-list.json"
"$install_prefix/bin/hive-local" workflow-run-launch \
    --vault "$adapter_vault" --request "$m33_launch" >"$test_root/m33-launched.json"
"$install_prefix/bin/hive-local" workflow-run-status \
    --vault "$adapter_vault" --run-id "$(<"$m33_run_id")" >"$test_root/m33-status.json"
"$install_prefix/bin/hive-local" workflow-replay \
    --vault "$adapter_vault" --run-id "$(<"$m33_run_id")" >"$test_root/m33-replay.json"
python3 - "$test_root/m33-preview.json" "$test_root/m33-list.json" "$test_root/m33-status.json" "$test_root/m33-replay.json" <<'PY'
import json
import sys

preview, listed, status, replay = [json.load(open(path, encoding="utf-8")) for path in sys.argv[1:]]
assert preview["execution_authorized"] is False
assert listed["versions"] == [1]
assert status == replay
assert replay["state"] == "RUNNING"
assert replay["execution_performed"] is False
assert replay["mutation_performed"] is False
PY

python3 "$bundle_dir/verify/m4-installed-shell-e2e.py" \
    --launcher "$install_prefix/bin/hive-local" \
    --vault "$adapter_vault" \
    --work-root "$test_root/m4-installed-shell" \
    >"$test_root/m4-installed-shell-result.json"
python3 - "$test_root/m4-installed-shell-result.json" <<'PY'
import json
import sys

result = json.load(open(sys.argv[1], encoding="utf-8"))
assert result["outcome"] == "VERIFIED"
assert result["second_process"] is True
assert result["browser_persistence"] is False
assert result["execution_performed"] is False
assert result["service_installed"] is False
assert result["session_rotated"] is True
PY

m32_owned_root="$test_root/m32-adapter-owned"
mkdir -p "$m32_owned_root"
printf '%s\n' 'adapter-owned' >"$m32_owned_root/owned.txt"
printf '%s\n' 'preserve-adapter-sentinel' >"$m32_owned_root/sentinel.txt"
python3 - "$adapter_vault" >"$test_root/m32-canonical-before.txt" <<'PY'
import hashlib
import sys
from pathlib import Path

root = Path(sys.argv[1])
digest = hashlib.sha256()
for relative in (
    "sources", "assets", "staging", "research", "prime", "workflows",
    ".hive/receipts/workflows", ".hive/workflow-keys",
):
    lane = root / relative
    if lane.exists():
        for path in sorted(lane.rglob("*")):
            if path.is_file() and not path.is_symlink():
                digest.update(path.relative_to(root).as_posix().encode())
                digest.update(b"\0")
                digest.update(path.read_bytes())
print(digest.hexdigest())
PY
python3 - "$test_root/adapter-list.json" "$m32_owned_root" "$test_root/m32-ownership.json" <<'PY'
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

adapters = json.load(open(sys.argv[1], encoding="utf-8"))["adapters"]
version = next(item["version"] for item in adapters if item["adapter_id"] == "nukotech.hive.local-capture")
root = Path(sys.argv[2]).resolve()
owned = root / "owned.txt"
document = {
    "schema_version": "hive.adapter-ownership-manifest.v1",
    "installation_id": "m32-fresh-install",
    "adapter_id": "nukotech.hive.local-capture",
    "adapter_version": version,
    "root": str(root),
    "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "paths": [{
        "path": "owned.txt",
        "kind": "file",
        "sha256": hashlib.sha256(owned.read_bytes()).hexdigest(),
    }],
}
with open(sys.argv[3], "w", encoding="utf-8") as handle:
    json.dump(document, handle, sort_keys=True, separators=(",", ":"))
PY
"$install_prefix/bin/hive-local" adapter-lifecycle-plan \
    --vault "$adapter_vault" --adapter nukotech.hive.local-capture \
    --operation uninstall --input "$test_root/m32-ownership.json" \
    --output "$test_root/m32-uninstall-plan.json" >/dev/null
"$install_prefix/bin/hive-local" adapter-approve \
    --vault "$adapter_vault" --plan "$test_root/m32-uninstall-plan.json" \
    --output "$test_root/m32-uninstall-approval.json" >/dev/null
"$install_prefix/bin/hive-local" adapter-uninstall \
    --vault "$adapter_vault" --adapter nukotech.hive.local-capture \
    --ownership-manifest "$test_root/m32-ownership.json" \
    --plan "$test_root/m32-uninstall-plan.json" \
    --approval "$test_root/m32-uninstall-approval.json" \
    --output "$test_root/m32-uninstall-result.json" >/dev/null
[[ ! -e "$m32_owned_root/owned.txt" ]]
[[ "$(<"$m32_owned_root/sentinel.txt")" == "preserve-adapter-sentinel" ]]
python3 - "$adapter_vault" >"$test_root/m32-canonical-after.txt" <<'PY'
import hashlib
import sys
from pathlib import Path

root = Path(sys.argv[1])
digest = hashlib.sha256()
for relative in (
    "sources", "assets", "staging", "research", "prime", "workflows",
    ".hive/receipts/workflows", ".hive/workflow-keys",
):
    lane = root / relative
    if lane.exists():
        for path in sorted(lane.rglob("*")):
            if path.is_file() and not path.is_symlink():
                digest.update(path.relative_to(root).as_posix().encode())
                digest.update(b"\0")
                digest.update(path.read_bytes())
print(digest.hexdigest())
PY
cmp "$test_root/m32-canonical-before.txt" "$test_root/m32-canonical-after.txt"
HIVE_FRESH_INSTALL=1 "$install_prefix/bin/hive-local" demo --work-root "$test_root/demo"

"$bundle_dir/install.sh" --prefix "$install_prefix"
second_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["installation_id"])' "$install_prefix/.nukotech-hive-local-owner.json")"
[[ "$first_id" != "$second_id" ]]
[[ "$(<"$install_prefix/unrelated.sentinel")" == "preserve-lifecycle-sentinel" ]]

manifest="$install_prefix/.nukotech-hive-local-manifest.json"
manifest_backup="$test_root/manifest.good.json"
cp "$manifest" "$manifest_backup"
printf '\n' >>"$manifest"
if "$bundle_dir/uninstall.sh" --prefix "$install_prefix" >/dev/null 2>&1; then
    echo "ERROR: tampered manifest was accepted" >&2
    exit 2
fi
[[ -L "$install_prefix/bin/hive-local" ]]
[[ "$(<"$install_prefix/unrelated.sentinel")" == "preserve-lifecycle-sentinel" ]]
cp "$manifest_backup" "$manifest"
"$bundle_dir/uninstall.sh" --prefix "$install_prefix" >/dev/null
[[ "$(<"$install_prefix/unrelated.sentinel")" == "preserve-lifecycle-sentinel" ]]
[[ ! -e "$install_prefix/bin/hive-local" && ! -L "$install_prefix/bin/hive-local" ]]
if "$bundle_dir/uninstall.sh" --prefix "$install_prefix" >/dev/null 2>&1; then
    echo "ERROR: repeated uninstall unexpectedly succeeded" >&2
    exit 2
fi
[[ "$(<"$install_prefix/unrelated.sentinel")" == "preserve-lifecycle-sentinel" ]]
echo "PASS: partial cleanup, reinstall, tamper refusal, manifest uninstall, repeated uninstall, and sentinel preservation"
