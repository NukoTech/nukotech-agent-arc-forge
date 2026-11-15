from __future__ import annotations

from pathlib import Path

from hive_protocol.product.workspace import HiveWorkspace
from hive_protocol.storage import read_json


def test_operation_bound_import_reuses_provenance_and_receipt(tmp_path: Path) -> None:
    workspace = HiveWorkspace.create(tmp_path / "hive")
    source = tmp_path / "source.md"
    source.write_text("# Exact\n\nidempotent import", encoding="utf-8")
    operation_id = "a" * 64

    first = workspace.import_content(source, operation_id=operation_id)[0]
    provenance_path = (
        workspace.provenance / f"{first.stable_id.removeprefix('doc:')}.json"
    )
    first_provenance = read_json(provenance_path)
    receipt_paths = sorted(workspace.receipts.glob("*content-imported.json"))
    second = workspace.import_content(source, operation_id=operation_id)[0]

    assert second == first
    assert read_json(provenance_path) == first_provenance
    assert sorted(workspace.receipts.glob("*content-imported.json")) == receipt_paths


def test_operation_bound_import_repairs_missing_derived_receipt_index(
    tmp_path: Path,
) -> None:
    workspace = HiveWorkspace.create(tmp_path / "hive")
    source = tmp_path / "source.md"
    source.write_text("# Exact\n\nrepair receipt index", encoding="utf-8")
    operation_id = "b" * 64
    workspace.import_content(source, operation_id=operation_id)
    receipt_path = next(
        workspace.receipts.glob(f"operation-{operation_id}-*-content-imported.json")
    )
    receipt_id = read_json(receipt_path)["receipt_id"]
    with workspace._connect() as connection:
        connection.execute(
            "DELETE FROM product_receipts WHERE receipt_id = ?", (receipt_id,)
        )

    workspace.import_content(source, operation_id=operation_id)

    with workspace._connect() as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM product_receipts WHERE receipt_id = ?", (receipt_id,)
        ).fetchone()[0]
    assert count == 1
