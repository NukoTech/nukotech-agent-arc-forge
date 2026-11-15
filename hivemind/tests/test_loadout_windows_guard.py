"""Native Windows loadouts are deferred to v1.1 and must refuse up front."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from hive_protocol.core import ProtocolError
from hive_protocol.loadouts import artifacts
from hive_protocol.loadouts.manager import LoadoutManager
from hive_protocol.product import loadout_adapter
from hive_protocol.product.workspace import HiveWorkspace

MESSAGE = "Windows support arrives in v1.1"


@pytest.fixture(params=["os.name", "sys.platform"])
def windows(request, monkeypatch):
    if request.param == "os.name":
        monkeypatch.setattr(artifacts, "os", SimpleNamespace(name="nt"))
    else:
        monkeypatch.setattr(artifacts, "sys", SimpleNamespace(platform="win32"))
    assert artifacts.running_on_windows()


def _refused(excinfo):
    assert excinfo.value.code == "LOADOUT_PLATFORM_UNSUPPORTED"
    assert MESSAGE in str(excinfo.value)


def test_posix_host_is_not_refused():
    assert artifacts.running_on_windows() is False
    artifacts.refuse_windows()


def test_artifact_reads_refuse_on_windows(windows, tmp_path):
    path = tmp_path / "recipe.yaml"
    path.write_text("schema: example\n")
    with pytest.raises(ProtocolError) as excinfo:
        artifacts.read_bounded(path)
    _refused(excinfo)


def test_manager_refuses_on_windows_before_touching_disk(windows, tmp_path):
    with pytest.raises(ProtocolError) as excinfo:
        LoadoutManager(tmp_path / "missing", target={}, registry=None, request_key=None,
            approver_key=None, state_key=None, approver_identity={})
    _refused(excinfo)
    assert not (tmp_path / "missing").exists()


def test_product_entry_points_refuse_on_windows(windows, tmp_path):
    root = tmp_path.resolve() / "Hive"
    HiveWorkspace.create(root)
    for call in (lambda: loadout_adapter.loadout_services(root),
                 lambda: loadout_adapter.loadout_status(root),
                 lambda: loadout_adapter.read_loadout_context(root, "drafting"),
                 lambda: loadout_adapter.verify_loadout_context(root, {"loadout_id": "drafting"}),
                 lambda: loadout_adapter.plan_loadout(root, operation="admit", loadout_id="drafting",
                     authorization_ref="synthetic-attended-review")):
        with pytest.raises(ProtocolError) as excinfo:
            call()
        _refused(excinfo)
    assert not (root / ".hive" / "loadouts").exists()
