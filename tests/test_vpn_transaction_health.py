"""Read-only journal health tests. No WireGuard kernel or host routes touched."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "vpn_transaction_health", ROOT / "deploy/vpn_transaction_health.py")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def root_dir(tmp_path):
    folder = tmp_path / "vpn"
    folder.mkdir(mode=0o700)
    folder.chmod(0o700)
    return folder


def record(folder, state, *, backup=True):
    lock = folder / "mesh-transaction.lock"
    lock.touch(mode=0o600)
    lock.chmod(0o600)
    digest = "a" * 64
    contents = {
        "schema_version": 1, "state": state,
        "phase": "done" if state in ("committed", "rolled_back") else "route",
        "route_ops": 1, "snapshot_sha256": digest,
        "pending_route": {"op": "add", "dst": "10.77.0.4/32", "dev": "wg0"}
    }
    journal = folder / "mesh-transaction.json"
    journal.write_text(json.dumps(contents))
    journal.chmod(0o600)
    if backup:
        data = {"snapshot_sha256": digest, "wg_conf": "FAKE PRIVATE DATA"}
        seal = hashlib.sha256(json.dumps(data, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        path = folder / "mesh-backup.json"
        path.write_text(json.dumps({"data": data, "sha256": seal}))
        path.chmod(0o600)


def test_no_state_is_safe_and_read_only(tmp_path):
    absent = tmp_path / "not-created"
    assert module.inspect_transaction(absent)["state"] == "not_initialized"
    assert not absent.exists()
    folder = root_dir(tmp_path)
    result = module.inspect_transaction(folder)
    assert result["state"] == "idle"
    assert not result["needs_attention"]
    assert not (folder / "mesh-transaction.json").exists()


@pytest.mark.parametrize("state,attention", [
    ("committed", False), ("rolled_back", False), ("prepared", True),
    ("applying", True), ("rolling_back", True), ("recovery_required", True),
])
def test_status_does_not_expose_keys_or_backup_contents(tmp_path, state, attention):
    folder = root_dir(tmp_path)
    record(folder, state)
    result = module.inspect_transaction(folder)
    assert result["state"] == state
    assert result["route_ops"] == 1
    assert result["backup_verified"] is True
    assert result["needs_attention"] is attention
    assert "FAKE PRIVATE DATA" not in json.dumps(result)
    assert "10.77.0.4" not in json.dumps(result)
    assert "snapshot_sha256" not in result


def test_interrupted_operation_with_missing_backup_fails_closed(tmp_path):
    folder = root_dir(tmp_path)
    record(folder, "applying", backup=False)
    result = module.inspect_transaction(folder)
    assert result["needs_attention"] is True
    assert result["reason"] == "missing_backup"


def test_invalid_backup_is_not_treated_as_recoverable(tmp_path):
    folder = root_dir(tmp_path)
    record(folder, "applying")
    backup = folder / "mesh-backup.json"
    packed = json.loads(backup.read_text())
    packed["data"]["wg_conf"] = "TAMPERED"
    backup.write_text(json.dumps(packed))
    result = module.inspect_transaction(folder)
    assert result["state"] == "recovery_required"
    assert result["reason"] == "invalid_backup"


def test_symlink_journal_is_refused_without_following(tmp_path):
    folder = root_dir(tmp_path)
    external = tmp_path / "external"
    external.write_text('{"state":"committed"}')
    (folder / "mesh-transaction.json").symlink_to(external)
    result = module.inspect_transaction(folder)
    assert result["reason"] == "unsafe_journal"
    assert external.read_text() == '{"state":"committed"}'


def test_held_exclusive_lock_only_reports_in_progress(tmp_path):
    folder = root_dir(tmp_path)
    record(folder, "applying")
    with (folder / "mesh-transaction.lock").open("a+") as lock:
        os.fchmod(lock.fileno(), 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = module.inspect_transaction(folder)
        assert result["state"] == "in_progress"
        assert result["needs_attention"] is False
        assert result["reason"] == "transaction_lock_held"


def test_transaction_status_is_read_only_and_connected_through_mtls():
    helper = (ROOT / "deploy/vpn_helper.py").read_text()
    rpc = (ROOT / "deploy/vpn_rpc.py").read_text()
    agent = (ROOT / "agents/app/agent.py").read_text()
    client = (ROOT / "agents/app/vpn_client.py").read_text()
    controller = (ROOT / "src/app.py").read_text()
    html = (ROOT / "templates/vpn_overview.html").read_text()
    install = (ROOT / "ansible/roles/services/tasks/main.yml").read_text()
    assert 'if args.command == "transaction-status":' in helper
    assert "inspect_transaction(STATE)" in helper
    assert all('"transaction-status"' in src for src in (rpc, agent, client))
    assert '_vpn_v2_send(node, "transaction-status")' in controller
    assert "def vpn_mesh_transaction_status():" in controller
    assert 'url_for("vpn_mesh_transaction_status")' in html
    assert "vpn_transaction_health.py" in install
    assert "vpn_helper.py" not in module.__dict__.get("__doc__", "")


def test_status_never_creates_lockfile(tmp_path):
    folder = root_dir(tmp_path)
    assert module.inspect_transaction(folder)["state"] == "idle"
    assert not (folder / "mesh-transaction.lock").exists()


def test_missing_lockfile_with_existing_journal_fails_closed(tmp_path):
    folder = root_dir(tmp_path)
    record(folder, "applying")
    (folder / "mesh-transaction.lock").unlink()
    result = module.inspect_transaction(folder)
    assert result["state"] == "recovery_required"
    assert result["reason"] == "missing_lock_file"
