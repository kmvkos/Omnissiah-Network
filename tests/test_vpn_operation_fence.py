"""At-most-once fencing regression tests. Never touch wg0 or host routes."""
import json
import os
from pathlib import Path
import sys
from uuid import uuid4

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
from vpn_operation_fence import (
    LEDGER, OperationRejected, finish, reserve, revision, status, validate_operation_id
)


def lab(tmp_path):
    path = tmp_path / "state"
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def plan():
    return {"schema_version": 1, "iface": "wg0", "steps": []}


def test_operation_uuid_is_canonical_v4_only():
    value = str(uuid4())
    assert validate_operation_id(value) == value
    for bad in (None, 42, "", "not-a-uuid", value.upper(),
                value.replace("-", ""), "00000000-0000-0000-0000-000000000000"):
        with pytest.raises(OperationRejected):
            validate_operation_id(bad)


def test_ledger_is_fsynced_owner_only_and_redacted(tmp_path):
    folder = lab(tmp_path)
    op_id = str(uuid4())
    reserve(folder, op_id, plan(), [{"public_key": "public-ident", "allowed_ips": ["10.77.0.3/32"]}])
    path = folder / LEDGER
    assert path.is_file()
    assert path.stat().st_mode & 0o777 == 0o600
    data = json.loads(path.read_text())
    assert data["operations"][op_id]["state"] == "reserved"
    assert len(data["operations"][op_id]["revision"]) == 64
    assert "public-ident" not in path.read_text()
    assert "10.77.0.3" not in path.read_text()
    assert status(folder, op_id) == {"state": "reserved", "writes_performed": False}
    finish(folder, op_id, "committed")
    assert status(folder, op_id)["state"] == "committed"
    with pytest.raises(OperationRejected, match="already used"):
        reserve(folder, op_id, plan(), [])


def test_previous_completed_uuid_cannot_be_reused_after_other_operations(tmp_path):
    folder = lab(tmp_path)
    first, second = str(uuid4()), str(uuid4())
    reserve(folder, first, plan(), [])
    finish(folder, first, "committed")
    reserve(folder, second, plan(), [])
    finish(folder, second, "rolled_back")
    with pytest.raises(OperationRejected, match="already used"):
        reserve(folder, first, plan(), [])
    assert len(json.loads((folder / LEDGER).read_text())["operations"]) == 2


def test_unknown_outcome_blocks_even_different_operation_id(tmp_path):
    folder = lab(tmp_path)
    a, b = str(uuid4()), str(uuid4())
    reserve(folder, a, plan(), [])
    with pytest.raises(OperationRejected, match="Earlier transaction outcome unknown"):
        reserve(folder, b, plan(), [])
    assert status(folder, a)["state"] == "reserved"
    assert status(folder, b)["state"] == "unknown"
    finish(folder, a, "rolled_back")
    reserve(folder, b, plan(), [])
    assert status(folder, b)["state"] == "reserved"


def test_invalid_or_symlink_ledger_fails_closed(tmp_path):
    folder = lab(tmp_path)
    external = tmp_path / "elsewhere"
    external.write_text('{"canary":"unchanged"}')
    (folder / LEDGER).symlink_to(external)
    with pytest.raises(OperationRejected, match="Unsafe operation ledger"):
        reserve(folder, str(uuid4()), plan(), [])
    assert external.read_text() == '{"canary":"unchanged"}'
    (folder / LEDGER).unlink()
    path = folder / LEDGER
    path.write_text("{garbage")
    path.chmod(0o600)
    with pytest.raises(OperationRejected, match="Unreadable"):
        reserve(folder, str(uuid4()), plan(), [])


def test_malformed_existing_operation_record_blocks_new_writes(tmp_path):
    folder = lab(tmp_path)
    path = folder / LEDGER
    path.write_text(json.dumps({"version": 1, "operations": {"invalid": {"revision": "a"*64, "state": "committed"}}}))
    path.chmod(0o600)
    with pytest.raises(OperationRejected):
        reserve(folder, str(uuid4()), plan(), [])


def test_operation_revision_changes_with_plan_and_desired_peers():
    assert revision(plan(), []) != revision(plan(), [{"name": "new"}])
    assert revision(plan(), []) != revision(dict(plan(), iface="wg1"), [])


def test_rpc_agent_controller_and_ui_pass_same_uuid():
    rpc = (ROOT / "deploy/vpn_rpc.py").read_text()
    agent = (ROOT / "agents/app/agent.py").read_text()
    client = (ROOT / "agents/app/vpn_client.py").read_text()
    helper = (ROOT / "deploy/vpn_helper.py").read_text()
    coord = (ROOT / "deploy/vpn_mesh_transaction.py").read_text()
    app = (ROOT / "src/app.py").read_text()
    ui = (ROOT / "templates/vpn_overview.html").read_text()
    install = (ROOT / "ansible/roles/services/tasks/main.yml").read_text()
    assert "validate_operation_id(operation_id)" in rpc
    assert 'parsed = uuid.UUID(operation_id)' in agent
    assert 'message["operation_id"] = operation_id' in client
    assert 'parser.add_argument("--operation-id")' in helper
    assert 'operation_id=args.operation_id' in helper
    assert 'operation_id=body.get("operation_id")' in app
    assert "crypto.randomUUID()" in ui
    assert "operation_id: operationId" in ui
    assert 'reserve(directory, operation_id, plan, desired)' in coord
    assert 'finish(directory, operation_id, "committed")' in coord
    assert "vpn_operation_fence.py" in install
