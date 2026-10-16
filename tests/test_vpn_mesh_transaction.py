"""Offline WireGuard+route+file coordinator failure-injection tests."""
import importlib.util
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
for name in ("vpn_route_tx", "vpn_route_journal", "vpn_route_executor_sim", "vpn_mesh_transaction"):
    src = ROOT / "deploy" / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, src)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)

from vpn_route_journal import prepare_transaction
from vpn_mesh_transaction import run_offline_mesh_transaction, MeshTransactionBlocked


class MemoryBackend:
    def __init__(self):
        self.peers = [{"public_key": "old", "allowed_ips": ["10.77.0.3/32"], "keepalive": 25}]
        self.routes = {"10.77.0.3/32"}
        self.config = "old"
        self.original = None
        self.events = []
        self.fail_phase = None
        self.fail_rollback = False

    def snapshot(self):
        return (self.peers, [{"dst": d, "dev": "wg0"} for d in sorted(self.routes)])

    def stage_backup(self):
        self.original = (list(self.peers), set(self.routes), self.config)
        self.events.append("backup")

    def sync_wireguard(self, desired):
        self.events.append("sync")
        self.peers = desired
        if self.fail_phase == "sync":
            raise RuntimeError("sync failed after write")

    def route_step(self, step):
        self.events.append("route")
        if step["op"] == "add":
            self.routes.add(step["dst"])
        else:
            self.routes.remove(step["dst"])
        if self.fail_phase == "route":
            raise RuntimeError("route failed after write")

    def verify(self, desired, plan):
        self.events.append("verify")
        if self.fail_phase == "verify":
            raise RuntimeError("verify failed")
        assert self.peers == desired
        assert self.routes == {"10.77.0.3/32", "10.77.0.4/32"}

    def persist_config(self, desired):
        self.events.append("persist")
        self.config = "new"
        if self.fail_phase == "persist":
            raise RuntimeError("persist failed after write")

    def restore_wireguard(self):
        self.events.append("restore_wg")
        if self.fail_rollback:
            raise RuntimeError("wg restore failed")
        self.peers = self.original[0]

    def restore_routes(self):
        self.events.append("restore_routes")
        self.routes = set(self.original[1])

    def restore_config(self):
        self.events.append("restore_config")
        self.config = self.original[2]

    def verify_restored(self):
        self.events.append("verify_restored")
        assert (self.peers, self.routes, self.config) == self.original


def desired_and_plan(b):
    peers, routes = b.snapshot()
    desired = peers + [{"public_key": "new", "allowed_ips": ["10.77.0.4/32"], "keepalive": 25}]
    return desired, prepare_transaction(desired, peers, routes)


def state(folder):
    return json.loads((folder / "mesh-transaction.json").read_text())["state"]


def test_success(tmp_path):
    b = MemoryBackend()
    desired, plan = desired_and_plan(b)
    assert run_offline_mesh_transaction(plan, desired, b, tmp_path)["state"] == "committed"
    assert state(tmp_path) == "committed"
    assert b.events == ["backup", "sync", "route", "verify", "persist"]
    assert (tmp_path / "mesh-transaction.json").stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("phase", ["sync", "route", "verify", "persist"])
def test_failure_restores_all_three_domains(tmp_path, phase):
    b = MemoryBackend()
    desired, plan = desired_and_plan(b)
    b.fail_phase = phase
    with pytest.raises(RuntimeError, match="failed"):
        run_offline_mesh_transaction(plan, desired, b, tmp_path)
    assert state(tmp_path) == "rolled_back"
    assert (b.peers, b.routes, b.config) == b.original
    assert b.events[-4:] == ["restore_wg", "restore_routes", "restore_config", "verify_restored"]


def test_unrecoverable_failure_blocks_retries(tmp_path):
    b = MemoryBackend()
    desired, plan = desired_and_plan(b)
    b.fail_phase = "route"
    b.fail_rollback = True
    with pytest.raises(MeshTransactionBlocked, match="manual recovery"):
        run_offline_mesh_transaction(plan, desired, b, tmp_path)
    assert state(tmp_path) == "recovery_required"
    before = len(b.events)
    with pytest.raises(MeshTransactionBlocked, match="Unresolved"):
        run_offline_mesh_transaction(plan, desired, b, tmp_path)
    assert len(b.events) == before


def test_interrupted_operation_fails_closed(tmp_path):
    b = MemoryBackend()
    desired, plan = desired_and_plan(b)
    (tmp_path / "mesh-transaction.json").write_text('{"state":"applying"}')
    with pytest.raises(MeshTransactionBlocked):
        run_offline_mesh_transaction(plan, desired, b, tmp_path)
    assert b.events == []


def test_stale_plan_rejected_before_backup(tmp_path):
    b = MemoryBackend()
    desired, plan = desired_and_plan(b)
    b.routes.add("10.77.0.5/32")
    with pytest.raises(ValueError, match="Stale"):
        run_offline_mesh_transaction(plan, desired, b, tmp_path)
    assert b.events == []
    assert not (tmp_path / "mesh-transaction.json").exists()


def test_forged_route_step_rejected(tmp_path):
    b = MemoryBackend()
    desired, plan = desired_and_plan(b)
    plan["steps"][0]["dst"] = "10.77.0.9/32"
    plan["rollback"][0]["dst"] = "10.77.0.9/32"
    with pytest.raises(MeshTransactionBlocked, match="Preview does not match"):
        run_offline_mesh_transaction(plan, desired, b, tmp_path)
    assert b.events == []


def test_no_real_commands_or_secret_journaling():
    source = (ROOT / "deploy" / "vpn_mesh_transaction.py").read_text()
    assert "subprocess" not in source
    assert "wg syncconf" not in source
    assert "ip route" not in source
    assert "private_key" not in source
