"""Failure-injection tests for the offline executor; no kernel route writes."""
import importlib.util
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
for name in ("vpn_route_tx", "vpn_route_journal", "vpn_route_executor_sim"):
    spec = importlib.util.spec_from_file_location(name, ROOT / "deploy" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)

from vpn_route_journal import prepare_transaction
from vpn_route_executor_sim import TransactionBlocked, run_simulated


class FakeBackend:
    def __init__(self):
        self.peers = [{"public_key": "key1", "allowed_ips": ["10.77.0.3/32"], "keepalive": 25}]
        self.routes = {"10.77.0.3/32"}
        self.fail_at = None
        self.fail_revert = False
        self.events = []

    def snapshot(self):
        return self.peers, [{"dst": x, "dev": "wg0"} for x in sorted(self.routes)]

    def apply(self, step):
        self.events.append(("apply", step["op"], step["dst"]))
        if step["op"] == "add":
            self.routes.add(step["dst"])
        else:
            self.routes.remove(step["dst"])
        if self.fail_at == step["dst"]:
            raise RuntimeError("Failure after mutation")

    def revert(self, step):
        self.events.append(("revert", step["op"], step["dst"]))
        if self.fail_revert:
            raise RuntimeError("Rollback unavailable")
        if step["op"] == "add":
            self.routes.add(step["dst"])
        else:
            self.routes.discard(step["dst"])

    def verify(self, tx):
        if self.fail_at == "verify":
            raise RuntimeError("Verification rejected")
        assert self.routes == {"10.77.0.3/32", "10.77.0.4/32"}


def tx(backend):
    peers, routes = backend.snapshot()
    desired = peers + [{"public_key": "key2", "allowed_ips": ["10.77.0.4/32"], "keepalive": 25}]
    return prepare_transaction(desired, peers, routes)


def journal(folder):
    return json.loads((folder / "route-journal.json").read_text())


def test_successful_simulation_commits_and_is_durable(tmp_path):
    backend = FakeBackend()
    result = run_simulated(tx(backend), backend, tmp_path)
    assert result["state"] == "committed"
    assert journal(tmp_path)["state"] == "committed"
    assert (tmp_path / "route-journal.json").stat().st_mode & 0o077 == 0
    assert "10.77.0.4/32" in backend.routes


def test_post_mutation_failure_is_rolled_back(tmp_path):
    backend = FakeBackend()
    backend.fail_at = "10.77.0.4/32"
    with pytest.raises(RuntimeError, match="after mutation"):
        run_simulated(tx(backend), backend, tmp_path)
    assert backend.routes == {"10.77.0.3/32"}
    assert journal(tmp_path)["state"] == "rolled_back"


def test_verification_failure_rolls_back(tmp_path):
    backend = FakeBackend()
    backend.fail_at = "verify"
    with pytest.raises(RuntimeError, match="Verification"):
        run_simulated(tx(backend), backend, tmp_path)
    assert backend.routes == {"10.77.0.3/32"}
    assert journal(tmp_path)["state"] == "rolled_back"


def test_failed_rollback_blocks_followup(tmp_path):
    backend = FakeBackend()
    plan = tx(backend)
    backend.fail_at = "verify"
    backend.fail_revert = True
    with pytest.raises(TransactionBlocked, match="manual recovery"):
        run_simulated(plan, backend, tmp_path)
    assert journal(tmp_path)["state"] == "recovery_required"
    with pytest.raises(TransactionBlocked, match="Unresolved"):
        run_simulated(plan, backend, tmp_path)


def test_interrupted_journal_blocks(tmp_path):
    backend = FakeBackend()
    plan = tx(backend)
    (tmp_path / "route-journal.json").write_text(json.dumps({"state": "applying", "pending": plan["steps"][0]}))
    with pytest.raises(TransactionBlocked, match="Unresolved"):
        run_simulated(plan, backend, tmp_path)
    assert backend.events == []


def test_stale_snapshot_blocks_without_journaling(tmp_path):
    backend = FakeBackend()
    plan = tx(backend)
    backend.routes.add("10.77.0.9/32")
    with pytest.raises(ValueError, match="Stale"):
        run_simulated(plan, backend, tmp_path)
    assert not (tmp_path / "route-journal.json").exists()


def test_tampered_rollback_blocks(tmp_path):
    backend = FakeBackend()
    plan = tx(backend)
    plan["rollback"] = []
    with pytest.raises(TransactionBlocked, match="Non-reversible"):
        run_simulated(plan, backend, tmp_path)


def test_no_real_route_backend():
    source = (ROOT / "deploy" / "vpn_route_executor_sim.py").read_text()
    assert "subprocess" not in source
    assert "os.system" not in source
    assert "ip route" not in source
    assert "wg syncconf" not in source
