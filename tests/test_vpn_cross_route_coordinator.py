"""Distributed path route coordination must prepare both and compensate failures."""
from types import SimpleNamespace as Obj
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vpn_cross_route_coordinator import (
    CrossRouteCoordinationError, run_direct_route_transaction
)

SRC = Obj(name="magos03", ip_pool="10.77.0.4/32")
DST = Obj(name="magos01", ip_pool="10.77.0.2/32")
PLAN1 = {"node_name": SRC.name, "address": SRC.ip_pool}
PLAN2 = {"node_name": DST.name, "address": DST.ip_pool}
OPID = "00000000-0000-4000-8000-000000000001"

class Transport:
    def __init__(self, fail=None):
        self.history = []
        self.state = {}
        self.fail = fail

    def __call__(self, node, action, plan, operation_id=None):
        self.history.append((node.name, action))
        if (node.name, action) == self.fail:
            raise TimeoutError("Unknown peer transport result")
        if action == "route-ext-prepare":
            self.state[node.name] = "prepared"
            return {"state": "prepared", "revision": "a"*64 if node.name == SRC.name else "b"*64,
                    "operation_id": operation_id, "writes_performed": False}
        if action == "route-ext-commit":
            self.state[node.name] = "committed"
            return {"state": "committed", "revision": plan["revision"],
                    "operation_id": operation_id}
        if action == "route-ext-revert":
            self.state[node.name] = "reverted"
            return {"state": "reverted", "operation_id": operation_id}
        if action == "policy-path-preview":
            return {"gateway_checks_passed": True, "writes_performed": False}
        if action == "route-ext-finalize":
            self.state[node.name] = "finished"
            return {"state": "finished", "operation_id": operation_id}
        raise AssertionError(action)


def test_prepare_both_then_commit_destination_then_source():
    tx = Transport()
    records = []
    result = run_direct_route_transaction(
        SRC, DST, PLAN1, PLAN2, tx, OPID,
        lambda *fields: records.append(fields))
    assert result["state"] == "committed"
    assert tx.history[:4] == [
        ("magos03", "route-ext-prepare"), ("magos01", "route-ext-prepare"),
        ("magos01", "route-ext-commit"), ("magos03", "route-ext-commit"),
    ]
    assert all(action != "route-ext-revert" for _, action in tx.history)
    assert records[-1][0] == "committed"


def test_commit_timeout_rolls_back_both_prepared_gateways():
    tx = Transport(fail=("magos03", "route-ext-commit"))
    records = []
    with pytest.raises(CrossRouteCoordinationError):
        run_direct_route_transaction(SRC, DST, PLAN1, PLAN2,
                                     tx, OPID, lambda *fields: records.append(fields))
    assert ("magos01", "route-ext-revert") in tx.history
    assert ("magos03", "route-ext-revert") in tx.history
    assert records[-1][0] == "reverted"


def test_failed_rollback_leaves_manual_recovery_fence():
    class BrokenRollback(Transport):
        def __call__(self, node, action, plan, operation_id=None):
            if action == "route-ext-revert" and node.name == DST.name:
                raise ConnectionError("Host not reachable")
            return super().__call__(node, action, plan, operation_id)
    tx = BrokenRollback(fail=("magos03", "route-ext-commit"))
    records = []
    with pytest.raises(CrossRouteCoordinationError, match="UNKNOWN"):
        run_direct_route_transaction(SRC, DST, PLAN1, PLAN2,
                                     tx, OPID, lambda *fields: records.append(fields))
    assert records[-1][0] == "recovery_required"
