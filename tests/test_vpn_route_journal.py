"""Pure transaction journal tests. Never modify live networking."""
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for name in ("vpn_route_tx", "vpn_route_journal"):
    source = ROOT / "deploy" / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)

from vpn_route_journal import prepare_transaction, assert_snapshot_unchanged
from vpn_route_tx import RouteConflict


def peer(key, cidr):
    return {"public_key": key, "allowed_ips": [cidr], "keepalive": 25}


def route(cidr, dev="wg0"):
    return {"dst": cidr, "dev": dev, "protocol": "static"}


def test_addition_has_inverse_and_is_not_executable():
    actual = [peer("k1", "10.77.0.3/32")]
    desired = actual + [peer("k2", "10.77.0.4/32")]
    routes = [route("10.77.0.3/32")]
    tx = prepare_transaction(desired, actual, routes)
    assert tx["steps"] == [{"op": "add", "dst": "10.77.0.4/32", "dev": "wg0"}]
    assert tx["rollback"] == [{"op": "delete", "dst": "10.77.0.4/32", "dev": "wg0"}]
    assert tx["writes_performed"] is False
    assert tx["executable"] is False
    assert assert_snapshot_unchanged(tx, actual, routes)


def test_removal_has_inverse():
    actual = [peer("k1", "10.77.0.3/32")]
    tx = prepare_transaction([], actual, [route("10.77.0.3/32")])
    assert tx["steps"][0]["op"] == "delete"
    assert tx["rollback"][0]["op"] == "add"


def test_stale_route_or_peer_snapshot_blocks():
    old = [peer("k1", "10.77.0.3/32")]
    routes = [route("10.77.0.3/32")]
    tx = prepare_transaction(old + [peer("k2", "10.77.0.4/32")], old, routes)
    with pytest.raises(RouteConflict, match="Stale"):
        assert_snapshot_unchanged(tx, old, routes + [route("10.77.0.8/32")])
    with pytest.raises(RouteConflict, match="Stale"):
        assert_snapshot_unchanged(tx, [peer("k1", "10.77.0.3/32") | {"keepalive": 0}], routes)


def test_foreign_route_conflict_blocks_preview():
    with pytest.raises(RouteConflict, match="overlaps"):
        prepare_transaction([peer("k2", "10.77.0.4/32")], [],
                            [route("10.77.0.0/24", dev="eth0")])


def test_snapshot_is_order_independent():
    old = [peer("k1", "10.77.0.3/32"), peer("k2", "10.77.0.4/32")]
    routes = [route("10.77.0.3/32"), route("10.77.0.4/32")]
    tx = prepare_transaction(old, old, routes)
    assert assert_snapshot_unchanged(tx, list(reversed(old)), list(reversed(routes)))


def test_blueprint_cannot_execute_route_changes():
    source = (ROOT / "deploy" / "vpn_route_journal.py").read_text()
    assert "subprocess" not in source
    assert "os.system" not in source
    assert '"executable": False' in source
