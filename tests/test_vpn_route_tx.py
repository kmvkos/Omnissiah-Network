"""Tests for route ownership and conflict handling; never touch host routes."""
import importlib.util
import sys
from pathlib import Path

import pytest

path = Path(__file__).resolve().parents[1] / "deploy" / "vpn_route_tx.py"
spec = importlib.util.spec_from_file_location("vpn_route_tx", path)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def peer(ip):
    return {"allowed_ips": [ip]}


def rt(ip, dev="wg0", **kwargs):
    return {"dst": ip, "dev": dev, "protocol": "static", **kwargs}


def test_new_peer_addition_to_existing_mesh():
    old = [peer("10.77.0.3/32")]
    new = old + [peer("10.77.0.4/32")]
    actual = [rt("10.77.0.3/32")]
    assert mod.plan_route_delta(new, old, actual) == {
        "add": ["10.77.0.4/32"], "remove": [],
        "unchanged": ["10.77.0.3/32"]}


def test_remove_is_explicit():
    old = [peer("10.77.0.3/32"), peer("10.77.0.4/32")]
    assert mod.plan_route_delta(old[:1], old,
        [rt("10.77.0.3/32"), rt("10.77.0.4/32")])["remove"] == ["10.77.0.4/32"]


@pytest.mark.parametrize("actual", [
    [rt("10.77.0.3/32", "eth0")],
    [rt("10.77.0.3/32", "wg0", gateway="192.168.32.1")],
    [rt("10.77.0.3/32", "wg0", metric=10)],
    [rt("10.77.0.3/32", "wg0", type="blackhole")],
    [],
])
def test_refuse_unowned_or_drifted_existing_routes(actual):
    with pytest.raises(mod.RouteConflict):
        mod.plan_route_delta([peer("10.77.0.3/32")],
                             [peer("10.77.0.3/32")], actual)


def test_refuse_reuse_of_foreign_wg0_route():
    with pytest.raises(mod.RouteConflict, match="not owned"):
        mod.plan_route_delta([peer("10.77.0.4/32")], [],
                             [rt("10.77.0.4/32")])


@pytest.mark.parametrize("bad", ["0.0.0.0/0", "10.77.0.0/24", "::1/128", "224.0.0.1/32"])
def test_no_broad_ipv6_or_multicast(bad):
    with pytest.raises(mod.RouteConflict):
        mod.desired_routes([peer(bad)])


def test_no_double_owned_routes():
    with pytest.raises(mod.RouteConflict):
        mod.desired_routes([peer("10.77.0.3/32"), peer("10.77.0.3/32")])


def test_is_pure_preflight():
    source = path.read_text()
    assert "subprocess" not in source
    assert "os.system" not in source
