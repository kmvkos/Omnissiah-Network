"""Pure fail-closed validation for root-only add-only recovery."""
import base64
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
from vpn_add_only_recovery import (
    AddOnlyRecoveryBlocked, _identity, _peers_by_key,
    _unmanaged_routes, _validate_new_routes
)


def peer(letter, ip, endpoint="192.0.2.3:51820"):
    return {
        "public_key": base64.b64encode(bytes(letter * 32, "ascii")).decode(),
        "endpoint": endpoint, "allowed_ips": [ip], "keepalive": 25
    }


def test_valid_peer_is_strictly_canonical():
    p = peer("a", "10.77.0.3/32")
    assert _identity(p, desired=True) == (
        p["public_key"], "192.0.2.3:51820", "10.77.0.3/32", 25)


@pytest.mark.parametrize("change", [
    {"endpoint": "not-an-ip:51820"},
    {"endpoint": "192.0.2.3:0"},
    {"allowed_ips": ["0.0.0.0/0"]},
    {"allowed_ips": ["10.77.0.0/24"]},
    {"keepalive": True},
    {"keepalive": -1},
    {"public_key": "wrong"},
])
def test_invalid_desired_peer_is_never_accepted(change):
    candidate = peer("a", "10.77.0.3/32")
    candidate.update(change)
    with pytest.raises(AddOnlyRecoveryBlocked):
        _identity(candidate, desired=True)


def test_repeated_destination_or_key_refused():
    a = peer("a", "10.77.0.3/32")
    b = peer("b", "10.77.0.3/32")
    with pytest.raises(AddOnlyRecoveryBlocked, match="Duplicate"):
        _peers_by_key([a, b], desired=True)
    with pytest.raises(AddOnlyRecoveryBlocked, match="Duplicate"):
        _peers_by_key([a, a], desired=True)


def test_ambiguous_owned_route_rejected():
    destination = {"10.77.0.4/32"}
    for row in [
        {"dst": "10.77.0.4", "dev": "eth0"},
        {"dst": "10.77.0.4", "dev": "wg0", "gateway": "192.0.2.1"},
        {"dst": "10.77.0.4", "dev": "wg0", "metric": 100},
        {"dst": "10.77.0.4", "dev": "wg0", "protocol": "static"},
    ]:
        with pytest.raises(AddOnlyRecoveryBlocked):
            _validate_new_routes([row], destination)


def test_unrelated_routes_are_preserved_in_full():
    old = [{"dst": "10.77.0.3", "dev": "wg0"},
           {"dst": "192.0.2.0/24", "dev": "eth0", "metric": 50}]
    new = old + [{"dst": "10.77.0.4", "dev": "wg0", "scope": "link"}]
    assert _unmanaged_routes(old, {"10.77.0.4/32"}) == _unmanaged_routes(
        new, {"10.77.0.4/32"})
    new[1]["metric"] = 60
    assert _unmanaged_routes(old, {"10.77.0.4/32"}) != _unmanaged_routes(
        new, {"10.77.0.4/32"})



def test_default_route_drift_is_not_discarded_from_kernel_snapshot():
    before = [{"dst": "default", "gateway": "192.0.2.1", "dev": "eth0"}]
    after = [{"dst": "default", "gateway": "192.0.2.254", "dev": "eth0"}]
    assert _unmanaged_routes(before, {"10.77.0.4/32"}) != _unmanaged_routes(
        after, {"10.77.0.4/32"})
