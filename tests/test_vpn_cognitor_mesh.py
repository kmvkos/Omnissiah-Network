"""Mesh + applied Cognitor desired-inventory regression tests, no I/O."""
import base64
from pathlib import Path
import sys
from types import SimpleNamespace
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vpn_cognitor_mesh import compose_expected, observe_managed, preview_managed, CognitorMeshError

M1 = base64.b64encode(b"a" * 32).decode()
M2 = base64.b64encode(b"b" * 32).decode()
C1 = base64.b64encode(b"c" * 32).decode()
OTHER = base64.b64encode(b"d" * 32).decode()

PLAN = {"node_id": 3, "node_name": "magos03", "address": "10.77.0.4/32",
        "peers": [
            {"name": "magos01", "public_key": M1, "allowed_ips": ["10.77.0.2/32"], "keepalive": 25, "endpoint": "192.168.32.168:51820"},
            {"name": "magos02", "public_key": M2, "allowed_ips": ["10.77.0.3/32"], "keepalive": 25, "endpoint": "192.168.32.169:51820"},
        ]}
COGNITOR = SimpleNamespace(name="cognitor01", status="applied", public_key=C1,
                            vpn_address="10.77.0.5/32", parent_magos_id=3)


def observation(allowed="10.77.0.5/32", key=C1):
    peers = [{**p, "rx_bytes": 10, "tx_bytes": 30, "latest_handshake": 1}
             for p in PLAN["peers"]]
    peers.append({"public_key": key, "allowed_ips": [allowed], "keepalive": 0,
                  "endpoint": "192.168.32.88:44111",
                  "rx_bytes": 42, "tx_bytes": 86, "latest_handshake": 100})
    return {"active": True, "peers": peers}


def test_expected_three_peers_are_exactly_two_mesh_and_one_cognitor():
    expected, mesh, client = compose_expected(PLAN, [COGNITOR])
    assert (len(expected), mesh, client) == (3, 2, 1)
    summary = observe_managed(PLAN, [COGNITOR], observation())
    assert summary["desired_peers"] == summary["observed_peers"] == 3
    assert summary["desired_mesh_peers"] == 2
    assert summary["desired_cognitor_peers"] == 1
    assert summary["observed_mesh_peers"] == 2
    assert summary["observed_cognitor_peers"] == 1
    assert summary["unregistered_peers"] == 0
    assert summary["state"] == "in_sync"
    preflight = preview_managed(PLAN, [COGNITOR], observation())
    assert preflight["decision"] == "no_change"
    assert preflight["remove"] == 0
    assert preflight["transaction_available"] is False


def test_foreign_peer_still_detected_and_never_applied():
    state = observation()
    state["peers"].append({"public_key": OTHER, "allowed_ips": ["10.77.0.99/32"], "keepalive": 0})
    summary = observe_managed(PLAN, [COGNITOR], state)
    assert summary["state"] == "drift"
    assert summary["unregistered_peers"] == 1
    assert summary["unexpected_peers"] == 1
    preview = preview_managed(PLAN, [COGNITOR], state)
    assert preview["decision"] == "blocked"
    assert preview["reason"] == "cognitor_managed_drift_requires_review"
    assert preview["remove"] == 1
    assert preview["transaction_available"] is False


def test_mismatched_client_route_does_not_get_hidden():
    summary = observe_managed(PLAN, [COGNITOR], observation(allowed="10.77.0.20/32"))
    assert summary["state"] == "drift"
    assert summary["different_peers"] == 1
    assert preview_managed(PLAN, [COGNITOR], observation(allowed="10.77.0.20/32"))["transaction_available"] is False


def test_missing_client_is_drift_not_success():
    state = observation()
    state["peers"].pop()
    summary = observe_managed(PLAN, [COGNITOR], state)
    assert summary["state"] == "drift"
    assert summary["missing_peers"] == 1
    assert preview_managed(PLAN, [COGNITOR], state)["transaction_available"] is False


def test_only_committed_clients_are_expected():
    draft = SimpleNamespace(name="cognitor02", status="draft", public_key=C1,
                            vpn_address="10.77.0.5/32", parent_magos_id=3)
    with pytest.raises(CognitorMeshError, match="does not match"):
        compose_expected(PLAN, [draft])
    expected, mesh, clients = compose_expected(PLAN, [])
    assert (len(expected), mesh, clients) == (2, 2, 0)


@pytest.mark.parametrize("bad_client", [
    SimpleNamespace(name="collidingKey", status="applied", public_key=M1, vpn_address="10.77.0.5/32", parent_magos_id=3),
    SimpleNamespace(name="collidingAddr", status="applied", public_key=C1, vpn_address="10.77.0.2/32", parent_magos_id=3),
    SimpleNamespace(name="wrongParent", status="applied", public_key=C1, vpn_address="10.77.0.5/32", parent_magos_id=1),
    SimpleNamespace(name="self", status="applied", public_key=C1, vpn_address="10.77.0.4/32", parent_magos_id=3),
    SimpleNamespace(name="wrongMask", status="applied", public_key=C1, vpn_address="10.77.0.5/24", parent_magos_id=3),
])
def test_registry_conflicts_are_fail_closed(bad_client):
    with pytest.raises(CognitorMeshError):
        compose_expected(PLAN, [bad_client])


def test_unknown_status_not_false_green():
    summary = observe_managed(PLAN, [COGNITOR], None)
    assert summary["state"] == "unknown"
    assert summary["observed_peers"] is None
    assert preview_managed(PLAN, [COGNITOR], None)["decision"] == "blocked"
