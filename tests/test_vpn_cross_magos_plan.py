"""Pure direct-hop policy routing plans are symmetric and fail closed."""
from pathlib import Path
import sys
from types import SimpleNamespace as Obj
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vpn_cross_magos_plan import plan_cross_magos, CrossPathRejected

def magos():
    return {
        1: Obj(id=1, name="magos01", role="Magos", ip_pool="10.77.0.2/32", public_key="A"*43+"="),
        3: Obj(id=3, name="magos03", role="Magos", ip_pool="10.77.0.4/32", public_key="B"*43+"="),
    }


CLIENT = Obj(parent_magos_id=3, vpn_address="10.77.0.5/32",
             public_key="C"*43+"=", status="applied")
RESOURCE = Obj(parent_magos_id=1, network="192.165.42.2/32")


def test_direct_hop_uses_target_subnet_outbound_and_client_32_for_return():
    s, t, outbound, reverse = plan_cross_magos(
        CLIENT, RESOURCE, magos(), [Obj(node1_id=3, node2_id=1)])
    assert (s.name, t.name) == ("magos03", "magos01")
    assert outbound["role"] == "source"
    assert outbound["required_peer_allowed_ip"] == "192.165.42.2/32"
    assert outbound["peer_public_key"] == magos()[1].public_key
    assert reverse["role"] == "destination"
    assert reverse["required_peer_allowed_ip"] == "10.77.0.5/32"
    assert reverse["peer_public_key"] == magos()[3].public_key
    assert outbound["address"] == outbound["own_vpn_cidr"]
    assert reverse["address"] == reverse["own_vpn_cidr"]


@pytest.mark.parametrize("edges", [
    [], [Obj(node1_id=3, node2_id=2)],
    [Obj(node1_id=1, node2_id=3), Obj(node1_id=3, node2_id=1)],
])
def test_missing_or_ambiguous_direct_peer_link_is_denied(edges):
    with pytest.raises(CrossPathRejected):
        plan_cross_magos(CLIENT, RESOURCE, magos(), edges)


def test_never_allows_management_or_tunnel_address_as_resource():
    for resource in ("10.77.0.5/32", "10.77.0.2/32", "0.0.0.0/0",
                     "127.0.0.0/8", "224.0.0.0/4"):
        with pytest.raises(CrossPathRejected):
            plan_cross_magos(
                CLIENT, Obj(parent_magos_id=1, network=resource),
                magos(), [Obj(node1_id=1, node2_id=3)])


def test_unapplied_cognitor_cannot_authorize_cross_path():
    with pytest.raises(CrossPathRejected):
        plan_cross_magos(
            Obj(**{**CLIENT.__dict__, "status": "draft"}), RESOURCE,
            magos(), [Obj(node1_id=1, node2_id=3)])
