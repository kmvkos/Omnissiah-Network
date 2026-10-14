"""Unit tests for the non-privileged VPN planning layer."""
import base64
import importlib.util
from pathlib import Path
import pytest

SOURCE = Path(__file__).resolve().parents[1] / "agents" / "app" / "vpn_plan.py"
spec = importlib.util.spec_from_file_location("vpn_plan", SOURCE)
import sys
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
Peer, VPNPlanError, plan_vpn, render_peer_sections = (
    module.Peer, module.VPNPlanError, module.plan_vpn, module.render_peer_sections)
KEY_A = base64.b64encode(b"A" * 32).decode()
KEY_B = base64.b64encode(b"B" * 32).decode()


def test_two_peers_are_preserved_and_routes_are_explicit():
    plan = plan_vpn("magos01", "10.77.0.2/32", [
        Peer("omni01", KEY_A, "192.168.32.167:51820", ("10.77.0.1/32",)),
        Peer("magos02", KEY_B, "192.168.32.169:51820", ("10.77.0.3/32",)),
    ])
    text = render_peer_sections(plan)
    assert text.count("[Peer]") == 2
    assert "0.0.0.0/0" not in text
    assert "PrivateKey" not in text
    assert "10.77.0.3/32" in text


@pytest.mark.parametrize("route", ["0.0.0.0/0", "10.77.0.0/24", "::/0", "bad"])
def test_refuses_broad_routes(route):
    with pytest.raises(VPNPlanError):
        plan_vpn("magos01", "10.77.0.2/32",
                 [Peer("magos02", KEY_A, "192.168.32.169:51820", (route,))])


def test_duplicate_routes_and_keys_rejected():
    for second in [
        Peer("magos03", KEY_A, "192.168.32.170:51820", ("10.77.0.4/32",)),
        Peer("magos03", KEY_B, "192.168.32.170:51820", ("10.77.0.3/32",)),
    ]:
        with pytest.raises(VPNPlanError):
            plan_vpn("magos01", "10.77.0.2/32", [
                Peer("magos02", KEY_A, "192.168.32.169:51820", ("10.77.0.3/32",)),
                second,
            ])


def test_rejects_controller_network_as_interface_address():
    with pytest.raises(VPNPlanError):
        plan_vpn("omni01", "10.77.0.0/24", [])


def test_rejects_local_address_as_peer_route():
    with pytest.raises(VPNPlanError):
        plan_vpn("magos01", "10.77.0.2/32",
                 [Peer("magos02", KEY_A, "192.168.32.169:51820", ("10.77.0.2/32",))])
