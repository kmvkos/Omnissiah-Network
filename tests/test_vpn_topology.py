"""Controller mesh preview tests; no real interfaces or root access."""
import base64
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace as N
import pytest

SOURCE = Path(__file__).resolve().parents[1] / "src"
spec_plan = importlib.util.spec_from_file_location("vpn_plan", SOURCE / "vpn_plan.py")
plan_mod = importlib.util.module_from_spec(spec_plan)
sys.modules[spec_plan.name] = plan_mod
spec_plan.loader.exec_module(plan_mod)
spec = importlib.util.spec_from_file_location("vpn_topology", SOURCE / "vpn_topology.py")
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)
KEY1 = base64.b64encode(b"A" * 32).decode()
KEY2 = base64.b64encode(b"B" * 32).decode()


def nodes():
    return [
        N(id=1, name="omni01", role="Omnissiah", ip_pool="10.77.0.0/24",
          public_key="", endpoint="192.168.32.167", listen_port=51820),
        N(id=2, name="magos01", role="Magos", ip_pool="10.77.0.2/32",
          public_key=KEY1, endpoint="192.168.32.168", listen_port=51820),
        N(id=3, name="magos02", role="Magos", ip_pool="10.77.0.3/32",
          public_key=KEY2, endpoint="192.168.32.169", listen_port=51820),
    ]


def test_no_link_means_no_magically_created_vpn_peers():
    plans = mod.project_magos_mesh(nodes(), [])
    assert len(plans) == 2
    assert all(not p["peers"] for p in plans)


def test_direct_mesh_is_symmetric_and_omni_is_not_data_path():
    plans = mod.project_magos_mesh(nodes(), [N(node1_id=2, node2_id=3)])
    by_name = {p["node_name"]: p for p in plans}
    assert by_name["magos01"]["peers"][0]["allowed_ips"] == ["10.77.0.3/32"]
    assert by_name["magos02"]["peers"][0]["allowed_ips"] == ["10.77.0.2/32"]
    assert by_name["magos01"]["peers"][0]["endpoint"] == "192.168.32.169:51820"
    assert "omni01" not in by_name
    assert all("0.0.0.0/0" not in str(p) for p in plans)


def test_management_hierarchy_not_data_path():
    assert all(not p["peers"] for p in mod.project_magos_mesh(
        nodes(), [N(node1_id=1, node2_id=2), N(node1_id=1, node2_id=3)]))


def test_missing_public_key_blocks_connected_mesh():
    ns = nodes()
    ns[2].public_key = ""
    with pytest.raises(plan_mod.VPNPlanError):
        mod.project_magos_mesh(ns, [N(node1_id=2, node2_id=3)])


def test_invalid_pool_blocks_mesh():
    ns = nodes()
    ns[1].ip_pool = "10.77.0.0/24"
    with pytest.raises(plan_mod.VPNPlanError):
        mod.project_magos_mesh(ns, [N(node1_id=2, node2_id=3)])
