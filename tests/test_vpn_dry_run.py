"""Regression checks: dry-run must remain a safe read-only preview."""
import importlib.util
from pathlib import Path

path = Path(__file__).resolve().parents[1] / "src" / "vpn_dry_run.py"
spec = importlib.util.spec_from_file_location("vpn_dry_run", path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

KEY1, KEY2 = "A"*44, "B"*44
def peer(key, ip):
    return {"public_key": key, "allowed_ips": [ip], "keepalive": 25}
def plan(*peers):
    return {"peers": list(peers)}
def actual(*peers):
    return {"active": True, "peers": list(peers)}

def test_identical_configuration_requires_no_changes():
    p = peer(KEY1, "10.77.0.3/32")
    result = mod.preview_change(plan(p), actual(p), "192.168.32.168")
    assert result["safe"] is True
    assert result["changes"] == []
    assert result["apply_permitted"] is False

def test_peer_addition_previews_host_route_not_activation():
    p = peer(KEY1, "10.77.0.3/32")
    q = peer(KEY2, "10.77.0.4/32")
    result = mod.preview_change(plan(p, q), actual(p), "192.168.32.168")
    assert result["routes_to_add"] == ["10.77.0.4/32"]
    assert result["changes"][0]["operation"] == "add_peer"
    assert result["apply_permitted"] is False

def test_block_management_host_route():
    result = mod.preview_change(plan(peer(KEY1, "192.168.32.168/32")), actual(), "192.168.32.168")
    assert result["safe"] is False

def test_missing_observations_are_not_safe():
    assert mod.preview_change(plan(), {"active": False}, "192.168.32.168")["safe"] is False
    assert mod.preview_change(plan(), {"active": True, "peers": None}, "192.168.32.168")["safe"] is False
