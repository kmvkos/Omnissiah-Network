"""Safe read-only preflight decisions for WireGuard changes."""
import importlib.util
import sys
from pathlib import Path

source = Path(__file__).resolve().parents[1] / "src" / "vpn_change_preview.py"
spec = importlib.util.spec_from_file_location("vpn_change_preview", source)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

K1 = "k1"
K2 = "k2"


def peer(key, route="10.77.0.3/32", keepalive=25):
    return {"public_key": key, "allowed_ips": [route], "keepalive": keepalive}


def test_in_sync_and_unknown():
    assert mod.preview([peer(K1)], [peer(K1)], active=True)["decision"] == "no_change"
    assert mod.preview([peer(K1)], None, active=True)["decision"] == "blocked"
    assert mod.preview([peer(K1)], [peer(K1)], active=False)["reason"] == "interface_inactive"


def test_reject_route_changes():
    result = mod.preview([peer(K1, "10.77.0.4/32")],
                         [peer(K1, "10.77.0.3/32")], active=True)
    assert result["decision"] == "blocked"
    assert result["reason"] == "route_change_requires_transaction"


def test_same_routes_can_be_previewed_not_applied():
    result = mod.preview([peer(K2)], [peer(K1)], active=True)
    assert result["decision"] == "eligible"
    assert result["add"] == 1 and result["remove"] == 1


def test_same_key_keepalive_change_is_eligible():
    result = mod.preview([peer(K1, keepalive=15)], [peer(K1)], active=True)
    assert result["decision"] == "eligible" and result["update"] == 1


def test_duplicate_key_fails_closed():
    result = mod.preview([peer(K1), peer(K1)], [peer(K1)], active=True)
    assert result["decision"] == "blocked"
