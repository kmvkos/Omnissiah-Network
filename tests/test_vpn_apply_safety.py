"""Conservative same-route live apply gate regression tests."""
import importlib.util
import sys
from pathlib import Path

path=Path(__file__).resolve().parents[1]/"src"/"vpn_apply_safety.py"
spec=importlib.util.spec_from_file_location("vpn_apply_safety",path)
mod=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=mod
spec.loader.exec_module(mod)

K="kxcRNbkovVjVFnZXdzaqljNFIStjy8fE/Ugb1G1LUm8="
K2="mxayvUz7Sweer3CqJ4oEWpkfl80gVADPwW1/Mxm+u0g="

def peer(key=K,addr="10.77.0.3/32",keepalive=25):
    return {"public_key":key,"allowed_ips":[addr],"keepalive":keepalive}

def test_same_peer_same_routes_is_safe_noop():
    assert mod.preview([peer()],[peer()],active=True)=={
        "allowed":True,"reason":"same_route_safe_update","changed":False,"changes":[]}

def test_keepalive_change_safe():
    assert mod.preview([peer(keepalive=30)],[peer()],active=True)["allowed"] is True
    assert mod.preview([peer(keepalive=30)],[peer()],active=True)["changed"] is True

def test_new_peer_and_route_blocked():
    actual=[peer()]
    for target in ([peer(),peer(K2,"10.77.0.4/32")],
                   [peer(addr="10.77.0.4/32")],[]):
        assert mod.preview(target,actual,active=True)["allowed"] is False

def test_not_active_or_unknown_blocked():
    assert not mod.preview([peer()],None,active=True)["allowed"]
    assert not mod.preview([peer()],[peer()],active=False)["allowed"]
