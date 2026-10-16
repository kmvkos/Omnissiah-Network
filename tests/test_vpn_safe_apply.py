"""Pure verification checks used by the active-wireguard transaction."""
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
source = ROOT / "deploy" / "vpn_helper.py"
spec = importlib.util.spec_from_file_location("vpn_helper_verify", source)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

KEY = "kxcRNbkovVjVFnZXdzaqljNFIStjy8fE/Ugb1G1LUm8="
HEADER = "SECRET\tPUBLIC\t51820\toff\n"


def dump(*, peer_key=KEY, ip="10.77.0.3/32", keepalive=25):
    return HEADER + f"{peer_key}\t(none)\t192.168.32.169:51820\t{ip}\t100\t10\t20\t{keepalive}\n"


def desired():
    return {"peers": [{"public_key": KEY, "allowed_ips": ["10.77.0.3/32"], "keepalive": 25}]}


def test_verify_kernel_matching_peers(monkeypatch):
    monkeypatch.setattr(mod, "run", lambda *_args, **_kwargs: dump())
    assert mod.verify_active_peers(desired()) == 1


@pytest.mark.parametrize("text", [
    dump(peer_key="another"),
    dump(ip="10.77.0.4/32"),
    dump(keepalive=0),
    HEADER,
])
def test_verify_kernel_mismatch_fails(monkeypatch, text):
    monkeypatch.setattr(mod, "run", lambda *_args, **_kwargs: text)
    with pytest.raises(mod.HelperError):
        mod.verify_active_peers(desired())


def test_controller_gates_apply_by_fresh_preflight():
    source = (ROOT / "src" / "app.py").read_text()
    route = source.split("def vpn_mesh_operation():", 1)[1].split("@app.route(", 1)[0]
    assert 'observed_before = _vpn_v2_send(node, "status")' in route
    assert 'if decision["decision"] != "eligible":' in route
    assert 'observed_after = _vpn_v2_send(node, "status")' in route
