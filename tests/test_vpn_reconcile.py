"""Read-only WireGuard dump parsing and desired / actual drift regression tests."""
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("vpn_reconcile", ROOT / "src/vpn_reconcile.py")
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

K1 = "kxcRNbkovVjVFnZXdzaqljNFIStjy8fE/Ugb1G1LUm8="
K2 = "mxayvUz7Sweer3CqJ4oEWpkfl80gVADPwW1/Mxm+u0g="


def test_parse_dump_excludes_secret_material():
    raw = ("PRIVATE_SENSITIVE_VALUE\tPUBLIC\t51820\toff\n" +
           f"{K1}\tPRESHARED_SENSITIVE_VALUE\t192.168.32.169:51820\t10.77.0.3/32\t1729000000\t800\t1200\t25\n")
    result = mod.parse_wg_dump(raw)
    assert result == [{
        "public_key": K1,
        "endpoint": "192.168.32.169:51820",
        "allowed_ips": ["10.77.0.3/32"],
        "latest_handshake": 1729000000,
        "rx_bytes": 800, "tx_bytes": 1200, "keepalive": 25,
    }]
    assert "PRIVATE_SENSITIVE_VALUE" not in str(result)
    assert "PRESHARED_SENSITIVE_VALUE" not in str(result)


def test_peer_diff_and_unknown():
    desired = [{"public_key": K1, "allowed_ips": ["10.77.0.3/32"], "keepalive": 25}]
    actual = [{"public_key": K1, "allowed_ips": ["10.77.0.3/32"], "keepalive": 25,
               "endpoint": "192.168.32.12:51820"}]
    assert mod.compare(desired, actual)["state"] == "in_sync"
    assert mod.compare(desired, [])["state"] == "drift"
    assert mod.compare(desired, None)["state"] == "unknown"
    assert mod.compare(desired, [dict(actual[0], keepalive=0)])["state"] == "drift"
    assert mod.compare(desired, [dict(actual[0], allowed_ips=["10.77.0.8/32"])])["state"] == "drift"
    assert mod.compare(desired, [dict(actual[0], public_key=K2)])["state"] == "drift"


def test_no_runtime_privileges_in_parser():
    source = (ROOT / "src/vpn_reconcile.py").read_text()
    assert "subprocess" not in source
    assert "private_key" not in source.lower()
