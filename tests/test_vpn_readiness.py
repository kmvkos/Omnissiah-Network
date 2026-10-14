import importlib.util
import sys
from pathlib import Path

path = Path(__file__).resolve().parents[1] / "agents/app/vpn_readiness.py"
spec = importlib.util.spec_from_file_location("vpn_readiness", path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def test_readiness_never_returns_credentials(monkeypatch):
    class Result:
        returncode = 1
        stdout = ""
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: Result())
    monkeypatch.setattr(module.shutil, "which", lambda *_: "/usr/bin/wg")
    value = module.get_readiness({
        "name": "magos01", "mtls_required": True,
        "private_key": "VERY_SECRET", "manage_wireguard": False})
    assert value["vpn_enabled"] is False
    assert value["management_mode"] == "isolated"
    assert "VERY_SECRET" not in str(value)
    assert value["key_present"] is None


def test_readiness_detects_interface(monkeypatch):
    class Result:
        returncode = 0
        stdout = '[{"flags":["UP"],"linkinfo":{"info_kind":"wireguard"}}]'
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: Result())
    monkeypatch.setattr(module.shutil, "which", lambda *_: "/usr/bin/wg")
    value = module.get_readiness({"name": "magos02", "mtls_required": True})
    assert value["vpn_enabled"] is True
