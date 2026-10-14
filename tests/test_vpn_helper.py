"""Pure, non-root tests of the restricted VPN helper; no network mutation."""
import base64
import importlib.util
import sys
from pathlib import Path
import pytest

path = Path(__file__).resolve().parents[1] / "deploy" / "vpn_helper.py"
spec = importlib.util.spec_from_file_location("vpn_helper", path)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)
KEY1 = base64.b64encode(b"a" * 32).decode()
KEY2 = base64.b64encode(b"b" * 32).decode()


def plan(peers=None):
    return {"node_name":"magos01", "address":"10.77.0.2/32",
            "listen_port":51820, "peers":peers if peers is not None else [
                {"public_key":KEY1, "endpoint":"192.168.32.169:51820",
                 "allowed_ips":["10.77.0.3/32"],"keepalive":25}]}


def test_plan_and_render():
    p = mod.validate_plan(plan(), "magos01")
    result = mod.render(p, "PRIVATE_KEY_NOT_PRINTED_BY_HELPER")
    assert result.count("[Peer]") == 1
    assert "0.0.0.0/0" not in result


@pytest.mark.parametrize("bad", ["0.0.0.0/0", "10.77.0.0/24", "::/0", "bad"])
def test_no_broad_routes(bad):
    p = plan()
    p["peers"][0]["allowed_ips"] = [bad]
    with pytest.raises(mod.HelperError):
        mod.validate_plan(p, "magos01")


def test_no_duplicate_peers():
    peer = plan()["peers"][0]
    p = plan([peer, dict(peer, public_key=KEY2)])
    with pytest.raises(mod.HelperError):
        mod.validate_plan(p, "magos01")


def test_no_incorrect_node_or_extra_commands():
    with pytest.raises(mod.HelperError):
        mod.validate_plan(plan(), "magos02")
    p = plan()
    p["shell_command"] = "reboot"
    with pytest.raises(mod.HelperError):
        mod.validate_plan(p, "magos01")


def test_rejects_non_host_address():
    p = plan()
    p["address"] = "10.77.0.0/24"
    with pytest.raises(mod.HelperError):
        mod.validate_plan(p, "magos01")


def test_prepared_config_header_allows_explicit_start(monkeypatch, tmp_path, capsys):
    """Regression: header check must match a real newline, not literal backslash-n."""
    cfg = tmp_path / "wg0.conf"
    cfg.write_text("# Managed by Omnissiah VPN v2\n[Interface]\n")
    monkeypatch.setattr(mod, "WG_DIR", tmp_path)
    monkeypatch.setattr(mod.os, "geteuid", lambda: 0)
    monkeypatch.setattr(sys, "argv", ["vpn_helper", "start", "--node-name", "magos01"])
    class Missing:
        returncode = 1
    monkeypatch.setattr(mod.subprocess, "run", lambda *a, **kw: Missing())
    executed = []
    monkeypatch.setattr(mod, "run", lambda argv, **kw: executed.append(argv) or "")
    mod.main()
    assert ["wg-quick", "up", "wg0"] in executed
    assert ["systemctl", "enable", "wg-quick@wg0.service"] in executed
    assert '"active": true' in capsys.readouterr().out.lower()
