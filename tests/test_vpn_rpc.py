"""Nonprivileged tests for the local root VPN RPC transport."""
import importlib.util
import json
import os
from pathlib import Path
import sys

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "deploy" / "vpn_rpc.py"
spec = importlib.util.spec_from_file_location("vpn_rpc", SOURCE)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def test_rejects_unexpected_commands_and_wrong_identity(monkeypatch):
    monkeypatch.setenv("OMNISSIAH_NODE_NAME", "magos01")
    for body in (
        {"action":"shell", "node_name":"magos01"},
        {"action":"start", "node_name":"magos02"},
        {"action":"start", "node_name":"magos01", "command":"reboot"},
        {"action":"prepare", "node_name":"magos01"},
    ):
        with pytest.raises(ValueError):
            mod.process(body)


def test_prepare_passes_only_root_staged_file(monkeypatch, tmp_path):
    monkeypatch.setenv("OMNISSIAH_NODE_NAME", "magos01")
    monkeypatch.setattr(mod, "STATE", tmp_path / "vpn")
    observed = {}
    class Completed:
        returncode = 0
        stdout = '{"action":"prepare","changed":true,"peers":1}'
        stderr = ""
    def fake_run(args, **kwargs):
        observed["argv"] = args
        observed["staged"] = Path(args[-1]).read_text()
        observed["mode"] = os.stat(args[-1]).st_mode & 0o777
        return Completed()
    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    result = mod.process({"action":"prepare", "node_name":"magos01", "plan":{
        "node_name":"magos01", "address":"10.77.0.2/32", "listen_port":51820, "peers":[]}})
    assert result["action"] == "prepare"
    assert observed["mode"] == 0o600
    assert json.loads(observed["staged"])["node_name"] == "magos01"
    assert not list((tmp_path / "vpn").glob("rpc-*.json"))


def test_explicit_start_rejects_supplied_plan(monkeypatch):
    monkeypatch.setenv("OMNISSIAH_NODE_NAME", "magos01")
    with pytest.raises(ValueError):
        mod.process({"action":"start", "node_name":"magos01", "plan":{"shell":"any"}})
