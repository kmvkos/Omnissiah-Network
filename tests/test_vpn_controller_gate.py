"""Controller feature gate must be persisted from trusted installer settings."""
import ast
import json
from pathlib import Path
import secrets
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _run_config(tmp_path, monkeypatch, value):
    source = ROOT / "deploy/bootstrap.py"
    tree = ast.parse(source.read_text())
    fn = next(n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name == "ensure_environment")
    writes = []
    class FakeFernet:
        @staticmethod
        def generate_key():
            return b"safe-test-key"
        def __init__(self, key):
            pass
    namespace = {
        "Path": Path, "json": json, "secrets": secrets,
        "os": SimpleNamespace(environ={} if value is None else
                              {"OMNISSIAH_BOOTSTRAP_ROUTE_TRANSACTIONS": value}),
        "Fernet": FakeFernet,
        "dotenv_values": lambda path: {"WG_MASTER_KEY": "TESTKEY", "SECRET_KEY": "TESTSECRET"},
        "write_if_changed": lambda path, payload, mode: writes.append(payload.decode()) or True,
        "load_dotenv": lambda *args, **kwargs: None,
    }
    module = ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[]))
    exec(compile(module, str(source), "exec"), namespace)
    return namespace["ensure_environment"], writes


@pytest.mark.parametrize("setting,expected", [
    (None, "NO"), ("false", "NO"), ("true", "YES"),
])
def test_controller_route_tx_gate_is_explicit_and_fail_closed(tmp_path, monkeypatch, setting, expected):
    configure, writes = _run_config(tmp_path, monkeypatch, setting)
    assert configure(tmp_path, tmp_path)
    lines = writes[0].splitlines()
    assert any(line == 'VPN_ROUTE_TRANSACTIONS_ENABLED="' + expected + '"' for line in lines)
    assert any(line.startswith("SECRET_KEY=") for line in lines)


def test_invalid_controller_gate_fails_before_write(tmp_path, monkeypatch):
    configure, writes = _run_config(tmp_path, monkeypatch, "YES")
    with pytest.raises(ValueError, match="Invalid route transaction"):
        configure(tmp_path, tmp_path)
    assert writes == []


def test_ansible_sets_controller_switch_from_inventory_default_false():
    controller = (ROOT / "ansible/roles/controller/tasks/main.yml").read_text()
    assert "OMNISSIAH_BOOTSTRAP_ROUTE_TRANSACTIONS" in controller
    assert "omnissiah_vpn_route_transactions_controller_enabled | default(false)" in controller
