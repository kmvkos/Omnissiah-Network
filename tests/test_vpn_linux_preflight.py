"""Read-only Linux kernel integration contract tests; no live commands."""
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
for name in ("vpn_route_tx", "vpn_route_journal", "vpn_reconcile", "vpn_linux_preflight"):
    spec = importlib.util.spec_from_file_location(name, ROOT / "deploy" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)

from vpn_linux_preflight import (
    KernelObservationError, LinuxReadOnlyPreflight, preview_route_commands
)
from vpn_route_tx import RouteConflict

KEY = "kxcRNbkovVjVFnZXdzaqljNFIStjy8fE/Ugb1G1LUm8="
DUMP = "SECRET\tPUBLIC\t51820\toff\n" + KEY + "\t(none)\t192.168.32.169:51820\t10.77.0.3/32\t100\t10\t20\t25\n"
ROUTES = '[{"dst":"10.77.0.3/32","dev":"wg0","protocol":"static"}]'


def fake_runner(*, bad_command=None, route_json=ROUTES):
    calls = []

    def invoke(argv, **kwargs):
        calls.append(argv)
        if bad_command and argv[0] == bad_command:
            return SimpleNamespace(returncode=1, stdout="", stderr="error")
        if argv == ["wg", "show", "wg0", "dump"]:
            return SimpleNamespace(returncode=0, stdout=DUMP, stderr="")
        if argv == ["ip", "-j", "-4", "route", "show", "table", "main"]:
            return SimpleNamespace(returncode=0, stdout=route_json, stderr="")
        raise AssertionError(f"Unexpected command {argv!r}")
    return invoke, calls


def test_real_snapshot_readonly_and_freshness():
    invoke, calls = fake_runner()
    probe = LinuxReadOnlyPreflight(invoke)
    wanted = [{"public_key": KEY, "allowed_ips": ["10.77.0.3/32"], "keepalive": 25},
              {"public_key": "new", "allowed_ips": ["10.77.0.4/32"], "keepalive": 25}]
    plan = probe.plan(wanted)
    assert plan["delta"]["add"] == ["10.77.0.4/32"]
    assert probe.recheck(plan)
    assert calls == [
        ["wg", "show", "wg0", "dump"],
        ["ip", "-j", "-4", "route", "show", "table", "main"],
        ["wg", "show", "wg0", "dump"],
        ["ip", "-j", "-4", "route", "show", "table", "main"]]
    preview = preview_route_commands(plan)
    assert preview["commands"] == [
        ["ip", "-4", "route", "add", "10.77.0.4/32", "dev", "wg0", "table", "main"]]
    assert preview["executable"] is False
    assert preview["writes_performed"] is False


@pytest.mark.parametrize("bad", ["wg", "ip"])
def test_fail_closed_on_unavailable_kernel_observation(bad):
    invoke, _ = fake_runner(bad_command=bad)
    with pytest.raises(KernelObservationError):
        LinuxReadOnlyPreflight(invoke).snapshot()


@pytest.mark.parametrize("invalid", ["{}", "not-json", '["missing route"]'])
def test_reject_incomplete_route_json(invalid):
    invoke, _ = fake_runner(route_json=invalid)
    with pytest.raises(KernelObservationError):
        LinuxReadOnlyPreflight(invoke).snapshot()


@pytest.mark.parametrize("bad", [
    {"op": "replace", "dst": "10.77.0.4/32", "dev": "wg0"},
    {"op": "add", "dst": "0.0.0.0/0", "dev": "wg0"},
    {"op": "add", "dst": "127.0.0.1/32", "dev": "wg0"},
    {"op": "add", "dst": "10.77.0.4/32", "dev": "eth0"},
    {"op": "add", "dst": "10.77.0.4/32", "dev": "wg0", "gateway": "1.1.1.1"},
])
def test_no_unsafe_route_command_preview(bad):
    with pytest.raises(RouteConflict):
        preview_route_commands({"schema_version": 1, "iface": "wg0",
                                "executable": False, "steps": [bad],
                                "rollback": []})


def test_no_linux_writes_are_exposed():
    source = (ROOT / "deploy" / "vpn_linux_preflight.py").read_text()
    assert "subprocess.run([" not in source
    assert "backend.apply(" not in source
    assert "backend.revert(" not in source
    assert "os.system" not in source
