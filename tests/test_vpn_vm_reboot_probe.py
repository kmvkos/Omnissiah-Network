"""Offline tests for the read-only reboot acceptance probe."""
import base64
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import os

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("vpn_vm_reboot_probe", ROOT / "scripts/vpn_vm_reboot_probe.py")
probe = module_from_spec(spec)
spec.loader.exec_module(probe)


class Result:
    returncode = 0
    def __init__(self, stdout):
        self.stdout = stdout


def observations(*, management="ens33", routes=True, timestamp=1000,
                 extra=False, boot_enabled="enabled"):
    a = base64.b64encode(b"a" * 32).decode()
    b = base64.b64encode(b"b" * 32).decode()
    data = {
        ("wg", "show", "wg0", "peers"): a + "\n" + b,
        ("wg", "show", "wg0", "latest-handshakes"): f"{a} {timestamp}\n{b} {timestamp}",
        ("wg", "show", "wg0", "allowed-ips"): f"{a}\t10.77.0.3/32\n{b}\t10.77.0.4/32",
        ("ip", "-j", "-4", "route", "show", "table", "main"): json.dumps([
            {"dst": "10.77.0.3", "dev": "wg0"},
            *([{"dst": "10.77.0.4", "dev": "wg0"}] if routes else []),
            *([{"dst": "10.77.0.99", "dev": "wg0"}] if extra else []),
            {"dst": "192.168.32.0/24", "dev": "ens33"},
        ]),
        ("ip", "-j", "-4", "route", "get", "192.168.32.167"): json.dumps(
            [{"dst": "192.168.32.167", "dev": management,
              "prefsrc": "192.168.32.168"}]),
        ("systemctl", "is-enabled", "wg-quick@wg0.service"): boot_enabled,
        ("systemctl", "is-active", "wg-quick@wg0.service"): "active",
    }

    def runner(argv, **kwargs):
        assert kwargs["check"] is False and kwargs["timeout"] == 10
        return Result(data[tuple(argv)])
    return runner, (a, b)


def test_before_and_after_reboot_consistent_no_raw_keys(tmp_path):
    runner, keys = observations()
    baseline = probe.snapshot("192.168.32.167", runner=runner, now=1050)
    assert baseline["handshakes_fresh"] is True
    assert baseline["wg0_routes"] == ["10.77.0.3/32", "10.77.0.4/32"]
    assert probe.verify(baseline, baseline) == []
    text = json.dumps(baseline)
    assert all(k not in text for k in keys)
    assert "private_key" not in text and "preshared" not in text
    out = tmp_path / "baseline.json"
    probe.write_baseline(out, baseline)
    assert (out.stat().st_mode & 0o777) == 0o600
    loaded = probe.load_baseline(out)
    assert loaded == baseline


def test_reboot_drift_detected_for_mgmt_or_missing_route():
    runner, _ = observations()
    previous = probe.snapshot("192.168.32.167", runner=runner, now=1050)
    runner2, _ = observations(management="eth0")
    now = probe.snapshot("192.168.32.167", runner=runner2, now=1050)
    assert "management" in probe.verify(previous, now)
    runner3, _ = observations(routes=False)
    with pytest.raises(probe.ProbeError, match="missing_or_duplicate_wg0_route"):
        probe.snapshot("192.168.32.167", runner=runner3, now=1050)


def test_reboot_refuses_mgmt_path_through_vpn():
    runner, _ = observations(management="wg0")
    with pytest.raises(probe.ProbeError, match="unsafe_management_route"):
        probe.snapshot("192.168.32.167", runner=runner, now=1050)


def test_reboot_refuses_unexpected_vpn_route():
    runner, _ = observations(extra=True)
    with pytest.raises(probe.ProbeError, match="unexpected_wg0_route"):
        probe.snapshot("192.168.32.167", runner=runner, now=1050)


def test_boot_persistence_and_handshake_must_be_current():
    runner, _ = observations(boot_enabled="disabled")
    with pytest.raises(probe.ProbeError, match="wg_quick_not_enabled_or_active"):
        probe.snapshot("192.168.32.167", runner=runner, now=1050)
    runner, _ = observations(timestamp=1)
    data = probe.snapshot("192.168.32.167", runner=runner, now=1050)
    assert data["handshakes_fresh"] is False


def test_changed_handshakes_do_not_count_as_peer_identity_drift():
    runner, _ = observations(timestamp=1000)
    before = probe.snapshot("192.168.32.167", runner=runner, now=1045)
    after = probe.snapshot("192.168.32.167", runner=runner, now=1050)
    assert probe.verify(before, after) == []


def test_no_raw_peer_keys_in_failure_response(tmp_path, capsys):
    runner, keys = observations()
    baseline = probe.snapshot("192.168.32.167", runner=runner, now=1050)
    output = tmp_path / "safe.json"
    probe.write_baseline(output, baseline)
    assert probe.main(["verify", "--controller-ip", "not-an-ip",
                       "--baseline", str(output)]) == 2
    message = capsys.readouterr().out
    assert '"result": "fail"' in message
    assert "invalid_controller_ip" in message
    assert all(k not in message for k in keys)


def test_symlinked_baseline_is_rejected(tmp_path):
    source = tmp_path / "real"
    source.write_text("{}")
    symlink = tmp_path / "link"
    symlink.symlink_to(source)
    with pytest.raises(probe.ProbeError, match="unsafe_baseline"):
        probe.load_baseline(symlink)
    with pytest.raises(probe.ProbeError, match="unsafe_baseline_destination"):
        probe.write_baseline(symlink, {"schema_version": 1})
    assert source.read_text() == "{}"


def test_read_only_commands_never_use_network_writes():
    script = (ROOT / "scripts/vpn_vm_reboot_probe.py").read_text()
    assert "subprocess.run" in script
    assert '["wg", "show", "wg0", "peers"]' in script
    assert '["ip", "-j", "-4", "route", "get", address]' in script
    for unsafe in ('"wg-quick", "up"', '"wg-quick", "down"',
                   '"ip", "-4", "route", "add"', '"systemctl", "restart"'):
        assert unsafe not in script
