"""Read-only Linux probe: exact AllowedIPs/route checks, no mutations."""
import importlib.util
from pathlib import Path
import json
import os
from types import SimpleNamespace as Obj

import pytest

path = Path(__file__).resolve().parents[1] / "deploy" / "vpn_cross_path_probe.py"
spec = importlib.util.spec_from_file_location("vpn_cross_path_probe", path)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

C = "C"*43+"="
S = "B"*43+"="
T = "A"*43+"="

def manifest(role="source"):
    source = role == "source"
    return {
        "node_name": "magos03" if source else "magos01",
        "address": "10.77.0.4/32" if source else "10.77.0.2/32",
        "role": role, "own_vpn_cidr": "10.77.0.4/32" if source else "10.77.0.2/32",
        "peer_name": "magos01" if source else "magos03",
        "peer_public_key": T if source else S,
        "peer_vpn_cidr": "10.77.0.2/32" if source else "10.77.0.4/32",
        "client_cidr": "10.77.0.5/32", "client_public_key": C,
        "resource_cidr": "192.165.42.2/32",
        "required_peer_allowed_ip": "192.165.42.2/32" if source else "10.77.0.5/32",
        "required_route": "192.165.42.2/32" if source else "10.77.0.5/32",
    }


def persisted(role="source", included=True):
    peer = T if role == "source" else S
    allowed = ("10.77.0.2/32" if role == "source" else "10.77.0.4/32")
    if included:
        allowed += ", " + ("192.165.42.2/32" if role == "source" else "10.77.0.5/32")
    text = ("[Interface]\nPrivateKey = NOT RETURNED\n"
            f"[Peer]\nPublicKey = {peer}\nAllowedIPs = {allowed}\n")
    if role == "source":
        text += f"[Peer]\nPublicKey = {C}\nAllowedIPs = 10.77.0.5/32\n"
    return text


class Observe:
    def __init__(self, role="source", included=True):
        self.role, self.included = role, included
        self.calls = []
        self.foreign_conflict = False
        self.broken_route = False

    def __call__(self, cmd, **kwargs):
        self.calls.append(tuple(cmd))
        allowed = ("10.77.0.2/32" if self.role == "source" else "10.77.0.4/32")
        if self.included:
            allowed += "," + ("192.165.42.2/32" if self.role == "source" else "10.77.0.5/32")
        peer = T if self.role == "source" else S
        if cmd[:3] == ["wg", "show", "wg0"]:
            body = ("private\tpublic\t51820\t0\n"
                    f"{peer}\t(none)\t192.168.32.168:51820\t{allowed}\t0\t0\t0\t25\n")
            if self.role == "source":
                body += f"{C}\t(none)\t(none)\t10.77.0.5/32\t0\t0\t0\t25\n"
            if self.foreign_conflict:
                body += f"{'D'*43+'='}\t(none)\t(none)\t{manifest(self.role)['required_route']}\t0\t0\t0\t25\n"
            return Obj(returncode=0, stdout=body, stderr="")
        if cmd[:2] == ["sysctl", "-n"]:
            return Obj(returncode=0, stdout="1\n" if "forward" in cmd[-1] else "0\n", stderr="")
        if cmd[:4] == ["ip", "-j", "-4", "route"]:
            dest = cmd[5]
            device = ("eth1" if dest.startswith("192.168.32.") else
                      "eth1" if self.role == "destination" and dest == "192.165.42.2" else
                      "eth1" if self.broken_route else "wg0")
            return Obj(returncode=0, stdout=json.dumps([{"dev": device}]), stderr="")
        raise AssertionError(f"Unexpected read-only command: {cmd}")


@pytest.fixture
def config(tmp_path):
    file = tmp_path / "wg0.conf"
    file.write_text(persisted())
    file.chmod(0o600)
    return file


def make_probe(plan, file, fake):
    return probe.LinuxCrossPathProbe(
        plan["node_name"], ["192.168.32.167", "192.168.32.172"],
        config=file, runner=fake)


def test_source_is_ready_only_when_live_and_persisted_routes_agree(config):
    plan = manifest()
    runner = Observe()
    response = make_probe(plan, config, runner).check(plan)
    assert response["gateway_checks_passed"] is True
    assert response["writes_performed"] is False
    assert response["protected_host_return_verified"] is False
    assert not any(cmd[:2] in (("wg", "set"), ("ip", "route"))
                   for cmd in runner.calls)


def test_missing_allowed_ips_in_kernel_or_disk_blocks(config):
    plan = manifest()
    for live, disk in [(False, True), (True, False)]:
        config.write_text(persisted(included=disk))
        result = make_probe(plan, config, Observe(included=live)).check(plan)
        assert result["gateway_checks_passed"] is False
        assert any("AllowedIPs" in msg for msg in result["blockers"])


def test_destination_check_includes_protected_LAN_and_return_route(config):
    plan = manifest("destination")
    config.write_text(persisted("destination"))
    result = make_probe(plan, config, Observe("destination")).check(plan)
    assert result["gateway_checks_passed"] is True


def test_conflicting_peer_ownership_fails_closed(config):
    plan = manifest()
    runner = Observe()
    runner.foreign_conflict = True
    result = make_probe(plan, config, runner).check(plan)
    assert result["gateway_checks_passed"] is False
    assert any("conflict" in s for s in result["blockers"])


def test_route_to_local_underlay_is_not_accepted(config):
    plan = manifest()
    runner = Observe()
    runner.broken_route = True
    result = make_probe(plan, config, runner).check(plan)
    assert result["gateway_checks_passed"] is False


def test_foreign_or_unsafe_plan_never_calls_kernel(config):
    runner = Observe()
    invalid = manifest()
    invalid["required_peer_allowed_ip"] = "0.0.0.0/0"
    with pytest.raises(probe.CrossPathCheckError):
        make_probe(invalid, config, runner).check(invalid)
    assert runner.calls == []


def test_persisted_peer_parser_handles_consecutive_peer_sections():
    peers = probe.parse_persisted_peers(persisted())
    assert set(peers) == {C,T}
    assert peers[T] == ["10.77.0.2/32", "192.165.42.2/32"]
