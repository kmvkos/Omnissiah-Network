"""nftables ACL engine contract: isolated table, strict preview, stale revision, rollback."""
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import uuid

import pytest

module_path = Path(__file__).resolve().parents[1] / "deploy" / "vpn_acl_policy.py"
spec = importlib.util.spec_from_file_location("vpn_acl_policy", module_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


KEY = "A" * 43 + "="
KEY2 = "B" * 43 + "="


def manifest():
    return {
        "node_name": "magos03", "address": "10.77.0.4/32",
        "clients": [{
            "name": "cognitor01", "address": "10.77.0.5/32",
            "public_key": KEY,
            "targets": [{"network": "172.16.40.10/32", "via_magos": False,
                         "rules": [
                             {"protocol": "tcp", "port": 22, "decision": "allow"},
                             {"protocol": "udp", "port": 53, "decision": "deny"},
                         ]}],
        }],
    }


class FakeCommands:
    def __init__(self):
        self.present = False
        self.calls = []
        self.allow_route = True
        self.fail_next_write = False
        self.revision = None
        self.forwarding = True

    def __call__(self, argv, *, input=None, text=None, capture_output=None, timeout=None):
        self.calls.append((tuple(argv), input))
        out = ""
        rc = 0
        if argv[:3] == ["wg", "show", "wg0"]:
            out = ("interface\\tkey\\tlisten\\tmark\\n".replace("\\t", "\t").replace("\\n", "\n")
                   + f"{KEY}\t(none)\t(none)\t10.77.0.5/32\t0\t0\t0\t0\n")
        elif argv == ["sysctl", "-n", "net.ipv4.ip_forward"]:
            out = "1\n" if self.forwarding else "0\n"
        elif argv[:4] == ["ip", "-j", "route", "get"]:
            out = json.dumps([{"dev": "eth1" if self.allow_route else "wg0"}])
        elif argv[:4] == ["nft", "-j", "list", "table"]:
            rc = 0 if self.present else 1
            if self.present:
                out = json.dumps({"nftables": [
                    {"table": {"family": "inet", "name": mod.TABLE}},
                    {"chain": {"name": "forward", "hook": "forward",
                               "prio": -30, "policy": "accept"}},
                    {"rule": {"comment": "omnissiah-rev-" + (self.revision or "0" * 64),
                              "expr": [{"counter": {"packets": 0, "bytes": 0}}]}},
                ]})
        elif argv[:3] == ["nft", "-c", "-f"]:
            assert "table inet omnissiah_acl_v2" in input
        elif argv[:3] == ["nft", "-f", "-"]:
            if self.fail_next_write:
                self.fail_next_write = False
                rc = 1
            else:
                self.present = "add table" in input
                if self.present:
                    import re
                    match = re.search(r"omnissiah-rev-([a-f0-9]{64})", input)
                    assert match
                    self.revision = match.group(1)
                else:
                    self.revision = None
        else:
            raise AssertionError("Unexpected system command " + str(argv))
        return SimpleNamespace(returncode=rc, stdout=out, stderr="mock")


def engine(tmp_path, fake):
    return mod.LinuxACL(node_name="magos03", state=tmp_path,
                        protected_ips=("192.168.32.167", "192.168.32.172"),
                        runner=fake)


def test_normalization_and_nft_compiler_is_scoped():
    m = mod.normalize(manifest(), "magos03", ["192.168.32.167"])
    output = mod.nft_batch(m)
    assert "table inet omnissiah_acl_v2" in output
    assert 'iifname "wg0" ip saddr 10.77.0.5' in output
    assert "tcp dport 22 accept" in output
    assert "udp dport 53 drop" in output
    assert "ip daddr 172.16.40.10/32 drop" in output
    assert "flush ruleset" not in output
    assert "iptables" not in output
    assert "route add" not in output
    assert "policy drop" not in output
    assert "hook input" not in output


@pytest.mark.parametrize("change", [
    lambda m: m.update(address="10.77.0.4/24"),
    lambda m: m.update(node_name="magos01"),
    lambda m: m["clients"][0].update(address="0.0.0.0/32"),
    lambda m: m["clients"][0]["targets"][0].update(network="0.0.0.0/0"),
    lambda m: m["clients"][0]["targets"][0].update(network="192.168.32.0/24"),
    lambda m: m["clients"][0]["targets"][0].update(network="10.77.0.4/32"),
    lambda m: m["clients"][0]["targets"][0]["rules"].append(
        {"protocol": "tcp", "port": 22, "decision": "deny"}),
    lambda m: m["clients"][0]["targets"][0]["rules"][0].update(port=0),
    lambda m: m["clients"][0]["targets"][0]["rules"][0].update(decision="REJECT"),
    lambda m: m["clients"][0]["targets"][0].update(via_magos="auto"),
])
def test_fail_closed_bad_manifest(change):
    m = manifest()
    change(m)
    with pytest.raises(mod.PolicyRejected):
        mod.normalize(m, "magos03", ["192.168.32.167", "192.168.32.172"])


def test_reject_is_explicit_nft_rejection_not_drop():
    m = manifest()
    m["clients"][0]["targets"][0]["rules"][1]["decision"] = "reject"
    result = mod.nft_batch(mod.normalize(m, "magos03"))
    assert "udp dport 53 reject with icmpx type admin-prohibited" in result
    assert "flush ruleset" not in result


def test_read_only_preview_never_runs_mutating_nft(tmp_path):
    fake = FakeCommands()
    result = engine(tmp_path, fake).preview(manifest())
    assert result["route_preflight_ok"] is True
    assert result["writes_performed"] is False
    assert result["client_count"] == 1
    assert result["rule_count"] == 2
    assert not any(cmd[:3] == ("nft", "-f", "-") for cmd, _ in fake.calls)
    assert not list(tmp_path.iterdir())


def test_route_mismatch_blocks_before_nft_apply(tmp_path, monkeypatch):
    fake = FakeCommands()
    fake.allow_route = False
    monkeypatch.setenv("OMNISSIAH_ENABLE_POLICY_APPLY", "YES")
    monkeypatch.setenv("OMNISSIAH_POLICY_RESTORE_READY", "YES")
    with pytest.raises(mod.PolicyRejected):
        engine(tmp_path, fake).preview(manifest())
    assert not fake.present


def test_policy_apply_disabled_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("OMNISSIAH_ENABLE_POLICY_APPLY", raising=False)
    fake = FakeCommands()
    revision = engine(tmp_path, fake).preview(manifest())["revision"]
    with pytest.raises(mod.PolicyRejected):
        engine(tmp_path, fake).apply(manifest(), revision=revision,
                                    operation_id=str(uuid.uuid4()))
    assert not fake.present


def test_guarded_apply_and_rollback_are_atomic(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNISSIAH_ENABLE_POLICY_APPLY", "YES")
    monkeypatch.setenv("OMNISSIAH_POLICY_RESTORE_READY", "YES")
    fake = FakeCommands()
    worker = engine(tmp_path, fake)
    revision = worker.preview(manifest())["revision"]
    with pytest.raises(mod.PolicyRejected):
        worker.apply(manifest(), revision="0" * 64, operation_id=str(uuid.uuid4()))
    response = worker.apply(manifest(), revision=revision, operation_id=str(uuid.uuid4()))
    assert response["state"] == "committed"
    assert response["revision"] == revision
    assert fake.present
    assert worker.status()["rollback_available"] is True
    assert worker.status()["active_revision"] == revision
    with pytest.raises(mod.PolicyRejected):
        worker.rollback(revision="f" * 64, operation_id=str(uuid.uuid4()))
    result = worker.rollback(revision=revision, operation_id=str(uuid.uuid4()))
    assert result["state"] == "rolled_back"
    assert not fake.present
    assert worker.status()["active_revision"] is None
    assert not (tmp_path / "acl-active.json").exists()
    assert not (tmp_path / "acl-previous.json").exists()


def test_apply_failure_rolls_back_without_taking_other_tables(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNISSIAH_ENABLE_POLICY_APPLY", "YES")
    monkeypatch.setenv("OMNISSIAH_POLICY_RESTORE_READY", "YES")
    fake = FakeCommands()
    service = engine(tmp_path, fake)
    preview = service.preview(manifest())
    fake.fail_next_write = True
    with pytest.raises(mod.PolicyRejected):
        service.apply(manifest(), revision=preview["revision"], operation_id=str(uuid.uuid4()))
    assert not fake.present
    assert not (tmp_path / "acl-active.json").exists()
    assert not (tmp_path / "acl-previous.json").exists()
    assert all("flush ruleset" not in str(value) for _, value in fake.calls)


def test_unmanaged_existing_nft_table_is_refused(tmp_path):
    fake = FakeCommands()
    fake.present = True
    with pytest.raises(mod.PolicyRejected, match="state mismatch"):
        engine(tmp_path, fake).preview(manifest())
    assert not any(cmd[:3] == ("nft", "-f", "-") for cmd, _ in fake.calls)


def test_missing_nft_table_after_reboot_is_reported_as_drift(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNISSIAH_ENABLE_POLICY_APPLY", "YES")
    monkeypatch.setenv("OMNISSIAH_POLICY_RESTORE_READY", "YES")
    fake = FakeCommands()
    worker = engine(tmp_path, fake)
    revision = worker.preview(manifest())["revision"]
    worker.apply(manifest(), revision=revision, operation_id=str(uuid.uuid4()))
    fake.present = False  # Simulate reboot or manual nft flush.
    state = worker.status()
    assert state["drift"] is True
    assert state["recovery_required"] is True
    assert state["active_revision"] == revision
    with pytest.raises(mod.PolicyRejected):
        worker.preview(manifest())


def test_boot_restore_recovers_last_trusted_acl_before_wg0(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNISSIAH_ENABLE_POLICY_APPLY", "YES")
    monkeypatch.setenv("OMNISSIAH_POLICY_RESTORE_READY", "YES")
    monkeypatch.setattr(mod.os, "geteuid", lambda: 0)
    fake = FakeCommands()
    worker = engine(tmp_path, fake)
    revision = worker.preview(manifest())["revision"]
    worker.apply(manifest(), revision=revision, operation_id=str(uuid.uuid4()))
    fake.present = False
    fake.revision = None
    result = worker.restore_on_boot()
    assert result["state"] == "restored"
    assert fake.present is True
    assert worker.status()["drift"] is False


def test_cross_magos_route_not_inferred_from_wg_interface(tmp_path):
    fake = FakeCommands()
    plan = manifest()
    plan["clients"][0]["targets"][0]["via_magos"] = True
    with pytest.raises(mod.PolicyRejected, match="Cross-Magos"):
        engine(tmp_path, fake).preview(plan)


def test_forwarding_disabled_blocks_policy_apply(tmp_path):
    fake = FakeCommands()
    fake.forwarding = False
    with pytest.raises(mod.PolicyRejected, match="forwarding"):
        engine(tmp_path, fake).preview(manifest())


def test_last_policy_can_be_explicitly_removed(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNISSIAH_ENABLE_POLICY_APPLY", "YES")
    monkeypatch.setenv("OMNISSIAH_POLICY_RESTORE_READY", "YES")
    fake = FakeCommands()
    worker = engine(tmp_path, fake)
    revision = worker.preview(manifest())["revision"]
    worker.apply(manifest(), revision=revision, operation_id=str(uuid.uuid4()))
    empty = {"node_name": "magos03", "address": "10.77.0.4/32", "clients": []}
    next_revision = worker.preview(empty)["revision"]
    result = worker.apply(empty, revision=next_revision, operation_id=str(uuid.uuid4()))
    assert result["state"] == "committed"
    assert worker.status()["active_revision"] == next_revision
    assert "ip saddr" not in mod.nft_batch(mod.normalize(empty, "magos03"))
