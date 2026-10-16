"""Real WG add-only Cognitor tests in a disposable Linux network namespace."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "deploy"))
from vpn_cognitor_transaction import add_cognitor
from vpn_cognitor_preview import preview_add
from vpn_helper import render
from vpn_reconcile import parse_wg_dump


def run(*args, input=None):
    return subprocess.run(args, capture_output=True, text=True,
                          check=True, timeout=20, input=input)


def make_key():
    private = run("wg", "genkey").stdout.strip()
    public = run("wg", "pubkey", input=private + "\n").stdout.strip()
    return private, public


class CognitorLiveNetnsTest(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(), 0, "CI requires root, disposable netns only")
        self.dir = tempfile.TemporaryDirectory(prefix="omni-cognitor-netns-")
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name)
        self.ns = "cog-" + uuid.uuid4().hex[:8]
        run("ip", "netns", "add", self.ns)
        self.addCleanup(self.destroy)
        run("ip", "-n", self.ns, "link", "add", "wg0", "type", "wireguard")
        run("ip", "-n", self.ns, "link", "set", "lo", "up")
        run("ip", "-n", self.ns, "address", "add", "10.77.0.4/32", "dev", "wg0")
        run("ip", "-n", self.ns, "link", "set", "wg0", "up")
        run("ip", "-n", self.ns, "-4", "route", "add", "192.0.2.0/24", "dev", "lo")
        secret, _ = make_key()
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.file = self.root / "wg0.conf"
        self.old = []
        for ip, underlay in [(2, 2), (3, 3)]:
            _, pub = make_key()
            self.old.append({"public_key": pub,
                             "endpoint": f"192.0.2.{underlay}:51820",
                             "allowed_ips": [f"10.77.0.{ip}/32"],
                             "keepalive": 25})
        self.node = {"node_name": "magos03", "address": "10.77.0.4/32",
                     "listen_port": 51820, "peers": self.old}
        self.file.write_text(render(self.node, secret))
        self.file.chmod(0o600)
        self.private = self.state / "private.key"
        self.private.write_text(secret + "\n")
        self.private.chmod(0o600)
        run("ip", "netns", "exec", self.ns, "wg", "set", "wg0",
            "private-key", str(self.private), "listen-port", "51820")
        for p in self.old:
            run("ip", "netns", "exec", self.ns, "wg", "set", "wg0", "peer",
                p["public_key"], "endpoint", p["endpoint"],
                "allowed-ips", p["allowed_ips"][0],
                "persistent-keepalive", "25")
            run("ip", "-n", self.ns, "-4", "route", "add", p["allowed_ips"][0],
                "dev", "wg0", "table", "main")
        _, client_public = make_key()
        self.plan = {"node_name": "magos03", "address": "10.77.0.4/32",
                     "client_name": "cognitor01",
                     "client_address": "10.77.0.5/32",
                     "public_key": client_public}
        self.initial_file = self.file.read_bytes()
        self.initial = self.snapshot()
        self.preview = preview_add(self.plan, expected_name="magos03",
                                   current_peers=self.initial[0],
                                   routes=self.initial[1],
                                   persisted_config=self.file.read_text(),
                                   protected_addresses=["192.0.2.1"])
        self.assertTrue(self.preview["safe_to_plan"])

    def destroy(self):
        subprocess.run(["ip", "netns", "del", self.ns],
                       capture_output=True, text=True, timeout=20, check=False)

    def runner(self, argv, **kw):
        return subprocess.run(["ip", "netns", "exec", self.ns, *argv], **kw)

    def snapshot(self):
        from vpn_linux_preflight import LinuxReadOnlyPreflight
        return LinuxReadOnlyPreflight(self.runner).snapshot()

    def test_add_client_preserves_mesh_and_persists_config(self):
        outcome = add_cognitor(
            self.plan, operation_id=str(uuid.uuid4()),
            expected_revision=self.preview["revision"],
            protected_addresses=["192.0.2.1"], runner=self.runner,
            state=self.state, config=self.file)
        self.assertEqual(outcome["state"], "committed")
        peers, routes = self.snapshot()
        old = {p["public_key"]: (p["allowed_ips"], p["keepalive"])
               for p in self.initial[0]}
        new = {p["public_key"]: (p["allowed_ips"], p["keepalive"])
               for p in peers}
        for key, value in old.items():
            self.assertEqual(new[key], value)
        self.assertEqual(new[self.plan["public_key"]][0], ["10.77.0.5/32"])
        self.assertIn("10.77.0.5/32", {r.get("dst") for r in routes})
        self.assertIn(self.plan["public_key"], self.file.read_text())
        self.assertIn("# Cognitor: cognitor01", self.file.read_text())
        record = json.loads((self.state / "mesh-transaction.json").read_text())
        self.assertEqual(record["state"], "committed")
        self.assertEqual(record["route_ops"], 1)
        self.assertNotIn(secret if False else "PrivateKey", json.dumps(record))

    def test_route_failure_after_mutation_rolls_back_client_only(self):
        def runner(argv, **kw):
            if argv[:4] == ["ip", "-4", "route", "add"] and "10.77.0.5/32" in argv:
                # Real route mutation followed by an injected execution failure.
                result = self.runner(argv, **kw)
                self.assertEqual(result.returncode, 0)
                return subprocess.CompletedProcess(argv, 1, stdout="", stderr="simulated failure")
            return self.runner(argv, **kw)
        with self.assertRaises(Exception):
            add_cognitor(self.plan, operation_id=str(uuid.uuid4()),
                         expected_revision=self.preview["revision"],
                         protected_addresses=["192.0.2.1"], runner=runner,
                         state=self.state, config=self.file)
        peers, routes = self.snapshot()
        self.assertEqual({p["public_key"] for p in peers},
                         {p["public_key"] for p in self.initial[0]})
        self.assertNotIn("10.77.0.5/32", {r.get("dst") for r in routes})
        self.assertEqual(self.file.read_bytes(), self.initial_file)
        record = json.loads((self.state / "mesh-transaction.json").read_text())
        self.assertEqual(record["state"], "rolled_back")
