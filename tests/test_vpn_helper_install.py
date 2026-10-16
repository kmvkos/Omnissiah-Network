"""Regression test for root VPN helper's deployed Python import layout.

The actual root command is /usr/local/libexec/omnissiah-vpn-helper. Python
imports from that executable's directory, not from the project sources.
"""
from pathlib import Path
import shutil
import subprocess
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
TASKS = ROOT / "ansible/roles/services/tasks/main.yml"
ROOT_MODULES = (
    "vpn_helper.py",
    "vpn_linux_backend.py",
    "vpn_linux_preflight.py",
    "vpn_mesh_transaction.py",
    "vpn_route_journal.py",
    "vpn_route_executor_sim.py",
    "vpn_reconcile.py",
    "vpn_route_tx.py",
)


def test_root_helper_is_importable_in_ansible_install_layout(tmp_path):
    tasks = yaml.safe_load(TASKS.read_text())
    alias = next(task for task in tasks if task.get("name") ==
        "Install importable VPN helper module for transaction backend")
    copy = alias["ansible.builtin.copy"]
    assert copy["src"] == "{{ omnissiah_project_dir }}/deploy/vpn_helper.py"
    assert copy["dest"] == "/usr/local/libexec/vpn_helper.py"
    assert copy["remote_src"] is True
    assert copy["owner"] == "root" and copy["group"] == "root"
    assert copy["mode"] == "0644"
    assert alias["when"] == "inventory_hostname in groups.magos"

    for name in ROOT_MODULES:
        shutil.copyfile(ROOT / "deploy" / name, tmp_path / name)
    shutil.copyfile(ROOT / "deploy/vpn_helper.py", tmp_path / "omnissiah-vpn-helper")
    # Smoke-test exactly the Python import that failed on magos01, in an
    # isolated subprocess without adding the repo's deploy directory to sys.path.
    completed = subprocess.run(
        [sys.executable, "-c",
         "from vpn_linux_backend import IsolatedLinuxMeshBackend; "
         "from vpn_mesh_transaction import run_offline_mesh_transaction; "
         "from vpn_helper import render, validate_plan; "
         "print('root helper imports OK')"],
        cwd=tmp_path, capture_output=True, text=True, timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
    assert "root helper imports OK" in completed.stdout


def test_executable_and_importable_module_from_same_source():
    tasks = yaml.safe_load(TASKS.read_text())
    copies = [task.get("ansible.builtin.copy", {}) for task in tasks]
    by_dest = {copy.get("dest"): copy for copy in copies if copy.get("dest")}
    assert by_dest["/usr/local/libexec/omnissiah-vpn-helper"]["src"] == (
        by_dest["/usr/local/libexec/vpn_helper.py"]["src"])
    assert by_dest["/usr/local/libexec/omnissiah-vpn-helper"]["mode"] == "0700"
