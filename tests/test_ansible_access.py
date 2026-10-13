"""Exercise production Ansible access checks and cross-play failure handling."""
import json
import os
from pathlib import Path
import socket
import subprocess

import pytest

from control_inventory import create_inventory

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(not os.getenv('OMNISSIAH_TEST_CONTROL_VENV'), reason='Ansible validation environment required')


def inventory(tmp_path, count=3):
    document = create_inventory([f'192.168.50.{i}' for i in range(10, count + 11)], 'admin')
    document['all']['vars'].update(ansible_connection='local', ansible_become=False)
    return document


def playbook(document, path, filename, *arguments):
    path.write_text(json.dumps(document))
    return subprocess.run([os.environ['OMNISSIAH_TEST_CONTROL_VENV'] + '/bin/ansible-playbook',
                           '-i', str(path), filename, *arguments], cwd=ROOT / 'ansible',
                          capture_output=True, text=True, timeout=30)


@pytest.mark.skipif(os.geteuid() != 0, reason='Successful local raw root check requires root')
def test_access_check_succeeds_for_every_host_without_installing(tmp_path):
    result = playbook(inventory(tmp_path, 10), tmp_path / 'inventory.yml', 'access.yml')
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'changed=0' in result.stdout
    for name in ['omni01'] + [f'magos{i:02d}' for i in range(1, 11)]:
        assert f'ok: [{name}]' in result.stdout
    assert 'Install system dependencies' not in result.stdout


@pytest.mark.parametrize('failure', ['missing-sudo', 'not-root', 'unreachable'])
def test_failed_node_stops_production_playbook_before_python_ca_or_services(tmp_path, failure, monkeypatch):
    document = inventory(tmp_path)
    bad = document['all']['children']['magos']['hosts']['magos01']
    if failure == 'unreachable':
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); port = listener.getsockname()[1]
        bad.update(ansible_connection='ssh', ansible_host='127.0.0.1', ansible_port=port)
    else:
        commands = tmp_path / 'commands'; commands.mkdir()
        fake_id = commands / 'id'
        fake_id.write_text("#!/bin/sh\nprintf '1000\\n'\n"); fake_id.chmod(0o755)
        if failure == 'not-root':
            fake_sudo = commands / 'sudo'
            fake_sudo.write_text('#!/bin/sh\nexit 1\n'); fake_sudo.chmod(0o755)
        plugins = tmp_path / 'connections'; plugins.mkdir()
        (plugins / 'limited_local.py').write_text("""import os, shlex
from ansible.plugins.connection import local
DOCUMENTATION = local.DOCUMENTATION.replace('name: local', 'name: limited_local')
class Connection(local.Connection):
    transport = 'limited_local'
    def exec_command(self, cmd, *args, **kwargs):
        cmd = 'export PATH=' + shlex.quote(os.environ['OMNISSIAH_TEST_REMOTE_PATH']) + '; ' + cmd
        return super().exec_command(cmd, *args, **kwargs)
""")
        monkeypatch.setenv('ANSIBLE_CONNECTION_PLUGINS', str(plugins))
        monkeypatch.setenv('OMNISSIAH_TEST_REMOTE_PATH', str(commands))
        bad['ansible_connection'] = 'limited_local'
    # The full production playbook is used. Only local source preparation is
    # skipped so it can run against edited source; all installation plays remain.
    result = playbook(document, tmp_path / 'inventory.yml', 'site.yml', '--tags', 'deploy')
    assert result.returncode != 0, result.stdout + result.stderr
    output = result.stdout + result.stderr
    assert 'magos01' in output
    if failure == 'missing-sudo':
        assert 'sudo is missing' in output
    if failure == 'unreachable':
        assert 'UNREACHABLE' in output
    assert 'Install Python before' not in output
    assert 'Install system dependencies' not in output
    assert 'TASK [controller :' not in output
    assert "Read each node's public CSR" not in output
    assert 'TASK [services :' not in output
