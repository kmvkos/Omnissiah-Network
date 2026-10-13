"""Real OpenSSH/sshpass/Ansible authentication against a local SSH server."""
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import threading
import time

import paramiko
import pytest

from control_inventory import create_inventory
from control_passwords import configure, vault_environment

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(not os.getenv('OMNISSIAH_TEST_SSHPASS') or not os.getenv('OMNISSIAH_TEST_CONTROL_VENV'),
                               reason='Opt-in real sshpass and Ansible environment required')


@pytest.fixture
def password_server(tmp_path, request):
    key = paramiko.RSAKey.generate(2048)
    stop = threading.Event()
    listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(); listener.settimeout(0.1)
    port = listener.getsockname()[1]
    known = tmp_path / 'known_hosts'; known.write_text(f'[127.0.0.1]:{port} {key.get_name()} {key.get_base64()}\n')
    received = []

    class Server(paramiko.ServerInterface):
        def __init__(self):
            self.executed = threading.Event()
        def get_allowed_auths(self, username):
            return 'password'
        def check_auth_password(self, username, password):
            received.append(('ssh', password))
            return paramiko.AUTH_SUCCESSFUL if username == 'admin' and password == 'ssh-test-secret' else paramiko.AUTH_FAILED
        def check_channel_request(self, kind, channel_id):
            return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        def check_channel_pty_request(self, *args):
            return True
        def check_channel_exec_request(self, channel, command):
            self.command = command; self.executed.set(); return True

    def serve():
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            transport = paramiko.Transport(connection); transport.add_server_key(key); server = Server()
            try:
                transport.start_server(server=server)
                channel = transport.accept(5)
                if channel is None or not server.executed.wait(5):
                    continue
                command = server.command
                if b'BECOME-SUCCESS-' in command:
                    prompt = re.search(rb'\[sudo via ansible, key=[a-z]+\] password:', command)
                    success = re.search(rb'BECOME-SUCCESS-[a-z]+', command)
                    assert prompt and success, command
                    if getattr(request.node, 'callspec', None) and request.node.callspec.params.get('case') == 'slow-sudo':
                        time.sleep(14)
                    channel.send(prompt.group() + b' ')
                    password = b''; channel.settimeout(5)
                    while b'\n' not in password:
                        password += channel.recv(1024)
                    password = password.strip().decode(); received.append(('sudo', password))
                    if password == 'sudo-test-secret':
                        channel.send(success.group() + b'\nOMNISSIAH_ROOT_ACCESS_OK\n')
                        channel.send_exit_status(0)
                    else:
                        channel.send(b'Sorry, try again.\n'); channel.send_exit_status(1)
                elif b'ADMIN_ACCESS_TOOL_AVAILABLE' in command:
                    channel.send(b'ADMIN_ACCESS_TOOL_AVAILABLE\n'); channel.send_exit_status(0)
                else:
                    channel.send_exit_status(0)
                channel.shutdown_write()
                deadline = time.monotonic() + 3
                while transport.is_active() and not stop.is_set() and time.monotonic() < deadline:
                    time.sleep(0.01)
            except (EOFError, OSError, paramiko.SSHException):
                pass
            finally:
                transport.close(); connection.close()
    thread = threading.Thread(target=serve, daemon=True); thread.start()
    try:
        yield port, known, received
    finally:
        stop.set(); thread.join(timeout=10); listener.close()
        assert not thread.is_alive()


@pytest.mark.parametrize('case', ['success', 'wrong-ssh', 'wrong-sudo', 'ssh-only', 'slow-sudo'])
def test_saved_password_installer_checks_real_login_and_sudo(tmp_path, password_server, monkeypatch, case):
    port, known, received = password_server
    folder = tmp_path / 'download'; folder.mkdir()
    for name in ('src', 'agents', 'deploy', 'ansible'):
        shutil.copytree(ROOT / name, folder / name,
                       ignore=shutil.ignore_patterns('__pycache__', 'artifacts', 'instance', 'database', 'inventory.yml', 'credentials.vault.yml'))
    shutil.copy(ROOT / 'control-install.sh', folder)
    (folder / '.ansible-venv').symlink_to(os.environ['OMNISSIAH_TEST_CONTROL_VENV'], target_is_directory=True)
    document = create_inventory(['192.168.50.10', '192.168.50.11'], 'admin')
    document['all']['vars'].update(ansible_port=port, ansible_ssh_args='-o ControlMaster=no',
                                  ansible_ssh_common_args=f'-o UserKnownHostsFile={known} -o GlobalKnownHostsFile=/dev/null')
    for group in document['all']['children'].values():
        for host in group['hosts'].values():
            host['ansible_host'] = '127.0.0.1'
    (folder / 'ansible/inventory.yml').write_text(json.dumps(document))
    environment = dict(os.environ, PATH=os.environ['OMNISSIAH_TEST_CONTROL_VENV'] + '/bin:' +
                       str(Path(os.environ['OMNISSIAH_TEST_SSHPASS']).parent) + ':' + os.environ['PATH'])
    monkeypatch.setenv('PATH', environment['PATH'])
    configure(folder / 'ansible/credentials.vault.yml', 'test-unlock',
              'wrong-ssh-secret' if case == 'wrong-ssh' else 'ssh-test-secret',
              'wrong-sudo-secret' if case == 'wrong-sudo' else 'sudo-test-secret')
    result = subprocess.run(['bash', str(folder / 'control-install.sh'), '--ssh-only' if case == 'ssh-only' else '--access-only'],
                            cwd=folder, env=environment, input='test-unlock\n', capture_output=True, text=True, timeout=90)
    output = result.stdout + result.stderr
    assert all(secret not in output for secret in ('ssh-test-secret', 'sudo-test-secret', 'test-unlock'))
    if case in ('success', 'ssh-only', 'slow-sudo'):
        assert result.returncode == 0, output
        assert ('ssh', 'ssh-test-secret') in received
        if case in ('success', 'slow-sudo'):
            assert ('sudo', 'sudo-test-secret') in received
        else:
            assert not any(kind == 'sudo' for kind, _ in received)
        if case == 'success':
            delegate = folder / 'ansible/delegate-test.yml'
            delegate.write_text('''- hosts: omnissiah
  gather_facts: false
  become: true
  tasks:
    - ansible.builtin.raw: 'test "$(id -u)" -eq 0 && echo OMNISSIAH_ROOT_ACCESS_OK'
      delegate_to: '{{ item }}'
      loop: '{{ groups.magos }}'
''')
            with vault_environment('test-unlock') as unlocked:
                unlocked['PATH'] = environment['PATH']
                delegated = subprocess.run(['ansible-playbook', '-i', 'inventory.yml', str(delegate),
                                            '-e', '@credentials.vault.yml'], cwd=folder / 'ansible',
                                           env=unlocked, capture_output=True, text=True, timeout=30)
            assert delegated.returncode == 0, delegated.stdout + delegated.stderr
            assert 'omni01 -> magos01' in delegated.stdout
    else:
        assert result.returncode != 0, output
        if case == 'wrong-ssh':
            assert 'UNREACHABLE' in output
            assert not any(kind == 'sudo' for kind, _ in received)
        else:
            assert 'Incorrect sudo password' in output
    assert 'Install Python before' not in output
    assert not (folder / 'ansible/artifacts').exists()
