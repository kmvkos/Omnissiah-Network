import json
import os
from pathlib import Path
import shlex
import select
import socket
import subprocess
import sys
import time
import threading

import paramiko

import pytest

from control_inventory import create_inventory
from control_ssh import inventory_hosts, ssh_command, verify_host


def test_ssh_uses_inventory_port_user_key_and_enforces_host_check():
    command = ssh_command({'ansible_host': '192.168.50.11', 'ansible_user': 'admin',
                           'ansible_port': 2222, 'ansible_ssh_private_key_file': '/tmp/key',
                           'ansible_ssh_common_args': '-o StrictHostKeyChecking=no'})
    assert command[command.index('-l') + 1] == 'admin'
    assert command[command.index('-p') + 1] == '2222'
    assert command[command.index('-i') + 1] == '/tmp/key'
    assert command.index('StrictHostKeyChecking=yes') < command.index('StrictHostKeyChecking=no')
    assert command[-3:] == ['--', '192.168.50.11', 'true']


def test_unknown_host_is_confirmed_in_terminal_then_key_login_rechecked(monkeypatch):
    results = iter([subprocess.CompletedProcess([], 255, '', 'Host key verification failed.'),
                    subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 0, '', '')])
    calls = []
    def run(command, **kwargs):
        calls.append((command, kwargs))
        return next(results)
    monkeypatch.setattr(subprocess, 'run', run)
    assert verify_host('magos03', {'ansible_host': '192.168.50.13'}, interactive=True)
    assert len(calls) == 3
    assert 'StrictHostKeyChecking=ask' in calls[1][0]
    assert 'capture_output' not in calls[1][1]
    assert calls[1][1]['env']['SSH_ASKPASS_REQUIRE'] == 'never'
    assert 'BatchMode=yes' in calls[2][0]


@pytest.mark.parametrize('password', [None, 'test-password'])
def test_changed_host_key_stops_without_prompt_or_removal(monkeypatch, capsys, password):
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 255, '',
            'WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\nHost key verification failed.')
    monkeypatch.setattr(subprocess, 'run', run)
    assert not verify_host('magos03', {'ansible_host': '192.168.50.13', 'ansible_password': password}, interactive=True)
    assert len(calls) == 1
    assert 'known_hosts не изменён' in capsys.readouterr().err


def test_missing_auth_reports_copy_command_instead_of_deploying(monkeypatch, capsys):
    monkeypatch.setattr(subprocess, 'run', lambda command, **kwargs:
        subprocess.CompletedProcess(command, 255, '', 'Permission denied (publickey).'))
    assert not verify_host('magos05', {'ansible_host': '192.168.50.15', 'ansible_user': 'fabricator'})
    assert 'ssh-copy-id -p 22 fabricator@192.168.50.15' in capsys.readouterr().err


@pytest.mark.skipif(not os.getenv('OMNISSIAH_TEST_CONTROL_VENV'), reason='Ansible validation environment required')
def test_inventory_resolution_includes_all_agents_and_cli_defaults(tmp_path, monkeypatch):
    monkeypatch.setenv('PATH', os.environ['OMNISSIAH_TEST_CONTROL_VENV'] + '/bin:' + os.environ['PATH'])
    path = tmp_path / 'inventory.yml'
    path.write_text(json.dumps(create_inventory([f'192.168.50.{i}' for i in range(10, 21)], 'admin')))
    hosts = inventory_hosts(path, ['-u', 'fabricator', '--private-key', '/tmp/deploy-key', '-e', 'ansible_port=2222'])
    assert len(hosts) == 11
    assert {name for name, *_ in hosts} == {'omni01'} | {f'magos{i:02d}' for i in range(1, 11)}
    assert all(user == 'fabricator' and key == '/tmp/deploy-key' and variables['ansible_port'] == '2222'
               for _, variables, user, key in hosts)
    _, variables, user, key = hosts[0]
    command = ssh_command(variables, user, key)
    assert command[command.index('-l') + 1] == 'admin'  # inventory takes precedence over -u
    assert command[command.index('-i') + 1] == '/tmp/deploy-key'


def run_terminal(command, environment):
    # util-linux script gives the child a controlling terminal without forking
    # Python while the in-process SSH server thread is running.
    child = subprocess.Popen(['script', '--quiet', '--return', '--command', shlex.join(command), '/dev/null'],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=environment)
    output = b''
    confirmed = False
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if select.select([child.stdout], [], [], 0.1)[0]:
                output += os.read(child.stdout.fileno(), 8192)
                if not confirmed and b'Are you sure you want to continue connecting' in output:
                    child.stdin.write(b'yes\n'); child.stdin.flush()
                    confirmed = True
            if child.poll() is not None:
                return child.returncode, output.decode(), confirmed
        raise AssertionError('SSH terminal timed out: ' + output.decode())
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=5)


def test_real_ssh_unknown_host_confirmation_repeat_and_changed_key(tmp_path):
    # A real OpenSSH client talks SSH to a local Paramiko server; no root,
    # system accounts, chroot or changes to the user's known_hosts are needed.
    key = tmp_path / 'client'
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
    client_key = paramiko.Ed25519Key.from_private_key_file(str(key))
    server_key = paramiko.RSAKey.generate(2048)
    known = tmp_path / 'known_hosts'
    stop = threading.Event()
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0)); listener.listen(); listener.settimeout(0.1)
    port = listener.getsockname()[1]

    class Server(paramiko.ServerInterface):
        def __init__(self):
            self.executed = threading.Event()
        def check_auth_publickey(self, username, public_key):
            return paramiko.AUTH_SUCCESSFUL if public_key == client_key else paramiko.AUTH_FAILED
        def get_allowed_auths(self, username):
            return 'publickey'
        def check_channel_request(self, kind, channel_id):
            return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        def check_channel_exec_request(self, channel, command):
            self.executed.set()
            return command == b'true'

    def serve():
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            transport = paramiko.Transport(connection)
            transport.add_server_key(server_key)
            server = Server()
            try:
                transport.start_server(server=server)
                channel = transport.accept(3)
                if channel is not None and server.executed.wait(3):
                    channel.send_exit_status(0)
                    channel.shutdown_write()
                    deadline = time.monotonic() + 3
                    while transport.is_active() and not stop.is_set() and time.monotonic() < deadline:
                        time.sleep(0.01)
            except (EOFError, OSError, paramiko.SSHException):
                pass  # Strict host verification can close before authentication.
            finally:
                transport.close()
                connection.close()

    thread = threading.Thread(target=serve, daemon=True); thread.start()
    try:
        variables = {'ansible_host': '127.0.0.1', 'ansible_user': 'admin', 'ansible_port': port,
                     'ansible_ssh_private_key_file': str(key),
                     'ansible_ssh_common_args': f'-o UserKnownHostsFile={known} -o GlobalKnownHostsFile=/dev/null -o IdentitiesOnly=yes'}
        assert not verify_host('magos10', variables, interactive=False)
        assert not known.exists()
        environment = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / 'deploy'))
        command = [sys.executable, '-c', 'import json,sys; from control_ssh import verify_host; '
                   'sys.exit(0 if verify_host("magos10",json.loads(sys.argv[1])) else 1)', json.dumps(variables)]
        status, output, confirmed = run_terminal(command, environment)
        assert status == 0 and confirmed, output
        saved = known.read_bytes()
        assert verify_host('magos10', variables, interactive=False)
        assert known.read_bytes() == saved
        public = Path(str(key) + '.pub').read_text().split()
        known.write_text(f'[127.0.0.1]:{port} {public[0]} {public[1]}\n')
        changed = known.read_bytes()
        assert not verify_host('magos10', variables, interactive=True)
        assert known.read_bytes() == changed
    finally:
        stop.set(); thread.join(timeout=5); listener.close()
        assert not thread.is_alive()


def test_password_mode_confirms_host_but_defers_login_to_ansible(monkeypatch):
    results = iter([subprocess.CompletedProcess([], 255, '', 'Host key verification failed.'),
                    subprocess.CompletedProcess([], 255),
                    subprocess.CompletedProcess([], 255, '', 'Permission denied (password).')])
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        return next(results)
    monkeypatch.setattr(subprocess, 'run', run)
    assert verify_host('magos03', {'ansible_host': '192.168.50.13', 'ansible_password': 'test-password'}, interactive=True)
    assert len(calls) == 3
    assert 'StrictHostKeyChecking=ask' in calls[1]
    assert 'StrictHostKeyChecking=yes' in calls[2]
