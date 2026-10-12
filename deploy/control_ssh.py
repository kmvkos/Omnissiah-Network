"""Verify SSH host trust and key login before bootstrap, without remote Python."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys


def inventory_hosts(inventory, ansible_args=()):
    # Resolve YAML, groups and host/group_vars using the same Ansible environment.
    options = argparse.ArgumentParser(add_help=False)
    options.add_argument('-u', '--user')
    options.add_argument('--private-key', '--key-file')
    options.add_argument('-e', '--extra-vars', action='append', default=[])
    args, _ = options.parse_known_args(ansible_args)
    command = ['ansible-inventory', '-i', str(inventory), '--playbook-dir',
               str(inventory.parent), '--list']
    for value in args.extra_vars:
        command.extend(['-e', value])
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    resolved = json.loads(result.stdout)
    return [(name, variables, args.user, args.private_key)
            for name, variables in sorted(resolved['_meta']['hostvars'].items())]


def ssh_command(variables, user=None, private_key=None):
    address = str(variables['ansible_host'])
    # Inventory connection variables take precedence over CLI defaults in Ansible.
    username = variables.get('ansible_ssh_user', variables.get('ansible_user')) or user
    port = str(variables.get('ansible_ssh_port', variables.get('ansible_port', 22)))
    identity = variables.get('ansible_ssh_private_key_file', variables.get('ansible_private_key_file')) or private_key
    command = ['ssh', '-p', port]
    if username:
        command.extend(['-l', str(username)])
    if identity:
        command.extend(['-i', str(Path(identity).expanduser())])
    for option in ('ansible_ssh_args', 'ansible_ssh_common_args', 'ansible_ssh_extra_args'):
        command.extend(shlex.split(variables.get(option) or ''))
    # These options precede inventory options: OpenSSH uses the first value.
    return ['ssh', '-o', 'StrictHostKeyChecking=yes', '-o', 'BatchMode=yes',
            '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1',
            '-o', 'ControlPath=none'] + command[1:] + ['--', address, 'true']


def verify_host(name, variables, user=None, private_key=None, interactive=None):
    command = ssh_command(variables, user, private_key)
    environment = dict(os.environ, SSH_ASKPASS_REQUIRE='never', LC_ALL='C')
    result = subprocess.run(command, capture_output=True, text=True, env=environment)
    if result.returncode == 0:
        print(f'SSH OK: {name}', flush=True)
        return True
    error = result.stderr
    changed_key = ('REMOTE HOST IDENTIFICATION HAS CHANGED' in error
                   or 'Offending ' in error or 'REVOKED HOST KEY' in error)
    unknown_key = 'Host key verification failed' in error or 'is known for' in error
    interactive = sys.stdin.isatty() if interactive is None else interactive
    if unknown_key and not changed_key and interactive:
        print(f'{name}: проверьте отпечаток SSH-ключа по консоли ВМ и подтвердите его ниже.', flush=True)
        prompt = command.copy()
        prompt[prompt.index('StrictHostKeyChecking=yes')] = 'StrictHostKeyChecking=ask'
        prompt[prompt.index('BatchMode=yes')] = 'BatchMode=no'
        # Trust confirmation and key passphrase use this terminal; account passwords
        # belong to ssh-copy-id, rather than an apparently successful key check.
        prompt[1:1] = ['-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no']
        subprocess.run(prompt, env=environment)
        result = subprocess.run(command, capture_output=True, text=True, env=environment)
        if result.returncode == 0:
            print(f'SSH OK: {name}', flush=True)
            return True
        error = result.stderr
    print(f'SSH не готов: {name}\n{error.strip()}', file=sys.stderr, flush=True)
    if changed_key:
        print('Ключ сервера изменился. Сверьте новый отпечаток на ВМ; known_hosts не изменён.', file=sys.stderr)
    elif 'Permission denied' in error:
        destination = variables['ansible_host']
        username = variables.get('ansible_ssh_user', variables.get('ansible_user')) or user
        if username:
            destination = f'{username}@{destination}'
        copy_command = ['ssh-copy-id', '-p', str(variables.get('ansible_ssh_port', variables.get('ansible_port', 22)))]
        identity = variables.get('ansible_ssh_private_key_file', variables.get('ansible_private_key_file')) or private_key
        if identity:
            copy_command.extend(['-i', str(Path(identity).expanduser())])
        copy_command.append(destination)
        print('Настройте вход по ключу: ' + shlex.join(copy_command) +
              '\nЕсли ключ защищён парольной фразой, загрузите его через ssh-add.', file=sys.stderr)
    elif unknown_key:
        print('Повторите --ssh-only в интерактивном терминале для подтверждения ключа.', file=sys.stderr)
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('ansible_args', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    forwarded = args.ansible_args
    if forwarded[:1] == ['--']:
        forwarded = forwarded[1:]
    hosts = inventory_hosts(args.inventory.resolve(), forwarded)
    if not hosts:
        parser.error('Inventory has no target hosts')
    # Visit every target so one run reports all missing keys/connections.
    ready = [verify_host(*host) for host in hosts]
    if not all(ready):
        sys.exit('SSH-проверка не пройдена; развёртывание не запущено. Исправьте доступ и повторите запуск.')


if __name__ == '__main__':
    main()
