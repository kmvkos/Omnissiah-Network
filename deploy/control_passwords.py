"""Configure encrypted SSH/sudo passwords and unlock Vault for one installer run."""
import argparse
from contextlib import contextmanager
import getpass
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


@contextmanager
def vault_environment(password):
    # Only the Vault unlock password is temporary; connection passwords never
    # appear in argv, the environment or an unencrypted project file.
    with tempfile.TemporaryDirectory(prefix='omnissiah-vault-') as directory:
        path = Path(directory) / 'unlock'
        path.write_text(password + '\n'); path.chmod(0o600)
        yield dict(os.environ, ANSIBLE_VAULT_PASSWORD_FILE=str(path),
                   OMNISSIAH_PASSWORD_AUTH_ACTIVE='1')


def configure(path, vault_password, ssh_password, sudo_password):
    data = {'ansible_password': ssh_password,
            'ansible_become_password': sudo_password,
            'ansible_ssh_password_mechanism': 'sshpass',
            'ansible_ssh_extra_args': '-o PreferredAuthentications=password,keyboard-interactive -o PubkeyAuthentication=no'}
    with vault_environment(vault_password) as environment:
        # Encrypt from stdin to a temporary sibling, then atomically replace.
        descriptor, temporary = tempfile.mkstemp(prefix='.credentials-', dir=path.parent)
        os.close(descriptor)
        try:
            result = subprocess.run(['ansible-vault', 'encrypt', '--output', temporary, '-'],
                                    input=json.dumps(data), capture_output=True, text=True, env=environment)
            if result.returncode:
                raise ValueError('Не удалось зашифровать пароли в Ansible Vault.')
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vault', type=Path, required=True)
    parser.add_argument('--configure', action='store_true')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('An installer command is required after --')
    if args.configure or not args.vault.exists():
        ssh_password = getpass.getpass('SSH-пароль целевых узлов: ')
        if not ssh_password:
            sys.exit('SSH-пароль не должен быть пустым.')
        sudo_password = getpass.getpass('Пароль sudo [Enter = SSH-пароль]: ') or ssh_password
        vault_password = getpass.getpass('Новый пароль Ansible Vault: ')
        if not vault_password or vault_password != getpass.getpass('Повторите пароль Vault: '):
            sys.exit('Пароль Vault пуст или подтверждение не совпало.')
        configure(args.vault, vault_password, ssh_password, sudo_password)
        print(f'SSH/sudo-пароли сохранены в зашифрованном файле: {args.vault}', flush=True)
    else:
        vault_password = getpass.getpass('Пароль Ansible Vault: ')
    with vault_environment(vault_password) as environment:
        # Authenticate the unlock password before starting any SSH or VM work.
        check = subprocess.run(['ansible-vault', 'view', str(args.vault)],
                               capture_output=True, text=True, env=environment)
        if check.returncode:
            sys.exit('Не удалось открыть Vault: проверьте пароль Vault.')
        result = subprocess.run(command, env=environment)
    sys.exit(result.returncode)


if __name__ == '__main__':
    main()
