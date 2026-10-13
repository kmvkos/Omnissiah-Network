import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from control_passwords import configure, main, vault_environment

pytestmark = pytest.mark.skipif(not os.getenv('OMNISSIAH_TEST_CONTROL_VENV'), reason='Ansible validation environment required')


@pytest.fixture(autouse=True)
def ansible_environment(monkeypatch):
    monkeypatch.setenv('PATH', os.environ['OMNISSIAH_TEST_CONTROL_VENV'] + '/bin:' + os.environ['PATH'])


def test_vault_encrypts_distinct_passwords_and_unlock_file_is_removed(tmp_path):
    path = tmp_path / 'credentials.vault.yml'
    configure(path, 'unlock-value', 'ssh-secret-$`quote', 'sudo-other-secret')
    ciphertext = path.read_text()
    assert ciphertext.startswith('$ANSIBLE_VAULT;')
    assert 'ssh-secret' not in ciphertext and 'sudo-other' not in ciphertext
    assert path.stat().st_mode & 0o777 == 0o600
    with vault_environment('unlock-value') as environment:
        unlock = Path(environment['ANSIBLE_VAULT_PASSWORD_FILE'])
        assert unlock.stat().st_mode & 0o777 == 0o600
        result = subprocess.run(['ansible-vault', 'view', str(path)], capture_output=True, text=True, env=environment)
        assert result.returncode == 0, result.stderr
        data = json.loads(result.stdout)
        assert data['ansible_password'] == 'ssh-secret-$`quote'
        assert data['ansible_become_password'] == 'sudo-other-secret'
        assert data['ansible_ssh_password_mechanism'] == 'sshpass'
    assert not unlock.exists()


def test_existing_vault_unlocks_once_and_cleans_up_on_child_failure(tmp_path, monkeypatch):
    path = tmp_path / 'credentials.vault.yml'
    configure(path, 'unlock-value', 'ssh-secret', 'sudo-secret')
    recorded = tmp_path / 'unlock-path'
    prompts = []
    def password(prompt):
        prompts.append(prompt)
        return 'unlock-value'
    monkeypatch.setattr('control_passwords.getpass.getpass', password)
    code = 'import os,pathlib,sys; pathlib.Path(sys.argv[1]).write_text(os.environ["ANSIBLE_VAULT_PASSWORD_FILE"]); sys.exit(7)'
    monkeypatch.setattr(sys, 'argv', ['passwords', '--vault', str(path), '--', sys.executable, '-c', code, str(recorded)])
    with pytest.raises(SystemExit) as status:
        main()
    assert status.value.code == 7
    assert len(prompts) == 1
    assert not Path(recorded.read_text()).exists()


def test_wrong_vault_password_does_not_start_child(tmp_path, monkeypatch):
    path = tmp_path / 'credentials.vault.yml'
    configure(path, 'correct-unlock', 'ssh-secret', 'sudo-secret')
    marker = tmp_path / 'must-not-exist'
    monkeypatch.setattr('control_passwords.getpass.getpass', lambda prompt: 'wrong-unlock')
    monkeypatch.setattr(sys, 'argv', ['passwords', '--vault', str(path), '--', sys.executable, '-c',
                                    'import pathlib,sys; pathlib.Path(sys.argv[1]).touch()', str(marker)])
    with pytest.raises(SystemExit, match='Не удалось открыть Vault'):
        main()
    assert not marker.exists()


def test_wizard_saves_and_forwards_passwords_without_printing_them(tmp_path, monkeypatch, capsys):
    path = tmp_path / 'credentials.vault.yml'
    entered = iter(['ssh-new-secret', 'sudo-new-secret', 'vault-new', 'vault-new'])
    monkeypatch.setattr('control_passwords.getpass.getpass', lambda prompt: next(entered))
    monkeypatch.setattr(sys, 'argv', ['passwords', '--vault', str(path), '--', sys.executable, '-c', 'pass'])
    with pytest.raises(SystemExit) as status:
        main()
    assert status.value.code == 0
    output = capsys.readouterr().out
    assert 'ssh-new-secret' not in output and 'sudo-new-secret' not in output
    assert path.exists()
