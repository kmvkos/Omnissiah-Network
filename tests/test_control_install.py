import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

import pytest

from control_inventory import create_inventory
from package_source import package

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def downloaded_folder(tmp_path):
    folder = tmp_path / 'download'; folder.mkdir()
    for name in ('src', 'agents', 'templates', 'deploy', 'ansible'):
        shutil.copytree(ROOT / name, folder / name,
                       ignore=shutil.ignore_patterns('__pycache__', 'artifacts', 'instance', 'database'))
    for name in ('requirements.txt', 'mtls_utils.py', 'control-install.sh'):
        shutil.copy(ROOT / name, folder / name)
    return folder


def test_downloaded_folder_packages_runtime_without_git_or_local_secrets(downloaded_folder):
    folder = downloaded_folder
    (folder / '.env').write_text('PRIVATE_SECRET=must-not-travel')
    (folder / 'ansible/inventory.yml').write_text('private-inventory')
    (folder / 'ansible/group_vars/secrets.yml').write_text('password: must-not-travel')
    (folder / 'agents/database').mkdir(); (folder / 'agents/database/retra.db').write_bytes(b'private-db')
    (folder / 'src/mtls_certs').mkdir(); (folder / 'src/mtls_certs/client.key').write_text('private-key')
    result = package(folder, folder / 'ansible/artifacts')
    assert result['changed'] is True
    with tarfile.open(result['archive']) as archive:
        names = {member.name for member in archive.getmembers()}
        assert {'src/app.py', 'agents/app/agent.py', 'deploy/bootstrap.py', 'mtls_utils.py'} <= names
        assert not any(name.startswith('ansible/') or Path(name).suffix in ('.key', '.db') or Path(name).name == '.env' for name in names)
        assert not any(b'must-not-travel' in archive.extractfile(member).read() for member in archive.getmembers() if member.isfile())
    assert package(folder, folder / 'ansible/artifacts')['changed'] is False
    (folder / '.env').write_text('CHANGED_SECRET=still-not-in-payload')
    assert package(folder, folder / 'ansible/artifacts')['revision'] == result['revision']


def test_source_symlink_is_rejected(downloaded_folder, tmp_path):
    secret = tmp_path / 'outside.py'; secret.write_text('private = True')
    (downloaded_folder / 'src/link.py').symlink_to(secret)
    with pytest.raises(ValueError, match='symlinks'):
        package(downloaded_folder, tmp_path / 'output')


@pytest.mark.parametrize('count', [1, 3, 5, 10, 253])
def test_inventory_contains_only_target_nodes(count):
    addresses = [f'192.168.50.{index}' for index in range(1, count + 2)]
    inventory = create_inventory(addresses, 'henry')
    assert 'control' not in str(inventory)
    assert inventory['all']['vars']['ansible_user'] == 'henry'
    agents = inventory['all']['children']['magos']['hosts']
    assert len(agents) == count
    assert agents[f'magos{count:02d}']['ansible_host'] == addresses[-1]
    assert agents[f'magos{count:02d}']['omnissiah_vpn_address'] == f'10.77.0.{count + 1}/32'
    with pytest.raises(ValueError):
        create_inventory(['192.168.50.10']*3, 'henry')


@pytest.mark.parametrize('count', [2, 3, 5, 10])
def test_inventory_wizard_preserves_existing_file(tmp_path, count):
    path = tmp_path / 'inventory.yml'
    result = subprocess.run([sys.executable, str(ROOT / 'deploy/control_inventory.py'), '--inventory', str(path)],
        input=str(count) + '\n' + '\n'.join(f'192.168.50.{i}' for i in range(10, 11 + count)) + '\nhenry\n',capture_output=True,text=True,timeout=10)
    assert result.returncode == 0, result.stderr
    saved = path.read_bytes()
    assert len(json.loads(saved)['all']['children']['magos']['hosts']) == count
    result = subprocess.run([sys.executable, str(ROOT / 'deploy/control_inventory.py'), '--inventory', str(path)],
        input='',capture_output=True,text=True,timeout=10)
    assert result.returncode == 0
    assert path.read_bytes() == saved


@pytest.mark.parametrize('count', [3, 5, 10])
@pytest.mark.skipif(not os.getenv('OMNISSIAH_TEST_CONTROL_VENV'), reason='Ansible validation environment is required')
def test_control_installer_prepare_from_downloaded_folder(downloaded_folder, count):
    folder = downloaded_folder
    (folder / '.ansible-venv').symlink_to(os.environ['OMNISSIAH_TEST_CONTROL_VENV'], target_is_directory=True)
    inventory = create_inventory([f'192.168.50.{index}' for index in range(10, 11 + count)], 'admin')
    (folder / 'ansible/inventory.yml').write_text(json.dumps(inventory))
    command = ['bash', str(folder / 'control-install.sh'), '--skip-system-packages', '--prepare-only']
    environment = dict(os.environ, PIP_NO_INDEX='1')
    for repeat in range(2):
        result = subprocess.run(command,cwd=folder,capture_output=True,text=True,env=environment,timeout=45)
        assert result.returncode == 0, result.stdout + result.stderr
        assert 'Control подготовлен' in result.stdout
        if repeat:
            assert 'changed=0' in result.stdout
    assert not (folder / '.git').exists()


@pytest.mark.parametrize('mode', ['--ssh-only', '--access-only', '--skip-system-packages'])
@pytest.mark.skipif(not os.getenv('OMNISSIAH_TEST_CONTROL_VENV'), reason='Ansible validation environment is required')
def test_control_installer_stops_before_deployment_on_failed_ssh(downloaded_folder, tmp_path, mode):
    folder = downloaded_folder
    (folder / '.ansible-venv').symlink_to(os.environ['OMNISSIAH_TEST_CONTROL_VENV'], target_is_directory=True)
    (folder / 'ansible/inventory.yml').write_text(json.dumps(
        create_inventory([f'192.168.50.{i}' for i in range(10, 14)], 'admin')))
    fake_bin = tmp_path / 'bin'; fake_bin.mkdir()
    fake_ssh = fake_bin / 'ssh'
    fake_ssh.write_text("#!/bin/sh\necho 'Permission denied (publickey).' >&2\nexit 255\n")
    fake_ssh.chmod(0o755)
    environment = dict(os.environ, PIP_NO_INDEX='1', PATH=str(fake_bin) + ':' + os.environ['PATH'])
    result = subprocess.run(['bash', str(folder / 'control-install.sh'), mode], cwd=folder,
                            capture_output=True, text=True, env=environment, timeout=45)
    assert result.returncode != 0
    assert result.stderr.count('SSH не готов:') == 4
    assert 'SSH-проверка не пройдена; развёртывание не запущено' in result.stderr
    assert 'Install Python before' not in result.stdout
    if mode in ('--ssh-only', '--access-only'):
        assert not (folder / 'ansible/artifacts').exists()


@pytest.mark.skipif(not os.getenv('OMNISSIAH_TEST_CONTROL_VENV') or os.geteuid() != 0,
                    reason='Ansible validation environment and local root required')
def test_access_only_installer_checks_root_without_preparing_or_installing(downloaded_folder, tmp_path):
    folder = downloaded_folder
    (folder / '.ansible-venv').symlink_to(os.environ['OMNISSIAH_TEST_CONTROL_VENV'], target_is_directory=True)
    inventory = create_inventory([f'192.168.50.{i}' for i in range(10, 14)], 'admin')
    inventory['all']['vars'].update(ansible_connection='local', ansible_become=False)
    (folder / 'ansible/inventory.yml').write_text(json.dumps(inventory))
    fake_bin = tmp_path / 'bin'; fake_bin.mkdir()
    fake_ssh = fake_bin / 'ssh'; fake_ssh.write_text('#!/bin/sh\nexit 0\n'); fake_ssh.chmod(0o755)
    environment = dict(os.environ, PATH=str(fake_bin) + ':' + os.environ['PATH'])
    result = subprocess.run(['bash', str(folder / 'control-install.sh'), '--access-only', '--', '--become'],
                            cwd=folder, capture_output=True, text=True, env=environment, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'Verify privilege escalation returns root' in result.stdout
    assert result.stdout.count('SSH OK:') == 4
    assert 'Install system dependencies' not in result.stdout
    assert not (folder / 'ansible/artifacts').exists()


@pytest.mark.skipif(not os.getenv('OMNISSIAH_TEST_CONTROL_VENV'), reason='Ansible validation environment required')
def test_password_mode_prepare_encrypts_credentials_and_reuses_vault(downloaded_folder, tmp_path):
    from control_passwords import vault_environment
    folder = downloaded_folder
    (folder / '.ansible-venv').symlink_to(os.environ['OMNISSIAH_TEST_CONTROL_VENV'], target_is_directory=True)
    document = create_inventory([f'192.168.50.{i}' for i in range(10, 14)], 'admin')
    (folder / 'ansible/inventory.yml').write_text(json.dumps(document))
    fake_bin = tmp_path / 'bin'; fake_bin.mkdir()
    tool = fake_bin / 'sshpass'; tool.write_text('#!/bin/sh\nexit 0\n'); tool.chmod(0o755)
    environment = dict(os.environ, PIP_NO_INDEX='1', PATH=str(fake_bin) + ':' + os.environ['PATH'])
    command = ['bash', str(folder / 'control-install.sh'), '--skip-system-packages', '--prepare-only']
    result = subprocess.run(command + ['--password-auth'], cwd=folder, env=environment,
                            input='ssh-pipeline-secret\nsudo-pipeline-secret\nunlock-pipeline\nunlock-pipeline\n',
                            capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'Control подготовлен' in result.stdout
    path = folder / 'ansible/credentials.vault.yml'; encrypted = path.read_bytes()
    assert encrypted.startswith(b'$ANSIBLE_VAULT;')
    assert b'ssh-pipeline-secret' not in encrypted and b'sudo-pipeline-secret' not in encrypted
    result = subprocess.run(command, cwd=folder, env=environment, input='unlock-pipeline\n',
                            capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'changed=0' in result.stdout
    assert path.read_bytes() == encrypted
    for archive_path in (folder / 'ansible/artifacts').glob('*.tar.gz'):
        with tarfile.open(archive_path) as archive:
            assert not any(member.name.startswith('ansible/') for member in archive.getmembers())
            assert not any(b'pipeline-secret' in archive.extractfile(member).read()
                           for member in archive.getmembers() if member.isfile())


def test_runtime_payload_installs_with_restrictive_root_umask(downloaded_folder, tmp_path):
    from install_source import install
    result = package(downloaded_folder, tmp_path / 'artifacts')
    destination = tmp_path / 'node'; destination.mkdir()
    previous_umask = os.umask(0o077)
    try:
        assert install(destination, result['archive'])['changed']
    finally:
        os.umask(previous_umask)
    assert (destination / 'src/wsgi.py').is_file()
    assert (destination / 'templates/main_node.html').is_file()
    assert (destination / 'src').stat().st_mode & 0o777 == 0o755
    assert (destination / 'src/wsgi.py').stat().st_mode & 0o777 == 0o644
