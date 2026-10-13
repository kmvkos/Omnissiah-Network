import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tarfile

import pytest

from backup import snapshot
from install_source import install

ROOT = Path(__file__).resolve().parents[1]


def archive(path, files):
    with tarfile.open(path, 'w:gz') as stream:
        for name, content in files.items():
            member = tarfile.TarInfo(name)
            content = content.encode()
            member.size = len(content)
            stream.addfile(member, io.BytesIO(content))


def test_source_update_removes_deleted_code_and_preserves_local_state(tmp_path):
    project = tmp_path / 'project'; project.mkdir()
    source = tmp_path / 'source.tar.gz'
    archive(source, {'src/old.py':'old', 'src/app.py':'v1', 'requirements.txt':'v1'})
    assert install(project, source)['changed']
    (project / '.env').write_text('secret=preserved')
    (project / 'venv').mkdir(); (project / 'venv/local').write_text('dependencies')
    (project / 'src/local.txt').write_text('not-owned-by-source')
    archive(source, {'src/app.py':'v2', 'requirements.txt':'v2'})
    assert install(project, source)['changed']
    assert not (project / 'src/old.py').exists()
    assert (project / 'src/app.py').read_text() == 'v2'
    assert (project / '.env').read_text() == 'secret=preserved'
    assert (project / 'venv/local').read_text() == 'dependencies'
    assert (project / 'src/local.txt').is_file()
    assert not install(project, source)['changed']


@pytest.mark.parametrize('name', ['../outside.py', '/outside.py', '.env', 'agents/database/retra.db'])
def test_invalid_source_archive_is_rejected_before_any_replacement(tmp_path, name):
    project = tmp_path / 'project'; project.mkdir()
    source = tmp_path / 'source.tar.gz'
    archive(source, {'src/app.py':'must-not-be-written', name:'unsafe'})
    with pytest.raises(ValueError):
        install(project, source)
    assert not (project / 'src/app.py').exists()


def test_backup_includes_committed_wal_database_and_keeps_secrets_private(tmp_path):
    project = tmp_path / 'project'; project.mkdir()
    state = tmp_path / 'state'; (state / 'data').mkdir(parents=True)
    (state / 'pki').mkdir(); (state / 'pki/identity.key').write_text('private-key')
    (state / 'bootstrap_config.json').write_text('{"manage_wireguard":true}')
    (project / '.env').write_text('session-secret')
    (project / '.source.tar.gz').write_bytes(b'previous-source')
    database = sqlite3.connect(state / 'data/vpngate.db')
    database.execute('PRAGMA journal_mode=WAL')
    database.execute('CREATE TABLE settings (value TEXT)')
    database.execute("INSERT INTO settings VALUES ('saved-policy')")
    database.commit()
    revision = 'a' * 64
    result = snapshot(project, state, revision)
    path = Path(result['backup'])
    assert result['changed']
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    with tarfile.open(path) as stream:
        names = stream.getnames()
        assert not any('backups/' in name or name.endswith(('-wal', '-shm')) for name in names)
        assert stream.extractfile('project/.env').read() == b'session-secret'
        assert stream.extractfile('state/pki/identity.key').read() == b'private-key'
        restored = tmp_path / 'restored.db'
        restored.write_bytes(stream.extractfile('state/data/vpngate.db').read())
    with sqlite3.connect(restored) as saved:
        assert saved.execute('SELECT value FROM settings').fetchone()[0] == 'saved-policy'
        assert saved.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    before = path.read_bytes()
    assert not snapshot(project, state, revision)['changed']
    assert path.read_bytes() == before
    database.close()


def git(folder, *args):
    return subprocess.run(['git', '-C', str(folder), *args], check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def git_control(tmp_path):
    remote = tmp_path / 'origin'; remote.mkdir()
    git(remote, 'init', '-b', 'main')
    git(remote, 'config', 'user.email', 'test@example.invalid'); git(remote, 'config', 'user.name', 'Test')
    shutil.copy(ROOT / 'control-update.sh', remote)
    (remote / 'control-install.sh').write_text('#!/bin/bash\nprintf "%s\\n" "$@" > ansible/called.txt\n')
    (remote / '.gitignore').write_text('ansible/inventory.yml\nansible/.control-update.lock\nansible/called.txt\n')
    git(remote, 'add', '.'); git(remote, 'commit', '-m', 'initial')
    control = tmp_path / 'control'
    subprocess.run(['git', 'clone', str(remote), str(control)], check=True, capture_output=True)
    (control / 'ansible').mkdir(); (control / 'ansible/inventory.yml').write_text('saved-inventory')
    return remote, control


def test_update_fetches_new_commit_and_calls_full_installer(git_control):
    remote, control = git_control
    (remote / 'new.txt').write_text('new-source')
    git(remote, 'add', '.'); git(remote, 'commit', '-m', 'new version')
    result = subprocess.run(['bash', 'control-update.sh'], cwd=control, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert git(control, 'rev-parse', 'HEAD') == git(remote, 'rev-parse', 'HEAD')
    assert (control / 'ansible/called.txt').read_text().splitlines() == ['--update', '--skip-system-packages']
    assert (control / 'ansible/inventory.yml').read_text() == 'saved-inventory'


@pytest.mark.parametrize('failure', ['dirty', 'diverged', 'fetch'])
def test_update_failure_does_not_start_ansible(git_control, failure):
    remote, control = git_control
    if failure == 'dirty':
        (control / 'control-install.sh').write_text('local changes')
    elif failure == 'diverged':
        git(control, 'config', 'user.email', 'test@example.invalid'); git(control, 'config', 'user.name', 'Test')
        (control / 'local.txt').write_text('local commit')
        git(control, 'add', '.'); git(control, 'commit', '-m', 'local')
    else:
        git(control, 'remote', 'set-url', 'origin', str(remote / 'missing.git'))
    result = subprocess.run(['bash', 'control-update.sh'], cwd=control, capture_output=True, text=True)
    assert result.returncode != 0
    assert not (control / 'ansible/called.txt').exists()


@pytest.mark.parametrize('missing_node', [False, True])
@pytest.mark.skipif(not os.getenv('OMNISSIAH_TEST_CONTROL_VENV') or os.geteuid() != 0,
                    reason='Local root and an Ansible environment are required')
def test_real_ansible_preflight_backs_up_all_nodes_or_stops_before_mutation(tmp_path, missing_node):
    inventory = dict(all=dict(hosts=dict(localhost=dict(source_revision='e' * 64)),
        vars=dict(ansible_connection='local', ansible_python_interpreter=sys.executable,
                  omnissiah_update=True),
        children=dict(omnissiah=dict(hosts={}), magos=dict(hosts={}))))
    locations = []
    for index, name in enumerate(('omni01', 'magos01', 'magos02', 'magos03')):
        project, state = tmp_path / name / 'project', tmp_path / name / 'state'
        project.mkdir(parents=True); (state / 'pki').mkdir(parents=True)
        (project / '.source.tar.gz').write_bytes(b'old-sources')
        for key in ('identity.key', 'identity.crt'):
            (state / 'pki' / key).write_text('local-identity')
        config = project / '.env' if index == 0 else state / 'bootstrap_config.json'
        config.write_text('existing-settings')
        database = state / ('data/vpngate.db' if index == 0 else 'database/retra.db')
        database.parent.mkdir()
        if not missing_node or name != 'magos03':
            with sqlite3.connect(database) as connection:
                connection.execute('CREATE TABLE state (value TEXT)')
                connection.execute("INSERT INTO state VALUES ('keep-me')")
        group = 'omnissiah' if index == 0 else 'magos'
        inventory['all']['children'][group]['hosts'][name] = dict(
            omnissiah_project_dir=str(project), omnissiah_state_dir=str(state))
        locations.append((project, state))
    path = tmp_path / 'inventory.yml'; path.write_text(json.dumps(inventory))
    executable = Path(os.environ['OMNISSIAH_TEST_CONTROL_VENV']) / 'bin/ansible-playbook'
    result = subprocess.run([str(executable), '-i', str(path), 'update-preflight.yml'],
                            cwd=ROOT / 'ansible', capture_output=True, text=True, timeout=90)
    if missing_node:
        assert result.returncode != 0
        assert 'Existing installation is incomplete' in result.stdout
        assert not any((state / 'backups').exists() for _, state in locations)
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert all((state / 'backups' / ('before-' + 'e' * 64 + '.tar.gz')).is_file()
                   for _, state in locations)
    for project, _ in locations:
        assert (project / '.source.tar.gz').read_bytes() == b'old-sources'
