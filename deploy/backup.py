"""Root-only pre-update snapshot; SQLite is copied through its online backup API."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import tarfile
import tempfile


def snapshot(project, state, revision):
    project, state = Path(project).resolve(), Path(state).resolve()
    if not re.fullmatch(r'[a-f0-9]{64}', revision):
        raise ValueError('Invalid source revision')
    backups = state / 'backups'
    backups.mkdir(mode=0o700, exist_ok=True)
    backups.chmod(0o700)
    destination = backups / f'before-{revision}.tar.gz'
    if destination.is_file():
        return {'changed': False, 'backup': str(destination)}
    with tempfile.TemporaryDirectory(prefix='.snapshot-', dir=backups) as work:
        work = Path(work)
        output = work / 'snapshot.tar.gz'
        with tarfile.open(output, 'w:gz') as archive:
            for path in sorted(state.rglob('*')):
                relative = path.relative_to(state)
                if relative.parts[0] in ('backups', '.update') or path.is_dir():
                    continue
                if path.name.endswith(('-wal', '-shm', '-journal')):
                    continue
                if path.suffix in ('.db', '.sqlite', '.sqlite3') and not path.is_symlink():
                    copy = work / 'database.sqlite'
                    with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=15) as source:
                        with sqlite3.connect(copy) as target:
                            source.backup(target)
                    archive.add(copy, arcname=f'state/{relative}', recursive=False)
                    copy.unlink()
                else:
                    archive.add(path, arcname=f'state/{relative}', recursive=False)
            # Existing source tarball allows restoration of the previous runtime;
            # installed venv and OS packages are deliberately not archived.
            for name in ('.env', '.source.tar.gz', '.runtime-version.json'):
                path = project / name
                if path.is_file():
                    archive.add(path, arcname=f'project/{name}', recursive=False)
            for path in (Path('/etc/systemd/system/omnissiah-network.service'),
                         Path('/etc/nginx/sites-available/omnissiah-network')):
                if path.is_file():
                    archive.add(path, arcname=str(path).lstrip('/'), recursive=False)
        output.chmod(0o600)
        os.replace(output, destination)
    return {'changed': True, 'backup': str(destination)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--revision', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    print(json.dumps(snapshot(args.project, args.state, args.revision)))
