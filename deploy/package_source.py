"""Build a secret-free node payload from a Git checkout or downloaded source folder."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

SOURCE_DIRECTORIES = {'src', 'agents', 'templates', 'deploy'}
SOURCE_SUFFIXES = {'.py', '.html', '.txt'}
ROOT_FILES = {'requirements.txt', 'mtls_utils.py'}
EXCLUDED_PARTS = {'.git', '.idea', '.vscode', '__pycache__', 'venv', '.venv', '.ansible-venv',
                  'instance', 'database', 'data', 'pki', 'mtls', 'mtls_certs', 'ssl_certs',
                  'users', 'tmp', 'logs', 'artifacts', 'old', 'dist', 'build', 'build_temp'}
EXCLUDED_NAMES = {'inventory.yml', 'inventory.local.yml', 'vars.secret.yml', 'app1.py', 'old.app.py'}


def allowed(path):
    if len(path.parts) == 1:
        return path.name in ROOT_FILES
    if any(part in EXCLUDED_PARTS or part.startswith('backup_') for part in path.parts):
        return False
    if path.name in EXCLUDED_NAMES or path.name == '.env' or (
            path.name.startswith('.env.') and path.name != '.env.example'):
        return False
    if path.suffix not in SOURCE_SUFFIXES and path.name not in ('.gitignore', '.env.example'):
        return False
    return path.parts[0] in SOURCE_DIRECTORIES


def package(root, output_directory):
    root, output_directory = Path(root).resolve(), Path(output_directory).resolve()
    if not (root / 'src/app.py').is_file() or not (root / 'agents/app/agent.py').is_file():
        raise ValueError('The full project folder is required, including src/ and agents/')
    git_commit = None
    if (root / '.git').exists():
        if not shutil.which('git'):
            raise ValueError('This folder is a Git checkout, but git is unavailable')
        result = subprocess.run(['git', '-C', str(root), 'status', '--porcelain', '--untracked-files=normal'],
                                check=True, capture_output=True, text=True)
        if result.stdout:
            raise ValueError('Commit project changes before deploying from a Git checkout')
        git_commit = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
        paths = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z']).decode().strip('\0').split('\0')
    else:
        paths = list(ROOT_FILES)
        for directory in SOURCE_DIRECTORIES:
            paths.extend(str(path.relative_to(root)) for path in (root / directory).rglob('*') if path.is_file())
    files = []
    for name in sorted(paths):
        relative = Path(name)
        if not allowed(relative):
            continue
        path = root / relative
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != root):
            raise ValueError(f'Source symlinks are unsupported: {relative}')
        files.append((relative.as_posix(), path.read_bytes(), 0o755 if path.suffix == '.sh' else 0o644))
    required = {'deploy/bootstrap.py', 'deploy/pki.py', 'src/wsgi.py', 'src/proxy_identity.py',
                'requirements.txt', 'agents/requirements.txt', 'mtls_utils.py'}
    if not required.issubset({name for name, _, _ in files}):
        raise ValueError('Downloaded project is incomplete: required deployment files are missing')
    fingerprint = hashlib.sha256()
    for name, content, mode in files:
        fingerprint.update(json.dumps([name, mode, hashlib.sha256(content).hexdigest()]).encode())
    revision = fingerprint.hexdigest()
    output_directory.mkdir(parents=True, exist_ok=True)
    output = output_directory / f'source-{revision}.tar.gz'
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode='wb', mtime=0) as stream:
        with tarfile.open(fileobj=stream, mode='w') as archive:
            for name, content, mode in files:
                entry = tarfile.TarInfo(name)
                entry.size, entry.mode, entry.mtime = len(content), mode, 0
                archive.addfile(entry, io.BytesIO(content))
    content = compressed.getvalue()
    changed = not output.exists() or output.read_bytes() != content
    if changed:
        output.write_bytes(content)
        output.chmod(0o600)
    return {'changed': changed, 'revision': revision, 'archive': str(output), 'files': len(files), 'git_commit': git_commit}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output-directory', type=Path, required=True)
    arguments = parser.parse_args()
    print(json.dumps(package(arguments.source, arguments.output_directory)))
