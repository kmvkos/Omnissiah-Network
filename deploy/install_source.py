"""Replace only files owned by source archives, including removed source files."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile


def members(archive):
    result = {}
    for entry in archive.getmembers():
        path = PurePosixPath(entry.name)
        if (not entry.isfile() or path.is_absolute() or '..' in path.parts or
                (len(path.parts) == 1 and entry.name not in ('requirements.txt', 'mtls_utils.py')) or
                (len(path.parts) > 1 and path.parts[0] not in ('src', 'agents', 'templates', 'deploy')) or
                any(part.startswith('.') or part in ('venv', 'database', 'data', 'pki', '__pycache__') for part in path.parts) or
                path.suffix not in ('.py', '.html', '.txt')):
            # .env.example and .gitignore were historically included in agents/.
            if entry.isfile() and not path.is_absolute() and '..' not in path.parts and len(path.parts) > 1 and path.parts[0] in ('src', 'agents', 'templates', 'deploy') and path.name in ('.env.example', '.gitignore'):
                result[entry.name] = entry
                continue
            raise ValueError(f'Unsupported source archive member: {entry.name}')
        result[entry.name] = entry
    return result


def target_path(project, name):
    path = project / name
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != project):
        raise ValueError(f'Refusing to overwrite a source symlink: {name}')
    return path


def install(project, incoming):
    project, incoming = Path(project).resolve(), Path(incoming).resolve()
    previous = project / '.source.tar.gz'
    with tarfile.open(incoming) as archive:
        desired = members(archive)
        old = {}
        if previous.is_file():
            with tarfile.open(previous) as prior:
                old = members(prior)
        # Validate every path before removing or replacing any source.
        paths = {name: target_path(project, name) for name in desired.keys() | old.keys()}
        changed = False
        for name, entry in desired.items():
            content = archive.extractfile(entry).read()
            target = paths[name]
            if target.is_file() and target.read_bytes() == content:
                continue
            missing = []
            directory = target.parent
            while not directory.exists():
                missing.append(directory)
                directory = directory.parent
            for directory in reversed(missing):
                directory.mkdir(mode=0o755)
                directory.chmod(0o755)
            descriptor, temporary = tempfile.mkstemp(prefix='.source-', dir=target.parent)
            try:
                with os.fdopen(descriptor, 'wb') as stream:
                    stream.write(content)
                os.chmod(temporary, 0o644)
                os.replace(temporary, target)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            changed = True
        for name in old.keys() - desired.keys():
            target = paths[name]
            if target.is_file():
                target.unlink()
                changed = True
        if not previous.is_file() or previous.read_bytes() != incoming.read_bytes():
            temporary = project / '.source-committed.tar.gz'
            shutil.copyfile(incoming, temporary)
            temporary.chmod(0o600)
            os.replace(temporary, previous)
            changed = True
    return {'changed': changed}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(install(args.project, args.archive)))
