#!/usr/bin/env bash
# Run from the downloaded full project folder on the control VM.
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

PREPARE_ONLY=false
SSH_ONLY=false
SKIP_SYSTEM_PACKAGES=false
ANSIBLE_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --prepare-only) PREPARE_ONLY=true; shift ;;
        --ssh-only) SSH_ONLY=true; SKIP_SYSTEM_PACKAGES=true; shift ;;
        --skip-system-packages) SKIP_SYSTEM_PACKAGES=true; shift ;;
        --help|-h)
            echo 'Запуск: bash control-install.sh [--prepare-only | --ssh-only] [--skip-system-packages] [-- параметры Ansible]'
            echo '--prepare-only: установить Ansible и подготовить inventory/архив, не подключаясь к ВМ.'
            echo '--skip-system-packages: использовать уже подготовленный Python/SSH на control.'
            echo '--ssh-only: проверить SSH и подтвердить новые ключи; ничего не устанавливать.'
            exit 0 ;;
        --) shift; ANSIBLE_ARGS=("$@"); break ;;
        *) echo "Неизвестный параметр: $1" >&2; exit 2 ;;
    esac
done
if [[ "$PREPARE_ONLY" == true && "$SSH_ONLY" == true ]]; then
    echo '--prepare-only и --ssh-only нельзя использовать вместе.' >&2
    exit 2
fi

if [[ ! -f ansible/site.yml || ! -f deploy/package_source.py || ! -f agents/app/agent.py ]]; then
    echo 'Нужна полная скачанная папка проекта рядом с control-install.sh.' >&2
    exit 1
fi

if [[ "$SKIP_SYSTEM_PACKAGES" == false ]]; then
    if ! command -v apt-get >/dev/null 2>&1; then
        echo 'Для автоматической подготовки control нужна Debian/Ubuntu с apt.' >&2
        exit 1
    fi
    SUDO=()
    if [[ "$EUID" -ne 0 ]]; then
        command -v sudo >/dev/null 2>&1 || { echo 'Нужны права root или sudo на control.' >&2; exit 1; }
        SUDO=(sudo)
    fi
    "${SUDO[@]}" apt-get update
    "${SUDO[@]}" apt-get install -y python3 python3-venv python3-pip openssh-client
fi

if [[ "$SSH_ONLY" == true ]]; then
    [[ -x .ansible-venv/bin/ansible-inventory && -f ansible/inventory.yml ]] || {
        echo 'Сначала выполните bash control-install.sh --prepare-only.' >&2; exit 1;
    }
    export PATH="$PROJECT_DIR/.ansible-venv/bin:$PATH"
    cd ansible
    exec python ../deploy/control_ssh.py --inventory inventory.yml -- "${ANSIBLE_ARGS[@]}"
fi

python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,12) else "На control требуется Python 3.12+; рекомендуется Debian 13.")'
if [[ ! -x .ansible-venv/bin/python ]]; then
    python3 -m venv .ansible-venv
fi
.ansible-venv/bin/python -m pip install -r ansible/requirements-control.txt
.ansible-venv/bin/python deploy/control_inventory.py --inventory ansible/inventory.yml

export PATH="$PROJECT_DIR/.ansible-venv/bin:$PATH"
cd ansible
ansible-playbook -i inventory.yml site.yml --syntax-check
ansible-playbook -i inventory.yml site.yml --tags prepare

if [[ "$PREPARE_ONLY" == true ]]; then
    echo 'Control подготовлен. Для раскатки повторите: bash control-install.sh'
    exit 0
fi

if [[ ${#ANSIBLE_ARGS[@]} -eq 0 ]]; then
    ANSIBLE_ARGS=(--ask-become-pass)
fi
python ../deploy/control_ssh.py --inventory inventory.yml -- "${ANSIBLE_ARGS[@]}"
echo 'SSH проверен. Запускается развёртывание на все целевые узлы inventory.'
exec ansible-playbook -i inventory.yml site.yml "${ANSIBLE_ARGS[@]}"
