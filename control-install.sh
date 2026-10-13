#!/usr/bin/env bash
# Run from the downloaded full project folder on the control VM.
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"
UPDATE=false
PREPARE_ONLY=false
SSH_ONLY=false
ACCESS_ONLY=false
PASSWORD_AUTH=false
CONFIGURE_PASSWORDS=false
PREPARED_STAGE=false
SKIP_SYSTEM_PACKAGES=false
ANSIBLE_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --update) UPDATE=true; SKIP_SYSTEM_PACKAGES=true; shift ;;
        --prepare-only) PREPARE_ONLY=true; shift ;;
        --ssh-only) SSH_ONLY=true; SKIP_SYSTEM_PACKAGES=true; shift ;;
        --access-only) ACCESS_ONLY=true; SKIP_SYSTEM_PACKAGES=true; shift ;;
        --password-auth) PASSWORD_AUTH=true; shift ;;
        --configure-passwords) PASSWORD_AUTH=true; CONFIGURE_PASSWORDS=true; shift ;;
        --prepared-stage) PREPARED_STAGE=true; shift ;;
        --skip-system-packages) SKIP_SYSTEM_PACKAGES=true; shift ;;
        --help|-h)
            echo 'Запуск: bash control-install.sh [--password-auth] [--prepare-only | --ssh-only | --access-only] [--skip-system-packages] [-- параметры Ansible]'
            echo '--update: обновить существующие узлы, сохранив резервные копии состояния.'
            echo '--password-auth: задать SSH/sudo-пароли в Vault и использовать вход по паролю.'
            echo '--configure-passwords: изменить сохранённые пароли и пароль Vault.'
            echo '--prepare-only: подготовить control и inventory без подключения к ВМ.'
            echo '--ssh-only: проверить SSH; --access-only: проверить SSH и sudo без установки компонентов.'
            echo '--skip-system-packages: использовать уже подготовленные Python/SSH/sshpass на control.'
            exit 0 ;;
        --) shift; ANSIBLE_ARGS=("$@"); break ;;
        *) echo "Неизвестный параметр: $1" >&2; exit 2 ;;
    esac
done
if [[ ( "$PREPARE_ONLY" == true && ( "$SSH_ONLY" == true || "$ACCESS_ONLY" == true ) ) || ( "$SSH_ONLY" == true && "$ACCESS_ONLY" == true ) ]]; then
    echo 'Выберите один режим: --prepare-only, --ssh-only или --access-only.' >&2
    exit 2
fi
if [[ "$UPDATE" == true ]]; then
    [[ "$PREPARE_ONLY" == false && "$SSH_ONLY" == false && "$ACCESS_ONLY" == false && -f ansible/inventory.yml ]] || {
        echo '--update требует существующий inventory и полный запуск.' >&2; exit 2;
    }
fi
if [[ ! -f ansible/site.yml || ! -f deploy/package_source.py || ! -f agents/app/agent.py ]]; then
    echo 'Нужна полная скачанная папка проекта рядом с control-install.sh.' >&2
    exit 1
fi
if [[ "$PREPARED_STAGE" == false ]]; then
    if [[ "$SSH_ONLY" == true || "$ACCESS_ONLY" == true ]]; then
        [[ -x .ansible-venv/bin/ansible-inventory && -f ansible/inventory.yml ]] || {
            echo 'Сначала выполните bash control-install.sh --prepare-only.' >&2; exit 1;
        }
    else
        if [[ "$SKIP_SYSTEM_PACKAGES" == false ]]; then
            command -v apt-get >/dev/null 2>&1 || { echo 'Для подготовки control нужна Debian/Ubuntu с apt.' >&2; exit 1; }
            SUDO=()
            if [[ "$EUID" -ne 0 ]]; then
                command -v sudo >/dev/null 2>&1 || { echo 'Нужны права root или sudo на control.' >&2; exit 1; }
                SUDO=(sudo)
            fi
            "${SUDO[@]}" apt-get update
            "${SUDO[@]}" apt-get install -y python3 python3-venv python3-pip openssh-client sshpass
        fi
        python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,12) else "На control требуется Python 3.12+; рекомендуется Debian 13.")'
        if [[ ! -x .ansible-venv/bin/python ]]; then
            python3 -m venv .ansible-venv
        fi
        .ansible-venv/bin/python -m pip install -r ansible/requirements-control.txt
        .ansible-venv/bin/python deploy/control_inventory.py --inventory ansible/inventory.yml
    fi
fi
export PATH="$PROJECT_DIR/.ansible-venv/bin:$PATH"
VAULT_FILE="$PROJECT_DIR/ansible/credentials.vault.yml"
if [[ "$PREPARED_STAGE" == false && ( "$PASSWORD_AUTH" == true || -f "$VAULT_FILE" ) ]]; then
    NEXT_ARGS=(--prepared-stage)
    [[ "$UPDATE" == false ]] || NEXT_ARGS+=(--update)
    [[ "$PREPARE_ONLY" == false ]] || NEXT_ARGS+=(--prepare-only)
    [[ "$SSH_ONLY" == false ]] || NEXT_ARGS+=(--ssh-only)
    [[ "$ACCESS_ONLY" == false ]] || NEXT_ARGS+=(--access-only)
    CONFIG_ARGS=()
    [[ "$CONFIGURE_PASSWORDS" == false ]] || CONFIG_ARGS+=(--configure)
    exec python deploy/control_passwords.py --vault "$VAULT_FILE" "${CONFIG_ARGS[@]}" -- \
        bash "$PROJECT_DIR/control-install.sh" "${NEXT_ARGS[@]}" -- "${ANSIBLE_ARGS[@]}"
fi
VAULT_ARGS=()
if [[ "${OMNISSIAH_PASSWORD_AUTH_ACTIVE:-0}" == 1 ]]; then
    command -v sshpass >/dev/null 2>&1 || {
        echo 'На control нужен sshpass: sudo apt-get install -y sshpass' >&2; exit 1;
    }
    VAULT_ARGS=(-e "@$VAULT_FILE")
fi
cd ansible
if [[ "$SSH_ONLY" == true || "$ACCESS_ONLY" == true ]]; then
    python ../deploy/control_ssh.py --inventory inventory.yml -- "${VAULT_ARGS[@]}" "${ANSIBLE_ARGS[@]}"
    if [[ "$SSH_ONLY" == true ]]; then
        if [[ ${#VAULT_ARGS[@]} -gt 0 ]]; then
            exec ansible-playbook -i inventory.yml ssh.yml "${VAULT_ARGS[@]}" "${ANSIBLE_ARGS[@]}"
        fi
        exit 0
    fi
    if [[ ${#ANSIBLE_ARGS[@]} -eq 0 && ${#VAULT_ARGS[@]} -eq 0 ]]; then
        ANSIBLE_ARGS=(--ask-become-pass)
    fi
    exec ansible-playbook -i inventory.yml access.yml "${VAULT_ARGS[@]}" "${ANSIBLE_ARGS[@]}"
fi
ansible-playbook -i inventory.yml site.yml --syntax-check "${VAULT_ARGS[@]}"
ansible-playbook -i inventory.yml site.yml --tags prepare "${VAULT_ARGS[@]}"
if [[ "$PREPARE_ONLY" == true ]]; then
    echo 'Control подготовлен. Для раскатки повторите: bash control-install.sh'
    exit 0
fi
if [[ ${#ANSIBLE_ARGS[@]} -eq 0 && ${#VAULT_ARGS[@]} -eq 0 ]]; then
    ANSIBLE_ARGS=(--ask-become-pass)
fi
python ../deploy/control_ssh.py --inventory inventory.yml -- "${VAULT_ARGS[@]}" "${ANSIBLE_ARGS[@]}"
UPDATE_ARGS=()
[[ "$UPDATE" == false ]] || UPDATE_ARGS=(-e omnissiah_update=true)
echo 'Запускается развёртывание на все целевые узлы inventory.'
exec ansible-playbook -i inventory.yml site.yml "${VAULT_ARGS[@]}" "${UPDATE_ARGS[@]}" "${ANSIBLE_ARGS[@]}"
