#!/usr/bin/env bash
# Updates are initiated on control; targets never need GitHub credentials.
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"
case "${1:-}" in
    --help|-h)
        echo 'Запуск на control: bash control-update.sh'
        echo 'Загружает main из origin и обновляет Omni и все Magos из inventory.'
        exit 0 ;;
    '') ;;
    *) echo 'Обновление всего inventory: bash control-update.sh (без параметров).' >&2; exit 2 ;;
esac
command -v git >/dev/null || { echo 'Установите git на control.' >&2; exit 1; }
[[ -f ansible/inventory.yml ]] || { echo 'Нет inventory: сначала выполните первоначальную установку.' >&2; exit 1; }
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo 'Обновление требует Git-клона проекта на control.' >&2; exit 1; }
[[ "$(git branch --show-current)" == main ]] || {
    echo 'Для обновления используйте Git-клон ветки main. Перенос inventory/Vault описан в docs/CONTROL.md.' >&2; exit 1;
}
[[ -z "$(git status --porcelain --untracked-files=normal)" ]] || {
    echo 'В клоне есть локальные изменения. Сохраните их перед обновлением; автоматического сброса нет.' >&2; exit 1;
}
# The lock survives exec and is inherited by the installer and Ansible.
exec 9>ansible/.control-update.lock
flock -n 9 || { echo 'Обновление из этой папки уже выполняется.' >&2; exit 1; }
PREVIOUS_COMMIT="$(git rev-parse HEAD)"
git fetch --no-tags origin main
git merge-base --is-ancestor HEAD refs/remotes/origin/main || {
    echo 'main содержит локальные коммиты или разошлась с origin/main. Обновление остановлено.' >&2; exit 1;
}
git merge --ff-only refs/remotes/origin/main
echo "Версия на control: $PREVIOUS_COMMIT -> $(git rev-parse HEAD)"
echo 'Обновляются Omni и все Magos; Vault будет открыт один раз.'
exec bash "$PROJECT_DIR/control-install.sh" --update --skip-system-packages
