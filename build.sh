#!/usr/bin/env bash
# Package committed project files only; runtime data stays outside the archive.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

if ! git rev-parse --verify HEAD >/dev/null 2>&1; then
    echo "Ошибка: для сборки нужен Git-репозиторий с коммитом." >&2
    exit 1
fi

mkdir -p dist
ARCHIVE_PATH="$PROJECT_DIR/dist/omnissiah-network-$(date -u +%Y%m%d_%H%M%S)-$(git rev-parse --short HEAD).tar.gz"
git archive --format=tar.gz --prefix=omnissiah-network/ --output="$ARCHIVE_PATH" HEAD

echo "Архив создан: $ARCHIVE_PATH"
echo "Включены только файлы текущего коммита. Локальные настройки создайте на целевой ВМ."
