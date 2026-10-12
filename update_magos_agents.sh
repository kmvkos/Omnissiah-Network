#!/bin/bash
# Скрипт для обновления кода Magos агентов на удаленных узлах
# 
# Использование:
#   ./update_magos_agents.sh <ip_адрес_magos> [ssh_user]
#
# Пример:
#   ./update_magos_agents.sh 10.11.11.100 nmc-admin

set -e

if [ $# -lt 1 ]; then
    echo "❌ Ошибка: не указан IP адрес Magos узла"
    echo ""
    echo "Использование: $0 <ip_адрес_magos> [ssh_user]"
    echo ""
    echo "Примеры:"
    echo "  $0 10.11.11.100"
    echo "  $0 10.11.11.100 nmc-admin"
    exit 1
fi

MAGOS_IP=$1
SSH_USER=${2:-nmc-admin}
AGENT_DIR="agents"

echo "🔄 Обновление Magos агента на $MAGOS_IP..."
echo ""

# Проверяем что директория агента существует
if [ ! -d "$AGENT_DIR" ]; then
    echo "❌ Ошибка: директория $AGENT_DIR не найдена!"
    echo "   Убедитесь что вы запускаете скрипт из корня проекта NMC_WG"
    exit 1
fi

# Проверяем что измененные файлы существуют
NEW_FILES=(
    "$AGENT_DIR/app/update_config.py"
    "$AGENT_DIR/app/agent.py"
)

for file in "${NEW_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo "⚠️  Предупреждение: файл $file не найден"
    fi
done

echo "📦 Файлы для обновления:"
echo "   - app/update_config.py (новый модуль)"
echo "   - app/agent.py (добавлен endpoint /api/magos/update_config)"
echo ""

# Спрашиваем подтверждение
read -p "Продолжить обновление? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "Отменено пользователем"
    exit 0
fi

echo ""
echo "📤 Отправка файлов на $MAGOS_IP..."

# Определяем целевую директорию на удаленном узле
# Предполагаем стандартную структуру: ~/NMC_WGr или /opt/magos
REMOTE_AGENT_DIR=$(ssh "$SSH_USER@$MAGOS_IP" "if [ -d ~/NMC_WGr ]; then echo ~/NMC_WGr; elif [ -d /opt/magos ]; then echo /opt/magos; else echo ~/NMC_WGr; fi" 2>/dev/null || echo "~/NMC_WGr")

echo "   Целевая директория: $REMOTE_AGENT_DIR"

# Отправляем новые/измененные файлы
scp "$AGENT_DIR/app/update_config.py" "$SSH_USER@$MAGOS_IP:$REMOTE_AGENT_DIR/app/" || {
    echo "❌ Ошибка отправки update_config.py"
    exit 1
}
echo "   ✅ app/update_config.py отправлен"

scp "$AGENT_DIR/app/agent.py" "$SSH_USER@$MAGOS_IP:$REMOTE_AGENT_DIR/app/" || {
    echo "❌ Ошибка отправки agent.py"
    exit 1
}
echo "   ✅ app/agent.py отправлен"

echo ""
echo "🔄 Проверка зависимости: cryptography"

# Проверяем наличие cryptography на удаленном узле
ssh "$SSH_USER@$MAGOS_IP" "python3 -c 'import cryptography.fernet' 2>/dev/null && echo 'OK' || echo 'MISSING'" | grep -q "OK" && {
    echo "   ✅ cryptography уже установлен"
} || {
    echo "   ⚠️  cryptography не найден, требуется установка"
    echo "   Выполните на узле Magos: pip3 install cryptography"
}

echo ""
echo "✅ Обновление завершено!"
echo ""
echo "📝 Следующие шаги:"
echo "   1. Если агент запущен, перезапустите его:"
echo "      ssh $SSH_USER@$MAGOS_IP 'cd $REMOTE_AGENT_DIR && pkill -f \"python.*run.py\" && python3 run.py &'"
echo ""
echo "   2. Или остановите и запустите вручную:"
echo "      ssh $SSH_USER@$MAGOS_IP"
echo "      cd $REMOTE_AGENT_DIR"
echo "      # Остановите текущий процесс"
echo "      python3 run.py"
echo ""
echo "   3. Проверьте логи на наличие endpoint /api/magos/update_config"
echo ""
echo "🔒 Важно: Убедитесь что WG_MASTER_KEY присутствует в bootstrap_config.json:"
echo "   ssh $SSH_USER@$MAGOS_IP 'cat $REMOTE_AGENT_DIR/setup/bootstrap_config.json | grep master_key'"

