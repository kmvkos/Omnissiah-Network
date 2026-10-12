#!/bin/bash

# Скрипт установки NMC WG
# Использование: ./install.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🚀 Установка NMC WG"
echo ""

# Проверка прав root/sudo
if [ "$EUID" -eq 0 ]; then
    SUDO_CMD=""
    echo "⚠️  Запуск от root. Рекомендуется запускать от обычного пользователя с sudo правами."
else
    SUDO_CMD="sudo"
    # Проверка наличия sudo
    if ! command -v sudo &> /dev/null; then
        echo "❌ Ошибка: sudo не установлен!"
        echo "Установите sudo или запустите скрипт от root"
        exit 1
    fi
    # Проверка прав sudo
    if ! sudo -n true 2>/dev/null; then
        echo "⚠️  Требуются права sudo. Введите пароль при необходимости."
    fi
fi

# Проверка Python
echo "🔍 Проверка зависимостей системы..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Ошибка: python3 не найден!"
    echo "Установите Python 3.8 или выше:"
    echo "  Ubuntu/Debian: sudo apt-get update && sudo apt-get install python3 python3-pip"
    echo "  CentOS/RHEL: sudo yum install python3 python3-pip"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "✅ Python $PYTHON_VERSION найден"

# Проверка pip
if ! command -v pip3 &> /dev/null; then
    echo "📦 Установка pip3..."
    $SUDO_CMD apt-get update 2>/dev/null || $SUDO_CMD yum update -y 2>/dev/null || true
    $SUDO_CMD apt-get install -y python3-pip 2>/dev/null || $SUDO_CMD yum install -y python3-pip 2>/dev/null || {
        echo "❌ Не удалось установить pip3 автоматически"
        echo "Установите pip3 вручную и запустите скрипт снова"
        exit 1
    }
fi

echo "✅ pip3 найден"

# Проверка WireGuard
echo "🔍 Проверка WireGuard..."
if ! command -v wg &> /dev/null; then
    echo "📦 Установка WireGuard..."
    
    # Определяем дистрибутив
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        echo "⚠️  Не удалось определить дистрибутив, пробуем Ubuntu"
        OS="ubuntu"
    fi
    
    case $OS in
        ubuntu|debian)
            $SUDO_CMD apt-get update
            $SUDO_CMD apt-get install -y wireguard wireguard-tools
            ;;
        centos|rhel|fedora)
            $SUDO_CMD yum install -y epel-release
            $SUDO_CMD yum install -y wireguard-tools
            ;;
        *)
            echo "⚠️  Автоматическая установка WireGuard не поддерживается для $OS"
            echo "Установите WireGuard вручную и запустите скрипт снова"
            exit 1
            ;;
    esac
    
    echo "✅ WireGuard установлен"
else
    echo "✅ WireGuard уже установлен"
fi

# Установка Python зависимостей
echo ""
echo "📦 Установка Python зависимостей..."
if [ -f "requirements.txt" ]; then
    pip3 install --user -r requirements.txt
    echo "✅ Python зависимости установлены"
else
    echo "❌ Ошибка: requirements.txt не найден!"
    exit 1
fi

# Создание необходимых директорий
echo ""
echo "📁 Создание директорий..."
$SUDO_CMD mkdir -p /etc/wireguard
$SUDO_CMD chmod 700 /etc/wireguard

mkdir -p instance
mkdir -p mtls_certs
mkdir -p ssl_certs
mkdir -p users
mkdir -p tmp

echo "✅ Директории созданы"

# Настройка .env файла
echo ""
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        echo "📝 Создание .env файла из примера..."
        cp .env.example .env
        echo "✅ Файл .env создан"
        echo ""
        echo "⚠️  ВАЖНО: Отредактируйте файл .env и заполните обязательные переменные:"
        echo "  - WG_MASTER_KEY (сгенерируйте ключ)"
        echo "  - SUDO_PASSWORD (ваш пароль sudo)"
        echo ""
        echo "Для генерации WG_MASTER_KEY выполните:"
        echo "  python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
        echo ""
    else
        echo "⚠️  Файл .env.example не найден, создайте .env вручную"
    fi
else
    echo "✅ Файл .env уже существует"
fi

# Установка прав на скрипты
echo ""
echo "🔐 Установка прав на скрипты..."
chmod +x start.sh 2>/dev/null || true
chmod +x install.sh 2>/dev/null || true

# Проверка наличия необходимых переменных в .env
if [ -f ".env" ]; then
    echo ""
    echo "🔍 Проверка конфигурации .env..."
    
    source .env 2>/dev/null || true
    
    if [ -z "$WG_MASTER_KEY" ]; then
        echo "⚠️  Предупреждение: WG_MASTER_KEY не установлен в .env"
    else
        echo "✅ WG_MASTER_KEY установлен"
    fi
    
    if [ -z "$SUDO_PASSWORD" ]; then
        echo "⚠️  Предупреждение: SUDO_PASSWORD не установлен в .env"
    else
        echo "✅ SUDO_PASSWORD установлен"
    fi
fi

echo ""
echo "✅ Установка завершена!"
echo ""
echo "Следующие шаги:"
echo "  1. Отредактируйте файл .env и заполните обязательные переменные"
echo "  2. Запустите приложение: ./start.sh"
echo ""
echo "Веб-интерфейс будет доступен по адресу:"
echo "  http://$(hostname -I | awk '{print $1}'):33787"
echo ""
echo "Учетные данные по умолчанию:"
echo "  Email: nmc-admin@nmcwg.loc"
echo "  Password: nmcwg"
echo ""

