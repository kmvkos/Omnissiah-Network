#!/bin/bash

# =============================================
# Omnissiah Network COMPLETE INSTALLATION SCRIPT (Fixed DB Init)
# Version: 3.7
# =============================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parameters
INSTALL_DIR="/opt/nmcwg"
VENV_DIR="$INSTALL_DIR/venv"
APP_DIR="$INSTALL_DIR/app"
SERVICE_USER="nmc-"
SERVICE_GROUP="nmcwgloc"
SERVICE_NAME="nmcwg"
SERVICE_PORT="33787"
WG_DIR="/etc/wireguard"
DEBUG_MODE=false
RUN_MODE="install"

# Full list of Python dependencies
PYTHON_DEPS="
flask==2.3.2
flask-sqlalchemy==3.0.3
flask-login==0.6.2
flask-wtf==1.0.1
werkzeug==2.3.6
wtforms==3.0.1
requests==2.31.0
python-dotenv==1.0.0
cryptography==41.0.2
qrcode[pil]==7.4.2
pillow==10.0.0
apscheduler==3.10.1
sqlalchemy==2.0.19
ipaddress==1.0.23
pycryptodome==3.18.0
fernet==1.0.1
python-prctl==1.8.1
pyjwt==2.8.0
wtforms[email]==3.0.1
pyopenssl==23.2.0
"

# ========================
# INSTALLATION FUNCTIONS
# ========================

# Logging
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

# Check root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log "${RED}Error: This script must be run as root${NC}"
        exit 1
    fi
}

# Install system dependencies
install_system_deps() {
    log "${YELLOW}Installing system dependencies...${NC}"

    local base_pkgs=(
        python3-pip python3-venv python3-dev
        build-essential libssl-dev libffi-dev libjpeg-dev
        zlib1g-dev libpng-dev libpq-dev net-tools
        qrencode git sqlite3 tmux htop
        libcap-dev libcap-ng-dev
    )

    local service_pkgs=(
        wireguard wireguard-tools resolvconf
        nginx supervisor ufw fail2ban
    )

    apt-get update -qq
    if ! apt-get install -y -qq "${base_pkgs[@]}" "${service_pkgs[@]}"; then
        log "${RED}Error: Failed to install system packages${NC}"
        exit 1
    fi

    log "${GREEN}System dependencies installed${NC}"
}

# Configure system
configure_system() {
    log "${YELLOW}Configuring system parameters...${NC}"

    if ! getent group "$SERVICE_GROUP" >/dev/null; then
        groupadd -r "$SERVICE_GROUP" || {
            log "${RED}Error: Failed to create group $SERVICE_GROUP${NC}"
            exit 1
        }
    fi

    if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
        useradd -r -g "$SERVICE_GROUP" -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER" || {
            log "${RED}Error: Failed to create user $SERVICE_USER${NC}"
            exit 1
        }
    fi

    mkdir -p "$WG_DIR" "$INSTALL_DIR" "$INSTALL_DIR/logs" || {
        log "${RED}Error: Failed to create directories${NC}"
        exit 1
    }

    chown -R "$SERVICE_USER":"$SERVICE_GROUP" "$WG_DIR" "$INSTALL_DIR" || {
        log "${RED}Error: Failed to set permissions${NC}"
        exit 1
    }
    chmod 750 "$INSTALL_DIR"

    # Configure UFW permissions
    log "${YELLOW}Configuring UFW permissions...${NC}"
    cat > /etc/sudoers.d/nmc-ufw << 'EOF'
# Rules for Omnissiah Network Manager
nmc-admin ALL=(root) NOPASSWD: /usr/sbin/ufw
%nmcwgloc ALL=(root) NOPASSWD: /usr/sbin/ufw
EOF

    chmod 0440 /etc/sudoers.d/nmc-ufw

    # Configure firewall
    log "${YELLOW}Configuring firewall...${NC}"
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow "$SERVICE_PORT/tcp"
    ufw allow 22/tcp
    ufw --force enable

    log "${GREEN}System configured${NC}"
}

# Setup Python environment
setup_python_env() {
    log "${YELLOW}Creating Python environment...${NC}"

    if [ ! -d "$VENV_DIR" ]; then
        python3 -m venv "$VENV_DIR" || {
            log "${RED}Error: Failed to create Python virtual environment${NC}"
            exit 1
        }
    fi

    source "$VENV_DIR/bin/activate"

    python3 -m pip install --upgrade pip wheel setuptools || {
        log "${RED}Error: Failed to upgrade pip${NC}"
        exit 1
    }

    for attempt in {1..3}; do
        echo "$PYTHON_DEPS" | pip install -r /dev/stdin && break

        if [ $attempt -eq 3 ]; then
            log "${RED}Error: Failed to install Python dependencies after 3 attempts${NC}"
            exit 1
        fi

        log "${YELLOW}Retrying Python dependencies installation (attempt $attempt)...${NC}"
        sleep 5
    done

    if ! python3 -c "import sqlalchemy, flask, cryptography, prctl" 2>/dev/null; then
        log "${RED}Error: Failed to verify critical dependencies${NC}"
        exit 1
    fi

    deactivate
    log "${GREEN}Python environment configured${NC}"
}

# Copy project files
copy_project_files() {
    log "${YELLOW}Copying project files...${NC}"

    local SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

    local required_dirs=("src" "templates")
    for dir in "${required_dirs[@]}"; do
        if [ ! -d "$SCRIPT_DIR/$dir" ]; then
            log "${RED}Error: Missing required directory: $dir${NC}"
            exit 1
        fi
    done

    local required_files=("src/app.py" "src/models.py")
    for file in "${required_files[@]}"; do
        if [ ! -f "$SCRIPT_DIR/$file" ]; then
            log "${RED}Error: Missing required file: $file${NC}"
            exit 1
        fi
    done

    mkdir -p "$APP_DIR"
    rsync -a --exclude='.git' --exclude='venv' "$SCRIPT_DIR/" "$APP_DIR/" || {
        log "${RED}Error: Failed to copy project files${NC}"
        exit 1
    }

    chown -R "$SERVICE_USER":"$SERVICE_GROUP" "$APP_DIR"
    find "$APP_DIR" -type d -exec chmod 750 {} \;
    find "$APP_DIR" -type f -exec chmod 640 {} \;

    log "${GREEN}Project files copied successfully${NC}"
}

# Initialize database
init_database() {
    log "${YELLOW}Initializing database...${NC}"

    source "$VENV_DIR/bin/activate"

    local DB_INIT_SCRIPT=$(mktemp)
    cat > "$DB_INIT_SCRIPT" << 'EOL'
import os
import sys

# Add app directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.app import create_app
from src.models import db

app = create_app()
with app.app_context():
    db.create_all()
    print("Database tables created successfully")
EOL

    if ! python3 "$DB_INIT_SCRIPT" > "$INSTALL_DIR/logs/db_init.log" 2>&1; then
        log "${RED}Error: Failed to initialize database${NC}"
        cat "$INSTALL_DIR/logs/db_init.log"
        rm -f "$DB_INIT_SCRIPT"
        exit 1
    fi

    rm -f "$DB_INIT_SCRIPT"
    deactivate
    log "${GREEN}Database initialized successfully${NC}"
}

# Setup systemd service
setup_systemd_service() {
    log "${YELLOW}Configuring systemd service...${NC}"

    cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=Omnissiah Network Service
After=network.target
Requires=network.target

[Service]
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$APP_DIR
Environment="PATH=$VENV_DIR/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="PYTHONUNBUFFERED=1"
ExecStart=$VENV_DIR/bin/python $APP_DIR/src/app.py
Restart=always
RestartSec=5
StandardOutput=file:$INSTALL_DIR/logs/service.log
StandardError=file:$INSTALL_DIR/logs/error.log

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"

    log "${GREEN}Systemd service configured${NC}"
}

# Setup NGINX proxy
setup_nginx() {
    log "${YELLOW}Configuring Nginx proxy...${NC}"

    if [ ! -f "/etc/nginx/sites-available/$SERVICE_NAME" ]; then
        cat > "/etc/nginx/sites-available/$SERVICE_NAME" << EOF
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:$SERVICE_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF

        ln -sf "/etc/nginx/sites-available/$SERVICE_NAME" "/etc/nginx/sites-enabled/"
        systemctl restart nginx
        log "${GREEN}Nginx proxy configured${NC}"
    else
        log "${YELLOW}Nginx configuration already exists, skipping${NC}"
    fi
}

# Start service
start_service() {
    log "${YELLOW}Starting service...${NC}"

    if [ "$DEBUG_MODE" = true ]; then
        log "${YELLOW}Running in DEBUG mode (foreground with output)...${NC}"
        systemctl stop "$SERVICE_NAME" >/dev/null 2>&1
        sleep 2
        sudo -u "$SERVICE_USER" "$VENV_DIR/bin/python" "$APP_DIR/src/app.py"
    else
        systemctl restart "$SERVICE_NAME"
        sleep 2
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            log "${GREEN}Service started successfully${NC}"
        else
            log "${RED}Error: Failed to start service${NC}"
            log "${YELLOW}Check logs: $INSTALL_DIR/logs/error.log${NC}"
            exit 1
        fi
    fi
}

# Completion message
show_completion() {
    log "${GREEN}Operation completed successfully!${NC}"
    echo ""
    echo "==============================="
    echo "Service access:"
    echo -e "  ${YELLOW}http://$(hostname -I | awk '{print $1}'):$SERVICE_PORT${NC}"
    echo ""
    echo "Service control:"
    echo "  sudo systemctl start $SERVICE_NAME"
    echo "  sudo systemctl stop $SERVICE_NAME"
    echo "  sudo systemctl status $SERVICE_NAME"
    echo ""
    echo "Logs:"
    echo "  sudo tail -f $INSTALL_DIR/logs/service.log"
    echo "  sudo tail -f $INSTALL_DIR/logs/error.log"
    echo ""
    echo "Default credentials:"
    echo "  Email: Adeptus"
    echo "  Password: Mechanicus"
    echo ""
    echo "IMPORTANT: Change default credentials immediately!"
    echo "==============================="
}

# Main installation process
main_install() {
    check_root
    log "${GREEN}Starting Omnissiah Network installation...${NC}"

    install_system_deps
    configure_system
    setup_python_env
    copy_project_files
    init_database
    setup_systemd_service
    setup_nginx

    start_service
    show_completion
}

# Update process
main_update() {
    check_root
    log "${GREEN}Starting Omnissiah Network update...${NC}"

    systemctl stop "$SERVICE_NAME"

    local SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

    log "${YELLOW}Copying updated files...${NC}"
    rsync -a --exclude='.git' --exclude='venv' "$SCRIPT_DIR/" "$APP_DIR/" || {
        log "${RED}Error: Failed to copy updated files${NC}"
        exit 1
    }

    install_system_deps
    setup_python_env
    init_database
    systemctl daemon-reload
    start_service

    log "${GREEN}Update completed!${NC}"
    systemctl status "$SERVICE_NAME"
}

# Start service only
main_start() {
    check_root
    log "${GREEN}Starting Omnissiah Network service...${NC}"
    start_service
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --install)
            RUN_MODE="install"
            shift
            ;;
        --update)
            RUN_MODE="update"
            shift
            ;;
        --start)
            RUN_MODE="start"
            shift
            ;;
        --debug)
            DEBUG_MODE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --install   Full installation (default)"
            echo "  --update    Update existing installation"
            echo "  --start     Start service only"
            echo "  --debug     Run in debug mode (with console output)"
            echo "  --help, -h  Show this help"
            exit 0
            ;;
        *)
            log "${RED}Error: Unknown argument $1${NC}"
            exit 1
            ;;
    esac
done

# Main execution
case "$RUN_MODE" in
    "install")
        main_install
        ;;
    "update")
        main_update
        ;;
    "start")
        main_start
        ;;
    *)
        log "${RED}Error: Invalid run mode${NC}"
        exit 1
        ;;
esac