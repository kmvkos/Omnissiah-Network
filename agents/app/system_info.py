import platform
import socket
from datetime import timedelta
from app import db
from models.local_state import General  # Модель узла

def get_uptime():
    try:
        with open("/proc/uptime", "r") as f:
            uptime_seconds = float(f.readline().split()[0])
            return str(timedelta(seconds=uptime_seconds))
    except Exception:
        return "Unknown"

def get_status_info():
    node = General.query.first()
    if not node:
        return {"error": "Magos node info not found in database"}

    return {
        "name": node.name,
        "ip_pool": node.ip_pool,
        "status": "online",
        "hostname": platform.node(),
        "uptime": get_uptime(),
        "connected_clients": get_connected_clients()
    }

def get_connected_clients():
    # Кол-во клиентов (Cognitor), у которых parent_id = ID этого Magos
    node = General.query.first()
    if not node:
        return 0
    return General.query.filter_by(parent_id=node.id).count()