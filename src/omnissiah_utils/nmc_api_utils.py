"""
Утилиты для работы с API узлов (Omnissiah, Magos, Cognitor)
"""
from ipaddress import ip_network


def get_api_url(node, endpoint="/api/add_peer", default_port=5001, use_ip=False):
    """
    Формирует URL для API запроса к узлу с учетом настроек nginx/TLS
    
    Args:
        node: Объект General (узел Magos или Omnissiah)
        endpoint: API endpoint (по умолчанию /api/add_peer)
        default_port: Порт по умолчанию для API (5001 для Magos, 33787 для Omnissiah)
        use_ip: Если True, использовать IP адрес вместо домена (для агентов)
    
    Returns:
        str: Полный URL (https:// или http://)
    """
    # Проверяем, настроен ли nginx с TLS
    if node.nginx_enabled and node.nginx_cert_path and node.nginx_key_path:
        # Используем HTTPS
        protocol = "https"
        port = node.nginx_https_port if node.nginx_https_port else 443
        # Для агентов используем IP, для браузера - домен (если не указано use_ip)
        if use_ip or not node.nginx_domain:
            # Используем IP из endpoint или ip_pool
            if node.endpoint:
                host = node.endpoint.split(':')[0]  # IP из endpoint (например, "10.11.11.65:51820" -> "10.11.11.65")
            else:
                host = node.ip_pool.split("/")[0] if node.ip_pool else "127.0.0.1"
        else:
            host = node.nginx_domain
    else:
        # Используем HTTP
        protocol = "http"
        port = default_port
        # Используем endpoint IP если есть, иначе ip_pool
        if node.endpoint:
            host = node.endpoint.split(':')[0]
        else:
            host = node.ip_pool.split("/")[0] if node.ip_pool else "127.0.0.1"
    
    # Если порт стандартный для протокола, можно его не указывать
    if (protocol == "https" and port == 443) or (protocol == "http" and port == 80):
        url = f"{protocol}://{host}{endpoint}"
    else:
        url = f"{protocol}://{host}:{port}{endpoint}"
    
    return url


def get_next_available_ip(node):
    """
    Возвращает следующий свободный IP для указанного узла
    
    Args:
        node: Объект General (узел)
    
    Returns:
        str: Следующий доступный IP адрес с префиксом (например, "10.0.0.5/24") или None
    """
    try:
        network = ip_network(node.ip_pool, strict=False)
        used_ips = set()
        
        # Добавляем IP самого узла
        server_ip = node.ip_pool.split('/')[0]
        used_ips.add(server_ip)
        
        # Добавляем все используемые IP от дочерних узлов
        for peer in node.all_children:
            if peer.ip_pool:
                peer_ip = peer.ip_pool.split('/')[0]
                used_ips.add(peer_ip)

        # Ищем первый свободный IP
        prefix_len = network.prefixlen
        for host in network.hosts():
            host_ip = str(host)
            if host_ip not in used_ips:
                return f"{host_ip}/{prefix_len}"
        return None
    except (ValueError, AttributeError, KeyError) as e:
        # Логирование будет выполнено в вызывающем коде
        return None


def get_next_available_ip_list(node, limit=50):
    """
    Возвращает список свободных IP для выбора (до limit штук)
    
    Args:
        node: Объект General (узел)
        limit: Максимальное количество IP для возврата
    
    Returns:
        list: Список доступных IP адресов с префиксом
    """
    try:
        network = ip_network(node.ip_pool, strict=False)
        used_ips = set()
        
        # Добавляем IP самого узла
        server_ip = node.ip_pool.split('/')[0]
        used_ips.add(server_ip)
        
        # Добавляем все используемые IP от дочерних узлов
        for peer in node.all_children:
            if peer.ip_pool:
                peer_ip = peer.ip_pool.split('/')[0]
                used_ips.add(peer_ip)
        
        # Собираем свободные IP
        prefix_len = network.prefixlen
        available = []
        for host in network.hosts():
            host_ip = str(host)
            if host_ip not in used_ips:
                available.append(f"{host_ip}/{prefix_len}")
                if len(available) >= limit:
                    break
        
        return available
    except (ValueError, AttributeError, TypeError) as e:
        # Логирование будет выполнено в вызывающем коде
        return []
    except (AttributeError, RuntimeError) as e:
        # Логирование будет выполнено в вызывающем коде
        return []

