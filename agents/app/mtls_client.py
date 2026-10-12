"""
Утилиты для работы с mTLS на стороне клиента (Magos агента)
"""
import os
from pathlib import Path
import requests
from requests.adapters import HTTPAdapter
try:
    from urllib3.util.ssl_ import create_urllib3_context
except ImportError:
    # Для старых версий urllib3
    from urllib3.poolmanager import PoolManager
    from urllib3.util import ssl_
    create_urllib3_context = ssl_.create_urllib3_context


class MTLSAdapter(HTTPAdapter):
    """HTTPAdapter с поддержкой клиентских сертификатов для mTLS"""
    
    def __init__(self, cert_file, key_file, ca_cert_file=None, *args, **kwargs):
        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_cert_file = ca_cert_file
        super().__init__(*args, **kwargs)
    
    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        # Загружаем клиентский сертификат и ключ (для mTLS)
        ctx.load_cert_chain(self.cert_file, self.key_file)
        
        # Настройка проверки серверного сертификата
        # ВАЖНО: Nginx использует TLS сертификат (self-signed для om.pro),
        # который НЕ подписан нашим mTLS CA. Поэтому отключаем проверку серверного сертификата.
        # Сервер все равно будет проверять клиентский сертификат агента (mTLS).
        ctx.check_hostname = False  # Отключаем проверку hostname (используем IP)
        import ssl
        ctx.verify_mode = ssl.CERT_NONE  # Отключаем проверку серверного сертификата
        # Клиентский сертификат все равно отправляется и проверяется сервером
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)


def create_mtls_session(cert_file, key_file, ca_cert_file=None):
    """
    Создает requests.Session с поддержкой mTLS
    
    Args:
        cert_file: путь к клиентскому сертификату (.crt)
        key_file: путь к клиентскому ключу (.key)
        ca_cert_file: путь к CA сертификату для проверки сервера (опционально)
    
    Returns:
        requests.Session с настроенным mTLS
    """
    session = requests.Session()
    
    # Проверяем наличие файлов
    if not os.path.exists(cert_file):
        raise FileNotFoundError(f"Клиентский сертификат не найден: {cert_file}")
    if not os.path.exists(key_file):
        raise FileNotFoundError(f"Клиентский ключ не найден: {key_file}")
    
    # Создаем адаптер с mTLS
    adapter = MTLSAdapter(cert_file, key_file, ca_cert_file)
    session.mount('https://', adapter)
    
    # ВАЖНО: Отключаем проверку серверного TLS сертификата
    # потому что Nginx использует self-signed TLS сертификат (om.pro.crt),
    # который не подписан нашим mTLS CA. 
    # Сервер все равно проверяет клиентский сертификат агента через mTLS.
    session.verify = False
    
    return session


def get_mtls_session_from_config(config):
    """
    Создает mTLS сессию на основе конфигурации агента
    
    Args:
        config: словарь конфигурации с полями:
            - mtls_cert_file: путь к клиентскому сертификату (относительно директории агента)
            - mtls_key_file: путь к клиентскому ключу (относительно директории агента)
            - mtls_ca_cert_file: путь к CA сертификату (опционально, относительно директории агента)
    
    Returns:
        requests.Session с mTLS или None, если сертификаты не настроены
    """
    cert_file = config.get('mtls_cert_file')
    key_file = config.get('mtls_key_file')
    ca_cert_file = config.get('mtls_ca_cert_file')
    
    if not cert_file or not key_file:
        return None
    
    # Преобразуем относительные пути в абсолютные (относительно директории агента)
    agent_dir = Path(__file__).parent.parent
    cert_file_abs = (agent_dir / cert_file).resolve() if not Path(cert_file).is_absolute() else Path(cert_file)
    key_file_abs = (agent_dir / key_file).resolve() if not Path(key_file).is_absolute() else Path(key_file)
    ca_cert_file_abs = None
    if ca_cert_file:
        ca_cert_file_abs = (agent_dir / ca_cert_file).resolve() if not Path(ca_cert_file).is_absolute() else Path(ca_cert_file)
    
    try:
        return create_mtls_session(str(cert_file_abs), str(key_file_abs), str(ca_cert_file_abs) if ca_cert_file_abs else None)
    except Exception as e:
        print(f"[mTLS] Ошибка создания mTLS сессии: {e}")
        import traceback
        print(f"[mTLS] Детали: {traceback.format_exc()}")
        return None

