"""
Модуль шифрования для Magos агента
Должен быть идентичным src/crypto_utils.py на Omnissiah
"""
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class ConfigEncryptor:
    """Класс для шифрования/расшифровки конфигураций"""
    
    def __init__(self, password: bytes = None):
        if password is None:
            password = os.environ.get('NMC_ENCRYPTION_KEY', '').encode()
            if not password:
                password = self._generate_default_key()
        
        self.fernet_key = self._derive_key(password)
        self.cipher = Fernet(self.fernet_key)
    
    @staticmethod
    def _generate_default_key():
        default_key = b'nmc-default-encryption-key-change-in-production'
        return default_key
    
    @staticmethod
    def _derive_key(password: bytes, salt: bytes = None) -> bytes:
        if salt is None:
            salt = b'nmc-salt-v1-2025'
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def encrypt(self, data: bytes) -> bytes:
        return self.cipher.encrypt(data)
    
    def decrypt(self, encrypted_data: bytes) -> bytes:
        return self.cipher.decrypt(encrypted_data)
    
    def encrypt_json(self, data: dict) -> bytes:
        import json
        json_str = json.dumps(data, ensure_ascii=False)
        return self.encrypt(json_str.encode('utf-8'))
    
    def decrypt_json(self, encrypted_data: bytes) -> dict:
        import json
        decrypted = self.decrypt(encrypted_data)
        return json.loads(decrypted.decode('utf-8'))


def get_local_encryptor():
    """
    Создает шифровальщик используя локальную конфигурацию
    
    Использует preshared key из WireGuard конфигурации узла
    """
    from app.config import load_config
    
    config = load_config()
    
    # Используем preshared key из конфигурации
    password = None
    if config.get('preshared_key'):
        password = config['preshared_key'].encode('utf-8')
    elif config.get('public_key'):
        password = config['public_key'].encode('utf-8')
    
    return ConfigEncryptor(password)

