"""
Утилиты для настройки mTLS (mutual TLS) между Omnissiah и Magos
"""
import subprocess
import os
import ipaddress
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
from cryptography.hazmat.backends import default_backend


def generate_ca_certificate(ca_dir):
    """
    Генерирует CA (Certificate Authority) сертификат и ключ
    Возвращает пути к CA сертификату и ключу
    """
    ca_dir = Path(ca_dir)
    ca_dir.mkdir(parents=True, exist_ok=True)
    
    # CA приватный ключ
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    ca_key_path = ca_dir / "ca.key"
    ca_cert_path = ca_dir / "ca.crt"
    if ca_key_path.exists() != ca_cert_path.exists():
        raise ValueError("Incomplete CA: restore the missing file instead of regenerating trust")
    if ca_key_path.exists():
        existing_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
        existing_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
        if existing_key.public_key().public_numbers() != existing_cert.public_key().public_numbers():
            raise ValueError("CA certificate does not match its private key")
        if not existing_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("Existing certificate is not a CA")
        return str(ca_cert_path), str(ca_key_path)
    with open(ca_key_path, "wb") as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    ca_key_path.chmod(0o600)
    
    # CA сертификат
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "RU"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Omnissiah Network"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Omnissiah CA"),
    ])
    
    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=3650)  # 10 лет
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(ca_key, hashes.SHA256(), default_backend())
    
    ca_cert_path = ca_dir / "ca.crt"
    with open(ca_cert_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    ca_cert_path.chmod(0o644)
    
    return str(ca_cert_path), str(ca_key_path)


def generate_server_certificate(ca_cert_path, ca_key_path, server_name, server_dir, server_ip=None):
    """
    Генерирует сертификат для сервера (Omnissiah)
    server_ip: опциональный IP адрес для добавления в SAN
    """
    server_dir = Path(server_dir)
    server_dir.mkdir(parents=True, exist_ok=True)
    
    # Загружаем CA сертификат и ключ
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    
    # Серверный приватный ключ
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    server_key_path = server_dir / "server.key"
    with open(server_key_path, "wb") as f:
        f.write(server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    server_key_path.chmod(0o600)
    
    # Серверный сертификат
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "RU"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Omnissiah Network"),
        x509.NameAttribute(NameOID.COMMON_NAME, server_name),
    ])
    
    # SAN (Subject Alternative Name) - добавляем домен и IP адреса
    san_list = [
        x509.DNSName(server_name),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]
    if server_ip:
        try:
            san_list.append(x509.IPAddress(ipaddress.IPv4Address(server_ip)))
        except:
            pass
    
    server_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        server_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName(san_list),
        critical=False,
    ).sign(ca_key, hashes.SHA256(), default_backend())
    
    server_cert_path = server_dir / "server.crt"
    with open(server_cert_path, "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))
    server_cert_path.chmod(0o644)
    
    return str(server_cert_path), str(server_key_path)


def generate_client_certificate(ca_cert_path, ca_key_path, client_name, client_dir):
    """
    Генерирует сертификат для клиента (Magos)
    """
    client_dir = Path(client_dir)
    client_dir.mkdir(parents=True, exist_ok=True)
    
    # Загружаем CA сертификат и ключ
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    
    # Клиентский приватный ключ
    client_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    client_key_path = client_dir / f"{client_name}.key"
    with open(client_key_path, "wb") as f:
        f.write(client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    client_key_path.chmod(0o600)
    
    # Клиентский сертификат
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "RU"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Omnissiah Network"),
        x509.NameAttribute(NameOID.COMMON_NAME, client_name),
    ])
    
    client_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        client_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(ca_key, hashes.SHA256(), default_backend())
    
    client_cert_path = client_dir / f"{client_name}.crt"
    with open(client_cert_path, "wb") as f:
        f.write(client_cert.public_bytes(serialization.Encoding.PEM))
    client_cert_path.chmod(0o644)
    
    return str(client_cert_path), str(client_key_path)
