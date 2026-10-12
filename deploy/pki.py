"""Persistent local keys and CSR-based issuance. No private key is exported."""
import argparse
from datetime import datetime, timedelta, timezone
import ipaddress
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def write_if_changed(path, content, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() == content:
        return False
    temporary = path.with_name(path.name + '.new')
    temporary.write_bytes(content)
    temporary.chmod(mode)
    temporary.replace(path)
    return True


def load_key(path):
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def public_bytes(key):
    return key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def expires(certificate):
    if hasattr(certificate, 'not_valid_after_utc'):
        return certificate.not_valid_after_utc
    return certificate.not_valid_after.replace(tzinfo=timezone.utc)


def ensure_key(path):
    path = Path(path)
    if path.exists():
        return load_key(path), False
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    write_if_changed(path, key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return key, True


def ensure_ca(directory):
    directory = Path(directory)
    key_path, cert_path = directory / 'ca.key', directory / 'ca.crt'
    if key_path.exists() != cert_path.exists():
        raise ValueError('Incomplete CA: restore the missing file; refusing to rotate trust')
    key, changed = ensure_key(key_path)
    if cert_path.exists():
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        if public_bytes(key) != cert.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
            raise ValueError('CA certificate does not match its key')
        if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError('Certificate is not a CA')
        if expires(cert) <= datetime.now(timezone.utc) + timedelta(days=30):
            raise ValueError('CA expires soon: explicit renewal is required')
        return False
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Omnissiah CA')])
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256()))
    write_if_changed(cert_path, certificate.public_bytes(serialization.Encoding.PEM), 0o644)
    return True


def ensure_csr(directory, name, address):
    directory = Path(directory)
    ip = ipaddress.ip_address(address)
    key, changed = ensure_key(directory / 'identity.key')
    csr_path = directory / 'identity.csr'
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    san = x509.SubjectAlternativeName([x509.DNSName(name), x509.IPAddress(ip)])
    if csr_path.exists():
        previous = x509.load_pem_x509_csr(csr_path.read_bytes())
        if (previous.is_signature_valid and previous.subject == subject
                and previous.public_key().public_bytes(serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo) == public_bytes(key)
                and previous.extensions.get_extension_for_class(x509.SubjectAlternativeName).value == san):
            return changed
    csr = (x509.CertificateSigningRequestBuilder().subject_name(subject)
           .add_extension(san, critical=False).sign(key, hashes.SHA256()))
    return write_if_changed(csr_path, csr.public_bytes(serialization.Encoding.PEM), 0o644) or changed


def sign_csr(ca_directory, csr_path, certificate_path):
    ca_directory = Path(ca_directory)
    key = load_key(ca_directory / 'ca.key')
    ca = x509.load_pem_x509_certificate((ca_directory / 'ca.crt').read_bytes())
    csr = x509.load_pem_x509_csr(Path(csr_path).read_bytes())
    if not csr.is_signature_valid:
        raise ValueError('Invalid CSR signature')
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    certificate_path = Path(certificate_path)
    if certificate_path.exists():
        previous = x509.load_pem_x509_certificate(certificate_path.read_bytes())
        try:
            previous.verify_directly_issued_by(ca)
            if (previous.subject == csr.subject and previous.public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                    == csr.public_key().public_bytes(serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo)
                    and previous.extensions.get_extension_for_class(x509.SubjectAlternativeName).value == san
                    and expires(previous) > datetime.now(timezone.utc) + timedelta(days=30)):
                return False
        except (ValueError, TypeError):
            pass
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(ca.subject)
        .public_key(csr.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(min(now + timedelta(days=365), expires(ca)))
        .add_extension(san, critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()), critical=False)
        .add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(key, hashes.SHA256()))
    return write_if_changed(certificate_path, certificate.public_bytes(serialization.Encoding.PEM), 0o644)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    ca = sub.add_parser('ca'); ca.add_argument('--directory', required=True)
    csr = sub.add_parser('csr'); csr.add_argument('--directory', required=True)
    csr.add_argument('--name', required=True); csr.add_argument('--address', required=True)
    sign = sub.add_parser('sign'); sign.add_argument('--ca-directory', required=True)
    sign.add_argument('--csr', required=True); sign.add_argument('--certificate', required=True)
    args = parser.parse_args()
    if args.operation == 'ca':
        changed = ensure_ca(args.directory)
    elif args.operation == 'csr':
        changed = ensure_csr(args.directory, args.name, args.address)
    else:
        changed = sign_csr(args.ca_directory, args.csr, args.certificate)
    print(json.dumps({'changed': changed}))


if __name__ == '__main__':
    main()
