"""Read nginx's verified certificate identity on loopback backends."""
from urllib.parse import unquote
from cryptography import x509
from cryptography.x509.oid import NameOID
from flask import request


def proxy_identity():
    # nginx MUST overwrite both headers and the backend MUST bind to loopback.
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return None
    if request.headers.get("X-SSL-Client-Verify") != "SUCCESS":
        return None
    try:
        certificate = x509.load_pem_x509_certificate(
            unquote(request.headers.get("X-SSL-Client-Cert", "")).encode()
        )
        names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value if len(names) == 1 else None
    except ValueError:
        return None


