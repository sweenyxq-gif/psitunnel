"""
Self-signed TLS certificate generator using standard cryptography module.
"""

import datetime
import ipaddress
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_self_signed_cert(
    common_name: str = "localhost",
    cert_days: int = 365,
) -> Tuple[bytes, bytes]:
    """
    Generates a private key and self-signed X.509 certificate in PEM format.
    Returns: (cert_pem_bytes, key_pem_bytes)
    """
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PsiTunnel Network"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # Try adding SAN (Subject Alternative Name)
    alt_names = []
    try:
        ip = ipaddress.ip_address(common_name)
        alt_names.append(x509.IPAddress(ip))
    except ValueError:
        alt_names.append(x509.DNSName(common_name))
    alt_names.append(x509.DNSName("localhost"))
    alt_names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=cert_days))
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return cert_pem, key_pem

