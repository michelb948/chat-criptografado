
from pathlib import Path
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_certificate():
    # Pasta onde ficarão o certificado e a chave privada.
    cert_dir = Path("certs")
    cert_dir.mkdir(exist_ok=True)

    key_path = cert_dir / "server.key"
    cert_path = cert_dir / "server.crt"

    # Gera uma chave privada RSA de 2048 bits.
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Identificação do servidor no certificado.
    subject = issuer = x509.Name([
        x509.NameAttribute(
            NameOID.COUNTRY_NAME, "BR"
        ),
        x509.NameAttribute(
            NameOID.STATE_OR_PROVINCE_NAME, "Ceara"
        ),
        x509.NameAttribute(
            NameOID.ORGANIZATION_NAME, "Mensageria Segura"
        ),
        x509.NameAttribute(
            NameOID.COMMON_NAME, "localhost"
        ),
    ])

    now = datetime.utcnow()

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(
                    __import__("ipaddress").ip_address("127.0.0.1")
                ),
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(
                ca=False,
                path_length=None
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Salva a chave privada em formato PEM.
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    # Salva o certificado em formato PEM.
    cert_path.write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM)
    )

    # Restringe permissões em sistemas que suportam chmod.
    try:
        key_path.chmod(0o600)
    except OSError:
        pass

    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()

    print("Certificado criado com sucesso!")
    print("Certificado:", cert_path)
    print("Chave privada:", key_path)
    print("Fingerprint SHA-256:", fingerprint)


if __name__ == "__main__":
    generate_certificate()
