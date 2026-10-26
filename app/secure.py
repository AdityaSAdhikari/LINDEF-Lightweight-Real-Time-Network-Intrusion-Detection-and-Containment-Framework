"""
Secure links between the LINDEF agent, desktop app, and phone app.

There is no certificate authority. Each listening side (the agent on the
defended server, and the desktop app for phones) creates its own key and
self-signed certificate on first run. The pairing code carries that
certificate's SHA-256 fingerprint, and the connecting side refuses any other
certificate. This is certificate pinning: it stops someone on the network
from impersonating either end, which a plain self-signed certificate would not.

Pairing codes look like:
    lindef://192.168.1.20:9443?key=SECRET&fp=SHA256HEX     (agent -> desktop)
    lindef://192.168.1.10:8766?pair=CODE&fp=SHA256HEX      (desktop -> phone)
"""

import datetime
import hashlib
import hmac
import http.client
import json
import os
import secrets
import socket
import ssl
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


class CertificateMismatch(Exception):
    """The other side presented a certificate other than the paired one."""


# -----------------------------------------------------------------------------
# Private files
# -----------------------------------------------------------------------------

def private_dir(path) -> Path:
    """Create a folder only this user can read."""
    path = Path(path).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def write_private(path: Path, data: bytes):
    """Write a file readable only by this user (keys, tokens, config)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return default


def write_json(path: Path, data):
    write_private(path, json.dumps(data, indent=2).encode())


def load_or_create_secret(path: Path) -> str:
    """Return the secret stored at path, creating it on first run."""
    if not path.exists():
        write_private(path, secrets.token_urlsafe(32).encode())
    return path.read_text().strip()


def hash_secret(secret: str) -> str:
    """Store tokens hashed, so a copied config file cannot be used to connect."""
    return hashlib.sha256(secret.encode()).hexdigest()


def secrets_match(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())

# -----------------------------------------------------------------------------
# Certificates
# -----------------------------------------------------------------------------

def load_or_create_identity(data_dir: Path) -> tuple[Path, Path, str]:
    """Return (cert path, key path, SHA-256 fingerprint), creating them on first run."""
    cert_path = data_dir / "cert.pem"
    key_path = data_dir / "key.pem"

    if not (cert_path.exists() and key_path.exists()):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"LINDEF {socket.gethostname()}")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))  # pinned, so expiry adds nothing but breakage
            .sign(key, hashes.SHA256())
        )
        write_private(key_path, key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        write_private(cert_path, cert.public_bytes(serialization.Encoding.PEM))

    der = ssl.PEM_cert_to_DER_cert(cert_path.read_text())
    return cert_path, key_path, hashlib.sha256(der).hexdigest()


def reset_identity(data_dir: Path):
    """Delete the certificate and key so new ones are made (forces re-pairing)."""
    for name in ("cert.pem", "key.pem"):
        (data_dir / name).unlink(missing_ok=True)

# -----------------------------------------------------------------------------
# Pairing codes
# -----------------------------------------------------------------------------

def make_pairing_code(host: str, port: int, fingerprint: str, **params) -> str:
    if ":" in host:
        host = f"[{host}]"  # IPv6
    return f"lindef://{host}:{port}?" + urlencode({**params, "fp": fingerprint})


def parse_pairing_code(code: str) -> dict:
    """Return {"host", "port", "fp", ...params}. Raises ValueError if malformed."""
    parts = urlsplit(str(code).strip())
    if parts.scheme != "lindef" or not parts.hostname or not parts.port:
        raise ValueError("That is not a LINDEF pairing code. It should start with lindef://")
    params = {k: v[0] for k, v in parse_qs(parts.query).items()}
    fingerprint = params.get("fp", "").lower()
    if len(fingerprint) != 64 or any(c not in "0123456789abcdef" for c in fingerprint):
        raise ValueError("The pairing code is missing its certificate fingerprint.")
    return {**params, "host": parts.hostname, "port": parts.port, "fp": fingerprint}


def lan_ip() -> str:
    """Best guess at this machine's network address (no packets are sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"

# -----------------------------------------------------------------------------
# HTTPS server and pinned client
# -----------------------------------------------------------------------------

class TLSServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that speaks TLS 1.2+.

    The handshake runs on each connection's own thread, so one slow or
    malicious client cannot stall the server.
    """

    def __init__(self, address, handler, cert_path: Path, key_path: Path):
        super().__init__(address, handler)
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.minimum_version = ssl.TLSVersion.TLSv1_2
        self.tls.load_cert_chain(cert_path, key_path)

    def finish_request(self, request, client_address):
        request.settimeout(15)
        try:
            tls_request = self.tls.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return  # failed handshake: drop the connection quietly
        try:
            super().finish_request(tls_request, client_address)
        except (ConnectionError, TimeoutError, ssl.SSLError):
            pass  # client hung up (for example after refusing our certificate): nothing to report
        finally:
            tls_request.close()


def pinned_request(host: str, port: int, fingerprint: str, method: str, path: str,
                   body: bytes | None = None, headers: dict | None = None, timeout: float = 15):
    """HTTPS request that only talks to the certificate with this fingerprint.

    The certificate is checked before any header (and so any secret) is sent.
    Returns (status, body bytes, headers dict). Raises CertificateMismatch or OSError.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # the pin below replaces CA verification
    conn = http.client.HTTPSConnection(host, port, context=context, timeout=timeout)
    try:
        conn.connect()
        der = conn.sock.getpeercert(binary_form=True)
        if not secrets_match(hashlib.sha256(der).hexdigest(), fingerprint.lower()):
            raise CertificateMismatch(f"{host}:{port} presented a different certificate than the one it was paired with.")
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        return response.status, response.read(), dict(response.getheaders())
    finally:
        conn.close()
