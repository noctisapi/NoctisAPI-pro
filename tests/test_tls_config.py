"""Tests for app.tls_config — configurable TLS trust store.

Unit tests verify that build_ssl_context() correctly loads CA material from
SSL_CERT_FILE, REQUESTS_CA_BUNDLE, and HP_EXTRA_CERTS_DIR.

Integration tests spin up a real HTTPS server whose certificate is signed by
a freshly generated test CA and verify that:
  - an httpx.Client configured with the custom CA can connect successfully
  - an httpx.Client using only the default trust store (no custom CA) is
    rejected with an SSL error
  - the HP_EXTRA_CERTS_DIR loading path also allows a successful connection
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import ssl
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.tls_config import build_ssl_context


# ---------------------------------------------------------------------------
# Environment override helper (same style as test_proxy_config.py)
# ---------------------------------------------------------------------------


class _EnvOverride:
    _TLS_VARS = (
        "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "HP_EXTRA_CERTS_DIR",
        "ssl_cert_file", "requests_ca_bundle",
    )

    def __init__(self, **kwargs: str | None):
        self._overrides = kwargs
        self._saved: dict[str, str | None] = {}

    def __enter__(self):
        self._saved = {k: os.environ.get(k) for k in self._TLS_VARS}
        for k in self._TLS_VARS:
            os.environ.pop(k, None)
        for k, v in self._overrides.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return self

    def __exit__(self, *_):
        for k in self._TLS_VARS:
            os.environ.pop(k, None)
        for k, v in self._saved.items():
            if v is not None:
                os.environ[k] = v


# ---------------------------------------------------------------------------
# PKI generation helpers
# ---------------------------------------------------------------------------


def _make_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a self-signed CA key and certificate with required extensions."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        # Self-signed: AKI points at its own key
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_server_cert(
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a server key + certificate signed by *ca_cert*."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        )
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        # AKI points at the CA's public key
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def _write_pem(obj, path: str) -> None:
    with open(path, "wb") as fh:
        if hasattr(obj, "public_bytes"):
            # Certificate
            fh.write(obj.public_bytes(serialization.Encoding.PEM))
        else:
            # Private key
            fh.write(
                obj.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )


# ---------------------------------------------------------------------------
# HTTPS test server
# ---------------------------------------------------------------------------


class _SilentOKHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):  # suppress output in test runs
        pass


def _start_https_server(certfile: str, keyfile: str) -> tuple[HTTPServer, int]:
    """Start a minimal TLS server on a random port; return (server, port)."""
    server = HTTPServer(("127.0.0.1", 0), _SilentOKHandler)
    srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv_ctx.load_cert_chain(certfile, keyfile)
    server.socket = srv_ctx.wrap_socket(server.socket, server_side=True)
    port: int = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, port


# ---------------------------------------------------------------------------
# Unit tests — build_ssl_context()
# ---------------------------------------------------------------------------


class TestBuildSslContextNoExtras(unittest.TestCase):
    """Without extra configuration build_ssl_context() returns a valid context."""

    def test_returns_ssl_context(self):
        with _EnvOverride():
            ctx = build_ssl_context()
        self.assertIsInstance(ctx, ssl.SSLContext)

    def test_verify_mode_is_required(self):
        """Certificate verification must never be disabled."""
        with _EnvOverride():
            ctx = build_ssl_context()
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_check_hostname_enabled(self):
        with _EnvOverride():
            ctx = build_ssl_context()
        self.assertTrue(ctx.check_hostname)


class TestBuildSslContextEnvBundle(unittest.TestCase):
    """CA bundle specified via SSL_CERT_FILE / REQUESTS_CA_BUNDLE is loaded."""

    def _write_ca_pem(self, path: str) -> None:
        _, ca_cert = _make_ca()
        _write_pem(ca_cert, path)

    def test_ssl_cert_file_is_loaded(self):
        with tempfile.TemporaryDirectory() as td:
            ca_path = os.path.join(td, "ca.pem")
            self._write_ca_pem(ca_path)
            with _EnvOverride(SSL_CERT_FILE=ca_path):
                ctx = build_ssl_context()
        self.assertIsInstance(ctx, ssl.SSLContext)

    def test_requests_ca_bundle_is_loaded(self):
        with tempfile.TemporaryDirectory() as td:
            ca_path = os.path.join(td, "ca.pem")
            self._write_ca_pem(ca_path)
            with _EnvOverride(REQUESTS_CA_BUNDLE=ca_path):
                ctx = build_ssl_context()
        self.assertIsInstance(ctx, ssl.SSLContext)

    def test_both_vars_same_file_no_error(self):
        """Deduplication: loading the same file twice must not raise."""
        with tempfile.TemporaryDirectory() as td:
            ca_path = os.path.join(td, "ca.pem")
            self._write_ca_pem(ca_path)
            with _EnvOverride(SSL_CERT_FILE=ca_path, REQUESTS_CA_BUNDLE=ca_path):
                ctx = build_ssl_context()
        self.assertIsInstance(ctx, ssl.SSLContext)

    def test_missing_file_raises(self):
        with _EnvOverride(SSL_CERT_FILE="/nonexistent/ca.pem"):
            with self.assertRaises(FileNotFoundError):
                build_ssl_context()


class TestBuildSslContextCertsDir(unittest.TestCase):
    """CA certificates in HP_EXTRA_CERTS_DIR are loaded."""

    def test_crt_file_in_dir_is_loaded(self):
        with tempfile.TemporaryDirectory() as td:
            _, ca_cert = _make_ca()
            _write_pem(ca_cert, os.path.join(td, "corp-root-ca.crt"))
            with _EnvOverride(HP_EXTRA_CERTS_DIR=td):
                ctx = build_ssl_context()
        self.assertIsInstance(ctx, ssl.SSLContext)

    def test_nonexistent_dir_is_silently_skipped(self):
        with _EnvOverride(HP_EXTRA_CERTS_DIR="/nonexistent/certs"):
            ctx = build_ssl_context()
        self.assertIsInstance(ctx, ssl.SSLContext)

    def test_non_cert_files_are_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            Path(os.path.join(td, "README.txt")).write_text("ignore me")
            with _EnvOverride(HP_EXTRA_CERTS_DIR=td):
                ctx = build_ssl_context()
        self.assertIsInstance(ctx, ssl.SSLContext)


# ---------------------------------------------------------------------------
# Integration tests — live HTTPS server with a custom CA
# ---------------------------------------------------------------------------


class TestCustomCaIntegration(unittest.TestCase):
    """Integration: verify TLS connections against a server with a custom CA."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        td = cls._tmp.name

        # Generate PKI material
        ca_key, ca_cert = _make_ca()
        srv_key, srv_cert = _make_server_cert(ca_key, ca_cert)

        cls._ca_cert_path = os.path.join(td, "ca.crt")
        srv_cert_path = os.path.join(td, "server.crt")
        srv_key_path = os.path.join(td, "server.key")

        _write_pem(ca_cert, cls._ca_cert_path)
        _write_pem(srv_cert, srv_cert_path)
        _write_pem(srv_key, srv_key_path)

        cls._server, cls._port = _start_https_server(srv_cert_path, srv_key_path)

    @classmethod
    def tearDownClass(cls):
        cls._server.shutdown()
        cls._tmp.cleanup()

    def _url(self) -> str:
        return f"https://127.0.0.1:{self._port}/"

    # --- SSL_CERT_FILE path -------------------------------------------------

    def test_connection_succeeds_via_ssl_cert_file(self):
        """httpx connects successfully when the custom CA is in SSL_CERT_FILE."""
        with _EnvOverride(SSL_CERT_FILE=self._ca_cert_path):
            ssl_ctx = build_ssl_context()
        with httpx.Client(verify=ssl_ctx) as client:
            resp = client.get(self._url())
        self.assertEqual(resp.status_code, 200)

    def test_connection_succeeds_via_requests_ca_bundle(self):
        """httpx connects successfully when the custom CA is in REQUESTS_CA_BUNDLE."""
        with _EnvOverride(REQUESTS_CA_BUNDLE=self._ca_cert_path):
            ssl_ctx = build_ssl_context()
        with httpx.Client(verify=ssl_ctx) as client:
            resp = client.get(self._url())
        self.assertEqual(resp.status_code, 200)

    # --- HP_EXTRA_CERTS_DIR path --------------------------------------------

    def test_connection_succeeds_via_extra_certs_dir(self):
        """httpx connects successfully when CA is in HP_EXTRA_CERTS_DIR."""
        with tempfile.TemporaryDirectory() as certs_dir:
            import shutil
            shutil.copy(self._ca_cert_path, os.path.join(certs_dir, "corp-root-ca.crt"))
            with _EnvOverride(HP_EXTRA_CERTS_DIR=certs_dir):
                ssl_ctx = build_ssl_context()
        with httpx.Client(verify=ssl_ctx) as client:
            resp = client.get(self._url())
        self.assertEqual(resp.status_code, 200)

    # --- Failure path -------------------------------------------------------

    def test_connection_fails_without_custom_ca(self):
        """An SSL error is raised (not swallowed) when the CA is not trusted."""
        # Build a context without the test CA — system CAs won't include it.
        untrusted_ctx = ssl.create_default_context()
        # httpx wraps the ssl error but still raises ConnectError / similar
        with self.assertRaises(Exception) as cm:
            with httpx.Client(verify=untrusted_ctx) as client:
                client.get(self._url())
        exc = cm.exception
        # Verify the error is TLS-related, not a connection-refused or timeout.
        exc_chain = str(exc).lower() + " " + repr(exc).lower()
        tls_keywords = ("ssl", "certificate", "verify", "tls", "cert")
        self.assertTrue(
            any(kw in exc_chain for kw in tls_keywords),
            f"Expected an SSL/TLS error, got: {exc!r}",
        )

    def test_tls_error_is_not_swallowed(self):
        """Requirement: verification failures must remain explicit (no fallback)."""
        untrusted_ctx = ssl.create_default_context()
        raised = False
        try:
            with httpx.Client(verify=untrusted_ctx) as client:
                client.get(self._url())
        except Exception:
            raised = True
        self.assertTrue(raised, "Expected an exception for untrusted CA but none was raised")


if __name__ == "__main__":
    unittest.main()
