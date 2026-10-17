import http.server
import asyncio
import socket
import ssl
import subprocess
import threading
from pathlib import Path

import httpx
import pytest

from app.scanning.http_client import BoundedHTTPClient


class LoopbackResolver:
    def __init__(self, address: str) -> None:
        self.address = address

    async def resolve(self, hostname: str) -> tuple[str, ...]:
        return (self.address,)


@pytest.fixture(scope="module")
def tls_material(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    directory = tmp_path_factory.mktemp("tls-material")
    certificate = directory / "alpha.test.crt"
    private_key = directory / "alpha.test.key"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=alpha.test",
            "-addext",
            "subjectAltName=DNS:alpha.test",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
        ],
        check=True,
        capture_output=True,
    )
    return certificate, private_key


class ControlledTLSServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, context: ssl.SSLContext) -> None:
        self.context = context
        self.accepted_connections = 0
        super().__init__(address, handler)

    def get_request(self):
        raw_socket, address = super().get_request()
        self.accepted_connections += 1
        return self.context.wrap_socket(raw_socket, server_side=True), address


@pytest.fixture
def tls_server(tls_material: tuple[Path, Path]):
    certificate, private_key = tls_material
    sni_names: list[str | None] = []
    request_connections: list[socket.socket] = []

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, private_key)
    context.set_servername_callback(
        lambda _ssl_socket, server_name, _context: sni_names.append(server_name)
    )

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            request_connections.append(self.connection)
            body = b"alpha-origin"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args) -> None:
            pass

    server = ControlledTLSServer(("127.0.0.1", 0), Handler, context)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, sni_names, request_connections, certificate
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_distinct_https_origins_do_not_reuse_authenticated_connection(
    monkeypatch: pytest.MonkeyPatch,
    tls_server,
):
    server, sni_names, request_connections, certificate = tls_server

    # This is only a transport fixture escape hatch. Production destination
    # policy remains unchanged and still rejects loopback addresses.
    monkeypatch.setattr(
        "app.security.dns.ip_policy.validate_ip_addresses",
        lambda values: tuple(values),
    )

    client_context = ssl.create_default_context()
    client_context.load_verify_locations(cafile=str(certificate))

    port = server.server_port
    resolver = LoopbackResolver("127.0.0.1")

    async def exercise():
        async with BoundedHTTPClient.for_testing(
            resolver=resolver,
            transport_factory=lambda: httpx.AsyncHTTPTransport(
                verify=client_context,
                trust_env=False,
            ),
        ) as client:
            response = await client.get(f"https://alpha.test:{port}/")
            assert response.status_code == 200
            assert response.text == "alpha-origin"

            with pytest.raises(httpx.ConnectError):
                await client.get(f"https://beta.test:{port}/")

    asyncio.run(exercise())

    assert sni_names == ["alpha.test", "beta.test"]
    assert server.accepted_connections == 2
    assert len(request_connections) == 1
