import pytest

from app.security.url_validation import URLValidationError, normalize_target_url


@pytest.mark.parametrize(
    ("raw_url", "normalized", "origin", "port", "path"),
    [
        ("http://example.com", "http://example.com/", "http://example.com", 80, "/"),
        (
            "HTTPS://Example.COM:443/path?q=1#ignored",
            "https://example.com/path?q=1",
            "https://example.com",
            443,
            "/path",
        ),
        (
            "https://[2001:4860:4860::8888]:8443/health",
            "https://[2001:4860:4860::8888]:8443/health",
            "https://[2001:4860:4860::8888]:8443",
            8443,
            "/health",
        ),
    ],
)
def test_normalizes_valid_http_urls(raw_url, normalized, origin, port, path):
    result = normalize_target_url(raw_url)

    assert result.url == normalized
    assert result.origin == origin
    assert result.port == port
    assert result.path == path


@pytest.mark.parametrize(
    "raw_url",
    [
        "",
        "example.com",
        "://example.com",
        "http://",
        "http://example.com:invalid",
        "http://[2001:db8::1",
        "http://example.com/path with spaces",
        "http://example.com/path\\with-slash",
    ],
)
def test_rejects_malformed_urls(raw_url):
    with pytest.raises(URLValidationError):
        normalize_target_url(raw_url)


@pytest.mark.parametrize("scheme", ["ftp", "file", "gopher", "ws", "wss"])
def test_rejects_unsupported_schemes(scheme):
    with pytest.raises(URLValidationError, match="Only http and https"):
        normalize_target_url(f"{scheme}://example.com/resource")


@pytest.mark.parametrize(
    "raw_url",
    [
        "https://user@example.com/",
        "https://:password@example.com/",
        "https://user:password@example.com/",
    ],
)
def test_rejects_embedded_credentials(raw_url):
    with pytest.raises(URLValidationError, match="credentials"):
        normalize_target_url(raw_url)


def test_ip_literal_is_preserved_in_normalized_url():
    result = normalize_target_url("http://127.0.0.1:8080/status")

    assert result.is_ip_literal is True
    assert result.hostname == "127.0.0.1"
    assert result.origin == "http://127.0.0.1:8080"
