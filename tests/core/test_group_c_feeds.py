"""Group C tests: Remote HTTP feed fetching, ETag caching, HMAC signature verification, and SSRF guard."""

from __future__ import annotations

import hashlib
import hmac
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from aicl.feeds import FeedStore
from aicl.policy.schema import FeedRef


class MockFeedServer(BaseHTTPRequestHandler):
    feed_content: bytes = b""
    etag: str = '"v1"'
    secret: str | None = None
    simulate_500: bool = False

    def do_GET(self):  # noqa: N802
        if self.simulate_500:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "simulated error")
            return

        client_etag = self.headers.get("if-none-match")
        if client_etag and client_etag.strip() == self.etag:
            self.send_response(HTTPStatus.NOT_MODIFIED)
            self.send_header("ETag", self.etag)
            self.end_headers()
            return

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/yaml")
        self.send_header("Content-Length", str(len(self.feed_content)))
        self.send_header("ETag", self.etag)
        if self.secret:
            sig = hmac.new(self.secret.encode("utf-8"), self.feed_content, hashlib.sha256).hexdigest()
            self.send_header("X-AICL-Feed-Signature", sig)
        self.end_headers()
        self.wfile.write(self.feed_content)

    def log_message(self, format, *args):
        pass


@pytest.fixture
def mock_feed_http_server():
    server = HTTPServer(("127.0.0.1", 0), MockFeedServer)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def test_remote_feed_fetch_and_etag(mock_feed_http_server):
    yaml_text = """
feed_version: "2026.1"
signatures:
  - id: SIG-TEST-001
    set: injection
    kind: regex
    pattern: "attack_payload"
    severity: high
"""
    MockFeedServer.feed_content = yaml_text.encode("utf-8")
    MockFeedServer.etag = '"etag-123"'
    MockFeedServer.simulate_500 = False
    MockFeedServer.secret = None

    store = FeedStore()
    ref = FeedRef(name="remote_feed", url=f"{mock_feed_http_server}/feed.yaml", refresh_seconds=10)
    store.configure([ref], force=True)

    snap = store.current()
    assert snap.version == "2026.1"
    assert len(snap.signatures) == 1
    assert snap.regex("SIG-TEST-001") is not None

    meta = store.feed_metadata()["remote_feed"]
    assert meta["status"] == "loaded"
    assert meta["etag"] == '"etag-123"'

    # Second load with ETag -> 304 Not Modified
    store.reload("remote_feed")
    meta2 = store.feed_metadata()["remote_feed"]
    assert meta2["status"] == "not_modified"
    assert store.current().version == "2026.1"


def test_remote_feed_hmac_verification(mock_feed_http_server):
    yaml_text = """
feed_version: "2026.2"
signatures:
  - id: SIG-HMAC-001
    set: artifact
    kind: pickle_global
    pattern: "os.system"
    severity: critical
"""
    MockFeedServer.feed_content = yaml_text.encode("utf-8")
    MockFeedServer.etag = '"etag-hmac"'
    MockFeedServer.simulate_500 = False
    MockFeedServer.secret = "my-secret-key"

    env = {"MY_FEED_KEY": "my-secret-key"}
    store = FeedStore(env=env)
    ref = FeedRef(
        name="hmac_feed",
        url=f"{mock_feed_http_server}/feed.yaml",
        refresh_seconds=10,
        signing_key_env="MY_FEED_KEY",
    )
    store.configure([ref], force=True)

    assert store.current().version == "2026.2"
    meta = store.feed_metadata()["hmac_feed"]
    assert meta["status"] == "loaded"

    # Now simulate wrong secret
    store_bad = FeedStore(env={"MY_FEED_KEY": "wrong-secret"})
    store_bad.configure([ref], force=True)
    meta_bad = store_bad.feed_metadata()["hmac_feed"]
    assert meta_bad["status"] == "rejected"
    assert "HMAC" in meta_bad["last_error"]


def test_remote_feed_ssrf_protection():
    store = FeedStore()
    ref = FeedRef(name="ssrf_feed", url="http://169.254.169.254/latest/meta-data")
    store.configure([ref], force=True)

    meta = store.feed_metadata()["ssrf_feed"]
    assert meta["status"] == "rejected"
    assert "insecure or untrusted" in meta["last_error"]


# --- hardening: url parsing, redirects, malformed responses -------------------------------------

@pytest.mark.parametrize("url", [
    "http://localhost:@evil.example/feed.yaml",       # userinfo trick: the host is evil.example
    "http://user:pw@127.0.0.1/feed.yaml",             # credentials in the url
    "http://127.0.0.1.evil.example/feed.yaml",        # prefix-match trick
    "ftp://127.0.0.1/feed.yaml",
])
def test_remote_feed_url_tricks_are_refused(url):
    store = FeedStore()
    store.configure([FeedRef(name="f", url=url)], force=True)
    meta = store.feed_metadata()["f"]
    assert meta["status"] == "rejected"


class _OddServer(BaseHTTPRequestHandler):
    mode = "redirect"

    def do_GET(self):  # noqa: N802
        if self.mode == "redirect":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data")
            self.end_headers()
        elif self.mode == "bad_length":
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Length", "abc")
            self.end_headers()
        elif self.mode == "not_utf8":
            body = b"feed_version: '1'\nsignatures: []\n\xff\xfe"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.mode == "chunked_huge":
            self.send_response(HTTPStatus.OK)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            chunk = b"#" * 65536
            for _ in range(100):  # 6.5 MB, no content-length
                self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")

    def log_message(self, format, *args):
        pass


@pytest.mark.parametrize("mode,error", [
    ("redirect", "HTTP 302"),
    ("bad_length", "cannot read feed"),        # httpx refuses the header itself: still a clean rejection
    ("not_utf8", "not UTF-8"),
    ("chunked_huge", "maximum size"),
])
def test_malformed_remote_feed_is_rejected_not_crashing(mode, error):
    _OddServer.mode = mode
    _OddServer.protocol_version = "HTTP/1.1" if mode == "chunked_huge" else "HTTP/1.0"
    server = HTTPServer(("127.0.0.1", 0), _OddServer)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        store = FeedStore()
        store.configure([FeedRef(name="f", url=f"http://127.0.0.1:{server.server_port}/feed.yaml")], force=True)
        meta = store.feed_metadata()["f"]
        assert meta["status"] == "rejected" and error in meta["last_error"]
    finally:
        server.shutdown()
        server.server_close()
