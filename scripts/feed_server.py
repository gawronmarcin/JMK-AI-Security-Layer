"""Minimal standalone feed server for remote signature feeds (Group C, C3).

Serves a YAML feed file (default: feeds/attacks.yaml) over HTTP with:
- ETag generation & If-None-Match -> 304 Not Modified
- Optional HMAC-SHA256 signing via X-AICL-Feed-Signature header

Usage:
    python scripts/feed_server.py --port 8088 --feed feeds/attacks.yaml
    python scripts/feed_server.py --port 8088 --secret-key mysecret
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


class FeedHandler(BaseHTTPRequestHandler):
    feed_path: Path
    secret: str | None = None

    def do_GET(self) -> None:  # noqa: N802
        if not self.feed_path.exists():
            self.send_error(HTTPStatus.NOT_FOUND, f"Feed file {self.feed_path} not found")
            return

        try:
            content = self.feed_path.read_bytes()
        except OSError as exc:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"Error reading feed: {exc}")
            return

        digest = hashlib.sha256(content).hexdigest()
        etag = f'"{digest}"'

        client_etag = self.headers.get("if-none-match")
        if client_etag and client_etag.strip() == etag:
            self.send_response(HTTPStatus.NOT_MODIFIED)
            self.send_header("ETag", etag)
            self.end_headers()
            return

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/yaml; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("ETag", etag)

        if self.secret:
            sig = hmac.new(self.secret.encode("utf-8"), content, hashlib.sha256).hexdigest()
            self.send_header("X-AICL-Feed-Signature", sig)

        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format: str, *args: object) -> None:
        pass  # Quiet down logs


def run(host: str = "127.0.0.1", port: int = 8088, feed: str = "feeds/attacks.yaml", secret: str | None = None) -> None:
    path = Path(feed).resolve()
    FeedHandler.feed_path = path
    FeedHandler.secret = secret

    server = HTTPServer((host, port), FeedHandler)
    print(f"Feed server listening on http://{host}:{port}/ serving {path}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Serve AICL signature feed")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8088, help="Port to listen on (default 8088)")
    parser.add_argument("--feed", default="feeds/attacks.yaml", help="Path to feed YAML file")
    parser.add_argument("--secret-key", default=os.environ.get("FEED_SIGNING_KEY"), help="Optional HMAC secret key")
    args = parser.parse_args()

    run(host=args.host, port=args.port, feed=args.feed, secret=args.secret_key)
