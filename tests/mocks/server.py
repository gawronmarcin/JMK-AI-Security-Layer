"""Uruchamia aplikację ASGI (mock) na prawdziwym porcie w wątku tła.

Dlaczego prawdziwy port, a nie ASGITransport?
Gateway łączy się z upstreamem przez własny, współdzielony `httpx.AsyncClient`
i URL z env (AICL_UPSTREAM_MOCK_URL itd.). Prawdziwy socket na 127.0.0.1 działa
z KAŻDĄ implementacją gatewaya bez wstrzykiwania transportu i bez zmian
kontraktu. Port 0 = system wybiera wolny port, więc równoległe workery
(pytest-xdist) nie kolidują.
"""

from __future__ import annotations

import threading
import time

import uvicorn


class BackgroundServer:
    def __init__(self, app, host: str = "127.0.0.1", port: int = 0) -> None:
        self.app = app
        config = uvicorn.Config(app, host=host, port=port, log_level="warning",
                                lifespan="off", access_log=False)
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.url = ""

    def start(self, timeout: float = 10.0) -> BackgroundServer:
        self.thread.start()
        deadline = time.monotonic() + timeout
        while not self.server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("mock server did not start")
            time.sleep(0.01)
        sock = self.server.servers[0].sockets[0]
        host, port = sock.getsockname()[:2]
        self.url = f"http://{host}:{port}"
        return self

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=5)

    def __enter__(self) -> BackgroundServer:
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
