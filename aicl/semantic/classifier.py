"""Fast prompt-injection classifier backends for C-INJ-BASTION (tier 2 of the injection cascade).

Cascade: C-INJ-PAT (regex/feed, <1 ms) -> C-INJ-BASTION (small classifier, ~5-20 ms) -> C-INJ-SEM
(Ollama LLM judge, slow, only for the classifier's grey zone and untrusted content).

Backends, chosen by `controls.injection_bastion.params.backend` (hot reload switches them):
- `none`    control skipped (default: tests and machines without the model)
- `bastion` in-process Bastion SDK (`pip install bastion-prompt-protection`, ONNX on CPU).
            AGPL-3.0: kept an optional dependency so the gateway itself does not link it.
- `remote`  HTTP service with Bastion's microservice contract:
            POST {url}/protect {"prompt": "..."} -> {"risk": 0..1, "label": "attack"|"benign"}.
            Fits the Bastion Docker image or any sidecar wrapping another model (e.g. ProtectAI).
"""

from __future__ import annotations

import asyncio
import logging
import math
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

log = logging.getLogger(__name__)

BACKENDS = ("none", "bastion", "remote")


class ClassifierError(Exception):
    """Backend failure; the engine applies the control's `on_error`."""


@dataclass(frozen=True)
class ClassifierSettings:
    backend: str = "none"
    url: str = ""  # remote backend: resolved from the env var named by `url_env`
    model: str = ""  # bastion backend: HF repo id; empty = the SDK's free English model
    timeout_ms: int = 300
    max_chars: int = 2000  # per chunk, ~512 tokens (DeBERTa limit)
    max_chunks: int = 4  # per text; longer texts keep the head chunks and the tail chunk
    max_texts: int = 16  # cap on classifier calls per request (latency guard)

    @classmethod
    def from_params(cls, params: Mapping[str, Any] | None, env: Mapping[str, str]) -> ClassifierSettings:
        p = params or {}
        backend = str(p.get("backend") or "none").strip().lower()
        if backend not in BACKENDS:
            log.warning("C-INJ-BASTION: unknown backend %r, using 'none'", backend)
            backend = "none"
        return cls(
            backend=backend,
            url=(env.get(str(p.get("url_env") or "AICL_BASTION_URL")) or "").strip(),
            model=str(p.get("model") or ""),
            timeout_ms=int(p.get("timeout_ms", 300)),
            max_chars=max(200, int(p.get("max_chars", 2000))),
            max_chunks=max(1, int(p.get("max_chunks", 4))),
            max_texts=max(1, int(p.get("max_texts", 16))),
        )


@dataclass(frozen=True)
class Score:
    risk: float  # 0..1, calibrated probability of an attack
    label: str = ""
    latency_ms: float = 0.0


class Classifier(Protocol):
    name: str

    @property
    def ready(self) -> bool: ...

    @property
    def error(self) -> str | None: ...

    def start(self) -> None:
        """Begin loading in the background (no-op when there is nothing to load)."""

    async def classify(self, text: str) -> Score: ...

    async def aclose(self) -> None: ...


def _clamp(v: Any) -> float:
    try:
        f = float(v)
    except (TypeError, ValueError) as exc:
        raise ClassifierError("classifier returned no usable risk") from exc
    if math.isnan(f):
        raise ClassifierError("classifier returned NaN")
    return min(1.0, max(0.0, f))


class BastionSDK:
    """Bastion Guard in-process. The model loads in a worker thread (first run downloads it to the
    Hugging Face cache), so neither startup nor requests block on it; until then the control skips."""

    name = "bastion"

    def __init__(self, model: str = "") -> None:
        self._model = model
        self._guard: Any = None
        self._error: str | None = None
        self._loading: asyncio.Task[None] | None = None

    @property
    def ready(self) -> bool:
        return self._guard is not None

    @property
    def error(self) -> str | None:
        return self._error

    def _load(self) -> Any:
        import bastion_prompt_protection as bpp  # optional dependency (AGPL-3.0)

        if self._model:
            return bpp.Guard(bpp.GuardConfig(model=self._model))
        return bpp.Guard()

    async def _load_async(self) -> None:
        t0 = time.perf_counter()
        try:
            self._guard = await asyncio.to_thread(self._load)
            self._error = None
            log.info("Bastion classifier loaded in %.0f ms", (time.perf_counter() - t0) * 1000)
        except ImportError:
            self._error = "bastion-prompt-protection not installed (pip install bastion-prompt-protection)"
        except Exception as exc:  # noqa: BLE001 - download/ONNX errors: report, keep the gateway running
            self._error = f"Bastion load failed: {type(exc).__name__}: {exc}"
        if self._error:
            log.warning("C-INJ-BASTION: %s", self._error)

    def start(self) -> None:
        if self._guard is not None or (self._loading is not None and not self._loading.done()):
            return
        if self._error and self._loading is not None:
            return  # failed once; a policy change (new backend instance) retries
        try:
            self._loading = asyncio.get_running_loop().create_task(self._load_async(), name="bastion-load")
        except RuntimeError:  # no running loop (sync caller): the first evaluate() starts it
            pass

    async def classify(self, text: str) -> Score:
        if self._guard is None:
            raise ClassifierError("Bastion model not loaded")
        t0 = time.perf_counter()
        try:
            res = await asyncio.to_thread(self._guard.protect, text)
        except Exception as exc:
            raise ClassifierError(f"Bastion inference failed: {type(exc).__name__}") from exc
        return Score(_clamp(getattr(res, "risk", None)), str(getattr(res, "label", "")),
                     (time.perf_counter() - t0) * 1000)

    async def aclose(self) -> None:
        if self._loading is not None and not self._loading.done():
            self._loading.cancel()


class RemoteClassifier:
    """HTTP backend (Bastion Docker image or a compatible sidecar). One pooled client per instance."""

    name = "remote"

    def __init__(self, url: str, timeout_ms: int = 300, client: httpx.AsyncClient | None = None) -> None:
        self._url = url if urlsplit(url).path not in ("", "/") else url.rstrip("/") + "/protect"
        self._timeout = timeout_ms / 1000.0
        self._client = client or httpx.AsyncClient()
        self._error = None if url else "remote backend needs a URL (env var from params.url_env)"

    @property
    def ready(self) -> bool:
        return self._error is None

    @property
    def error(self) -> str | None:
        return self._error

    def start(self) -> None:
        return None

    async def classify(self, text: str) -> Score:
        t0 = time.perf_counter()
        try:
            resp = await self._client.post(self._url, json={"prompt": text}, timeout=self._timeout)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ClassifierError(f"remote classifier failed: {type(exc).__name__}") from exc
        if not isinstance(data, dict):
            raise ClassifierError("remote classifier returned no JSON object")
        risk = next((data[k] for k in ("risk", "score", "probability") if k in data), None)
        return Score(_clamp(risk), str(data.get("label", "")), (time.perf_counter() - t0) * 1000)

    async def aclose(self) -> None:
        await self._client.aclose()


def build(settings: ClassifierSettings) -> Classifier | None:
    if settings.backend == "bastion":
        return BastionSDK(settings.model)
    if settings.backend == "remote":
        return RemoteClassifier(settings.url, settings.timeout_ms)
    return None


def chunks(text: str, max_chars: int, max_chunks: int, overlap: int = 200) -> list[str]:
    """Split long text into overlapping windows that fit the model. Past `max_chunks`, keep the
    head windows and the last one: injections often sit at the end of long documents."""
    if len(text) <= max_chars:
        return [text]
    step = max(1, max_chars - overlap)
    windows = [text[i:i + max_chars] for i in range(0, len(text) - overlap, step)]
    if len(windows) > max_chunks:
        windows = windows[: max_chunks - 1] + [text[-max_chars:]]
    return windows
