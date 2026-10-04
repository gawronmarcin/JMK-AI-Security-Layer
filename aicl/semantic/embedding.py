"""Embedding similarity for C-INJ-EMB: multilingual semantic match against an example corpus.

A text is embedded with a multilingual model served by Ollama (`/api/embed`, e.g. bge-m3) and
compared (cosine) with the attack and benign examples from `feeds/injection_examples.yaml`:

    s_attack = mean similarity to the `top_k` closest attack examples
    s_benign = the same for benign examples (hard negatives keep this honest)

Averaging the few closest examples (default 3) instead of taking the single closest one makes a
lone, accidentally similar example matter less: in leave-group-out calibration on the shipped
corpus it raised the share of attacks blocked at the same false-positive rate (52% -> 67%).

The control turns (s_attack, s_attack - s_benign) into block / escalate / clean with per-profile
thresholds. Meaning, not words, is compared, so paraphrases and other languages match.

The corpus index is built in the background (startup, policy change, corpus file change) and
cached on disk per (model, corpus hash), so restarts do not re-embed. Until it is ready the
control is skipped. numpy is used when installed; a pure-Python fallback keeps it optional.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import os
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

import httpx
import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

log = logging.getLogger(__name__)

_np: Any
try:  # optional fast path
    import numpy

    _np = numpy
except ImportError:  # pragma: no cover - depends on the environment
    _np = None


class EmbeddingError(Exception):
    """Embedding backend failure; the engine applies the control's `on_error`."""


# --------------------------------------------------------------------------- corpus file


class Example(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    label: Literal["attack", "benign"]
    text: str = Field(min_length=1)
    category: str = ""
    lang: str = ""
    group: str = ""  # translations / variants of one example share a group (honest calibration)


class CorpusFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    corpus_version: str = Field(min_length=1)
    examples: list[Example]

    @field_validator("corpus_version", mode="before")
    @classmethod
    def _str(cls, v: Any) -> Any:
        return str(v) if v is not None else v

    @field_validator("examples")
    @classmethod
    def _sane(cls, v: list[Example]) -> list[Example]:
        ids = [e.id for e in v]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise ValueError(f"duplicate example ids: {', '.join(dupes)}")
        if not any(e.label == "attack" for e in v) or not any(e.label == "benign" for e in v):
            raise ValueError("corpus needs at least one attack and one benign example")
        return v


def load_corpus(path: Path) -> tuple[CorpusFile, str]:
    """-> (parsed corpus, content hash). Raises ValueError with a readable message."""
    raw = path.read_bytes()
    try:
        corpus = CorpusFile.model_validate(yaml.safe_load(raw))
    except (yaml.YAMLError, ValidationError) as exc:
        raise ValueError(f"invalid corpus {path.name}: {exc}") from exc
    return corpus, hashlib.sha256(raw).hexdigest()[:16]


# --------------------------------------------------------------------------- settings


@dataclass(frozen=True)
class EmbeddingSettings:
    backend: str = "none"  # none | ollama
    url: str = ""
    model: str = "bge-m3"
    corpus_path: Path | None = None
    cache_dir: Path | None = None
    timeout_ms: int = 1500
    max_chars: int = 600  # short windows: an attack sentence must not be diluted by a long document
    max_chunks: int = 8
    max_texts: int = 16
    top_k: int = 3  # similarity = mean of the k closest examples of each label
    refresh_seconds: float = 5.0  # how often the corpus file is checked for changes

    @classmethod
    def from_params(cls, params: Mapping[str, Any] | None, env: Mapping[str, str], base_dir: Path) -> EmbeddingSettings:
        p = params or {}
        backend = str(p.get("backend") or "none").strip().lower()
        if backend not in ("none", "ollama"):
            log.warning("C-INJ-EMB: unknown backend %r, using 'none'", backend)
            backend = "none"

        def _path(v: Any) -> Path | None:
            if not v:
                return None
            path = Path(str(v))
            return path if path.is_absolute() else (base_dir / path).resolve()

        return cls(
            backend=backend,
            url=(env.get(str(p.get("url_env") or "AICL_OLLAMA_URL")) or "").strip().rstrip("/"),
            model=str(p.get("model") or "bge-m3"),
            corpus_path=_path(p.get("corpus") or "./feeds/injection_examples.yaml"),
            cache_dir=_path(p.get("cache_dir") or "./data/embeddings"),
            timeout_ms=int(p.get("timeout_ms", 1500)),
            max_chars=max(100, int(p.get("max_chars", 600))),
            max_chunks=max(1, int(p.get("max_chunks", 8))),
            max_texts=max(1, int(p.get("max_texts", 16))),
            top_k=max(1, int(p.get("top_k", 3))),
            refresh_seconds=float(p.get("refresh_seconds", 5.0)),
        )


# --------------------------------------------------------------------------- embedders


class Embedder(Protocol):
    name: str

    async def embed(self, texts: Sequence[str], *, timeout_s: float | None = None) -> list[list[float]]: ...

    async def aclose(self) -> None: ...


class OllamaEmbedder:
    """Ollama `/api/embed` (batch input). Vectors are L2-normalized by Ollama."""

    name = "ollama"

    def __init__(self, url: str, model: str, timeout_ms: int = 1500, client: httpx.AsyncClient | None = None):
        self._url = url.rstrip("/") + "/api/embed" if url else ""
        self._model = model
        self._timeout = timeout_ms / 1000.0
        self._client = client or httpx.AsyncClient()

    async def embed(self, texts: Sequence[str], *, timeout_s: float | None = None) -> list[list[float]]:
        if not self._url:
            raise EmbeddingError("no embedding URL (env var from params.url_env)")
        payload = {"model": self._model, "input": list(texts), "keep_alive": "30m", "truncate": True}
        try:
            resp = await self._client.post(self._url, json=payload, timeout=timeout_s or self._timeout)
            resp.raise_for_status()
            vecs = resp.json()["embeddings"]
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            raise EmbeddingError(f"embedding call failed: {type(exc).__name__}") from exc
        if not isinstance(vecs, list) or len(vecs) != len(texts):
            raise EmbeddingError("embedding service returned a wrong number of vectors")
        return [[float(x) for x in v] for v in vecs]

    async def aclose(self) -> None:
        await self._client.aclose()


# --------------------------------------------------------------------------- index


def _normalize(v: Sequence[float]) -> list[float]:
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]


@dataclass(frozen=True)
class Match:
    s_attack: float
    s_benign: float
    attack_id: str
    attack_category: str
    benign_id: str

    @property
    def margin(self) -> float:
        return self.s_attack - self.s_benign


@dataclass
class _Matrix:
    examples: list[Example]
    ids: list[str]
    categories: list[str]
    vectors: Any  # numpy array (n, d) or list[list[float]], rows L2-normalized

    def score(self, q: list[float], k: int = 1, exclude: Any = None) -> tuple[float, int]:
        """-> (mean similarity of the k closest rows, index of the closest row).
        `exclude`: boolean mask of rows to skip (leave-group-out calibration; numpy only)."""
        if _np is not None:
            sims = self.vectors @ _np.asarray(q, dtype=_np.float32)
            if exclude is not None:
                sims = _np.where(exclude, -2.0, sims)
            i = int(sims.argmax())
            kk = min(k, int((sims > -2.0).sum()) or 1)
            return float(_np.sort(sims)[-kk:].mean()), i
        sims_l = sorted(((sum(a * b for a, b in zip(row, q)), i) for i, row in enumerate(self.vectors)), reverse=True)
        top = sims_l[: max(1, k)]
        return sum(sv for sv, _ in top) / len(top), top[0][1]


def _matrix(rows: list[tuple[Example, list[float]]]) -> _Matrix:
    vecs = [_normalize(v) for _, v in rows]
    return _Matrix(
        examples=[e for e, _ in rows],
        ids=[e.id for e, _ in rows],
        categories=[e.category for e, _ in rows],
        vectors=_np.asarray(vecs, dtype=_np.float32) if _np is not None else vecs,
    )


@dataclass
class EmbeddingIndex:
    """Corpus embeddings + scoring. Rebuilt in the background; the old index serves meanwhile."""

    settings: EmbeddingSettings
    embedder: Embedder
    corpus_version: str | None = None
    error: str | None = None
    build_ms: float | None = None
    _attack: _Matrix | None = None
    _benign: _Matrix | None = None
    _sig: tuple[float, int] | None = None  # corpus file (mtime, size) of the built index
    _checked: float = 0.0
    _task: asyncio.Task[None] | None = field(default=None, repr=False)

    @property
    def ready(self) -> bool:
        return self._attack is not None and self._benign is not None

    @property
    def size(self) -> int:
        return (len(self._attack.ids) if self._attack else 0) + (len(self._benign.ids) if self._benign else 0)

    # ---- building

    def start(self) -> None:
        """Schedule a (re)build if none is running. No-op without a running event loop."""
        if self._task is not None and not self._task.done():
            return
        try:
            self._task = asyncio.get_running_loop().create_task(self.build(), name="emb-index-build")
        except RuntimeError:
            pass

    def maybe_refresh(self) -> None:
        """Cheap per-request check (at most every refresh_seconds): rebuild when the corpus changed."""
        now = time.monotonic()
        if now - self._checked < self.settings.refresh_seconds:
            return
        self._checked = now
        sig = self._file_sig()
        if sig is not None and sig != self._sig:
            self.start()

    def _file_sig(self) -> tuple[float, int] | None:
        try:
            st = self.settings.corpus_path.stat() if self.settings.corpus_path else None
        except OSError:
            return None
        return (st.st_mtime, st.st_size) if st else None

    def _cache_file(self, digest: str) -> Path | None:
        if self.settings.cache_dir is None:
            return None
        safe = "".join(c if c.isalnum() or c in "-._" else "_" for c in self.settings.model)
        return self.settings.cache_dir / f"{safe}-{digest}.json"

    async def build(self) -> None:
        s = self.settings
        sig = self._file_sig()
        t0 = time.perf_counter()
        try:
            if s.corpus_path is None:
                raise ValueError("no corpus path")
            corpus, digest = load_corpus(s.corpus_path)
            cache = self._cache_file(digest)
            vectors = self._read_cache(cache, corpus)
            if vectors is None:
                vectors = []
                texts = [e.text for e in corpus.examples]
                for i in range(0, len(texts), 32):  # batches: one slow call must not hit the timeout
                    vectors += await self.embedder.embed(texts[i:i + 32], timeout_s=max(30.0, s.timeout_ms / 1000))
                self._write_cache(cache, corpus, vectors)
        except (OSError, ValueError, EmbeddingError) as exc:
            # keep the last good index (like signature feeds); report why
            self.error = f"corpus index not built: {exc}"
            if isinstance(exc, ValueError):
                self._sig = sig  # broken file: wait for the next edit. Backend down: retried by maybe_refresh
            log.warning("C-INJ-EMB: %s", self.error)
            return
        pairs = list(zip(corpus.examples, vectors))
        self._attack = _matrix([p for p in pairs if p[0].label == "attack"])
        self._benign = _matrix([p for p in pairs if p[0].label == "benign"])
        self.corpus_version, self._sig, self.error = corpus.corpus_version, sig, None
        self.build_ms = (time.perf_counter() - t0) * 1000
        log.info("C-INJ-EMB: corpus %s indexed (%d examples, model %s) in %.0f ms",
                 corpus.corpus_version, len(pairs), s.model, self.build_ms)

    def _read_cache(self, cache: Path | None, corpus: CorpusFile) -> list[list[float]] | None:
        if cache is None or not cache.exists():
            return None
        try:
            data = json.loads(cache.read_text(encoding="utf-8"))
            if data.get("ids") == [e.id for e in corpus.examples]:
                return data["vectors"]
        except (OSError, ValueError, KeyError):
            pass
        return None

    def _write_cache(self, cache: Path | None, corpus: CorpusFile, vectors: list[list[float]]) -> None:
        if cache is None:
            return
        try:
            cache.parent.mkdir(parents=True, exist_ok=True)
            tmp = cache.with_suffix(".tmp")
            tmp.write_text(json.dumps({"model": self.settings.model, "corpus_version": corpus.corpus_version,
                                       "ids": [e.id for e in corpus.examples], "vectors": vectors}),
                           encoding="utf-8")
            os.replace(tmp, cache)
        except OSError as exc:  # cache is an optimization only
            log.warning("C-INJ-EMB: cannot write embedding cache: %s", exc)

    # ---- scoring

    async def match(self, texts: Sequence[str]) -> list[Match]:
        if not self.ready:
            raise EmbeddingError("corpus index not ready")
        vecs = await self.embedder.embed(texts)
        assert self._attack is not None and self._benign is not None
        k = self.settings.top_k
        out = []
        for v in vecs:
            q = _normalize(v)
            sa, ia = self._attack.score(q, k)
            sb, ib = self._benign.score(q, k)
            out.append(Match(sa, sb, self._attack.ids[ia], self._attack.categories[ia], self._benign.ids[ib]))
        return out

    def leave_group_out(self) -> list[tuple[Example, Match]]:
        """Score every corpus example against the rest of the corpus with its own group (itself,
        its translations and variants) left out: how an unseen text of that kind would score.
        Used to calibrate thresholds (scripts/check_semantic.py --calibrate). Needs numpy."""
        if not self.ready or _np is None:
            raise EmbeddingError("leave-group-out needs a ready index and numpy")
        assert self._attack is not None and self._benign is not None
        out: list[tuple[Example, Match]] = []
        for own in (self._attack, self._benign):
            for i, ex in enumerate(own.examples):
                q = own.vectors[i]
                picks = []
                for other in (self._attack, self._benign):
                    same = _np.asarray([o.id == ex.id or (bool(ex.group) and o.group == ex.group)
                                        for o in other.examples])
                    picks.append(other.score(q, self.settings.top_k, exclude=same))
                (sa, ia), (sb, ib) = picks
                out.append((ex, Match(sa, sb, self._attack.ids[ia], self._attack.categories[ia],
                                      self._benign.ids[ib])))
        return out

    async def aclose(self) -> None:
        if self._task is not None and not self._task.done():
            self._task.cancel()
        await self.embedder.aclose()


@dataclass(frozen=True)
class Thresholds:
    sim_block: float
    margin_block: float
    sim_grey: float
    margin_grey: float
    block_recall: float  # share of attacks blocked
    block_fpr: float  # share of benign texts blocked
    total_recall: float  # share of attacks blocked or escalated to the judge
    escalation: float  # share of benign texts blocked or escalated


def calibrate(points: Sequence[tuple[bool, float, float]], *, max_block_fpr: float = 0.01,
              max_escalation: float = 0.10) -> Thresholds:
    """Pick thresholds from (is_attack, similarity, margin) points (leave-group-out scores).

    Block: the highest attack recall with at most `max_block_fpr` of benign texts blocked.
    Judge: then the highest recall of "blocked or escalated" with at most `max_escalation` of
    benign texts reaching the judge or a block. Ties go to the higher (more conservative)
    thresholds, which leaves headroom for benign texts unlike the corpus."""
    att = [(sv, mv) for a, sv, mv in points if a]
    ben = [(sv, mv) for a, sv, mv in points if not a]
    if not att or not ben:
        raise ValueError("calibration needs attack and benign points")
    sims = [x / 100 for x in range(40, 96)]
    margins = [x / 100 for x in range(41)]

    def hit(sv: float, mv: float, sb: float, mb: float, sg: float = 9.0, mg: float = 9.0) -> bool:
        return (sv >= sb and mv >= mb) or (sv >= sg and mv >= mg)

    def share(pts: list[tuple[float, float]], *t: float) -> float:
        return sum(hit(sv, mv, *t) for sv, mv in pts) / len(pts)

    block = max(((share(att, sb, mb), sb + mb, sb, mb) for sb in sims for mb in margins
                 if share(ben, sb, mb) <= max_block_fpr), default=(0.0, 0.0, 0.95, 0.40))
    _, _, sb, mb = block
    grey = max(((share(att, sb, mb, sg, mg), sg + mg, sg, mg) for sg in sims for mg in margins
                if sg <= sb and share(ben, sb, mb, sg, mg) <= max_escalation), default=(0.0, 0.0, sb, mb))
    _, _, sg, mg = grey
    return Thresholds(sb, mb, sg, mg, share(att, sb, mb), share(ben, sb, mb),
                      share(att, sb, mb, sg, mg), share(ben, sb, mb, sg, mg))


def build_index(settings: EmbeddingSettings) -> EmbeddingIndex | None:
    if settings.backend != "ollama":
        return None
    return EmbeddingIndex(settings, OllamaEmbedder(settings.url, settings.model, settings.timeout_ms))
