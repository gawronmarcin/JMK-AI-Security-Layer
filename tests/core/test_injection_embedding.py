"""C-INJ-EMB: embedding similarity tier of the injection cascade.

A fake embedder returns fixed vectors, so these tests check the decision logic, the corpus index
(cache, hot reload, last-good) and the wiring, not model quality (scripts/check_semantic.py and
`make test-live` measure that with a real model).
"""

from __future__ import annotations

import importlib.util
import json
import math
from collections.abc import Sequence
from pathlib import Path

import httpx
import pytest
import yaml

from aicl import registry
from aicl.controls import injection_embedding, injection_semantic
from aicl.engine import controls_for_stage, run_stage
from aicl.integrations import detector_status, embedding_listener
from aicl.models import Action, Origin, RequestContext, Stage
from aicl.normalize import build_segment
from aicl.policy.loader import parse_policy
from aicl.semantic.embedding import (
    EmbeddingError,
    EmbeddingIndex,
    EmbeddingSettings,
    OllamaEmbedder,
    load_corpus,
)
from aicl.semantic.ollama import Verdict
from aicl.semantic.settings import SemanticSettings

REPO = Path(__file__).parents[2]
CORPUS = REPO / "feeds" / "injection_examples.yaml"


def unit(angle_deg: float, *, z: float = 0.0) -> list[float]:
    """Vector at `angle_deg` from the attack axis (x) towards the benign axis (y)."""
    a = math.radians(angle_deg)
    return [math.cos(a), math.sin(a), z]


def cos_to_angle(sim: float) -> float:
    return math.degrees(math.acos(sim))


# corpus: one attack example on the x axis, one benign example on the y axis
VECTORS = {
    "corpus attack example": [1.0, 0.0, 0.0],
    "corpus benign example": [0.0, 1.0, 0.0],
    "new attack example": [0.0, 0.0, 1.0],
    "q-attack": unit(cos_to_angle(0.95)),  # sim 0.95 to attack, ~0.31 to benign
    "q-grey": [0.0, 0.0, 0.0],  # set below
    "q-third-axis": [0.0, 0.0, 1.0],
    "q-clean": [0.0, 1.0, 0.0],
}
# q-grey: between sim_grey (0.59) and sim_block (0.64), closer to the attack than to the benign example
_g = 0.62
VECTORS["q-grey"] = [_g, 0.2, math.sqrt(1 - _g**2 - 0.04)]  # sim 0.62 attack, 0.20 benign
# similar enough to the attack to be escalated (0.70 >= sim_grey), but even closer to a benign
# hard negative (0.71) -> margin < margin_grey (0.03) -> clean
VECTORS["q-near-benign"] = [0.70, 0.71, math.sqrt(1 - 0.70**2 - 0.71**2)]
# sim 0.66, margin 0.05: strict blocks (margin_block 0.03), balanced only escalates (margin_block 0.07)
VECTORS["q-strict"] = [0.66, 0.61, math.sqrt(1 - 0.66**2 - 0.61**2)]


class FakeEmbedder:
    name = "fake"

    def __init__(self, *, fail: bool = False):
        self.calls: list[list[str]] = []
        self.fail = fail

    async def embed(self, texts: Sequence[str], *, timeout_s: float | None = None) -> list[list[float]]:
        self.calls.append(list(texts))
        if self.fail:
            raise EmbeddingError("backend down")
        out = []
        for t in texts:
            key = next((k for k in VECTORS if k in t), None)
            out.append(VECTORS[key] if key else [0.0, 0.0, 1.0])
        return out

    async def aclose(self) -> None:
        return None


class FakeJudge:
    def __init__(self, score: float):
        self.score, self.calls = score, 0

    async def judge(self, text: str, *, untrusted: bool = False) -> Verdict:
        self.calls += 1
        return Verdict(self.score >= 0.5, self.score, "fake judge")


def write_corpus(path: Path, extra: list[dict] | None = None, version: str = "t1") -> Path:
    examples = [
        {"id": "T-A-1", "label": "attack", "category": "override", "lang": "en", "text": "corpus attack example"},
        {"id": "T-B-1", "label": "benign", "category": "hard_negative", "lang": "en", "text": "corpus benign example"},
        *(extra or []),
    ]
    path.write_text(yaml.safe_dump({"corpus_version": version, "examples": examples}), encoding="utf-8")
    return path


def settings(tmp_path: Path, **kw) -> EmbeddingSettings:
    base = {"backend": "ollama", "url": "http://ollama", "corpus_path": write_corpus(tmp_path / "corpus.yaml"),
            "cache_dir": tmp_path / "cache", "refresh_seconds": 0.0, "top_k": 1}
    return EmbeddingSettings(**{**base, **kw})


async def ready_index(tmp_path: Path, embedder: FakeEmbedder | None = None, **kw) -> EmbeddingIndex:
    ix = EmbeddingIndex(settings(tmp_path, **kw), embedder or FakeEmbedder())
    await ix.build()
    assert ix.ready, ix.error
    injection_embedding.configure(ix.settings, ix)
    return ix


def _policy(**params):
    raw = yaml.safe_load((REPO / "policies" / "default.yaml").read_text(encoding="utf-8"))
    raw["controls"]["injection_embedding"]["params"].update(params)
    raw["controls"]["injection_bastion"]["params"]["backend"] = "none"  # isolate this tier
    return parse_policy(yaml.safe_dump(raw, sort_keys=False, allow_unicode=True))


@pytest.fixture
def policy():
    registry.discover()
    return _policy()


@pytest.fixture(autouse=True)
def _reset():
    yield
    injection_embedding.configure(EmbeddingSettings())
    injection_semantic.configure(SemanticSettings())


def ctx(text: str, profile: str = "balanced", origin: Origin = Origin.user) -> RequestContext:
    return RequestContext(
        request_id="r", session_id="s", endpoint="chat", identity="support-agent-01", role="support_agent",
        profile=profile, model="mock-commercial", policy_version="v1", stage=Stage.input,
        segments=[build_segment(0, text, origin)],
    )


def decision(res, cid="C-INJ-EMB"):
    return next(d for d in res.decisions if d.control_id == cid)


# --------------------------------------------------------------------------- cascade


def test_cascade_order(policy):
    cids = [cid for _, cid in controls_for_stage(policy, Stage.input)]
    assert cids.index("C-INJ-PAT") < cids.index("C-INJ-EMB") < cids.index("C-INJ-BASTION") < cids.index("C-INJ-SEM")


async def test_skipped_without_backend(policy):
    res = await run_stage(policy, ctx("q-attack"), Stage.input)
    d = decision(res)
    assert d.skipped and "not configured" in d.reason


async def test_close_to_attack_blocks_before_judge(policy, tmp_path):
    await ready_index(tmp_path)
    judge = FakeJudge(0.99)
    injection_semantic.configure(SemanticSettings(model="fake"), judge)
    res = await run_stage(policy, ctx("q-attack"), Stage.input)
    assert res.action == Action.block and res.blocking.control_id == "C-INJ-EMB"
    assert "T-A-1" in res.blocking.reason and "q-attack" not in res.blocking.reason  # example id, no user text
    assert judge.calls == 0


async def test_grey_zone_goes_to_judge(policy, tmp_path):
    await ready_index(tmp_path)
    judge = FakeJudge(0.95)
    injection_semantic.configure(SemanticSettings(model="fake"), judge)
    res = await run_stage(policy, ctx("q-grey"), Stage.input)
    assert decision(res).action == Action.allow and decision(res).risk == 0.5
    assert judge.calls == 1 and res.blocking.control_id == "C-INJ-SEM"


async def test_closer_to_benign_hard_negative_is_clean(policy, tmp_path):
    await ready_index(tmp_path)
    judge = FakeJudge(0.99)
    injection_semantic.configure(SemanticSettings(model="fake"), judge)
    res = await run_stage(policy, ctx("q-near-benign"), Stage.input)
    d = decision(res)
    assert d.action == Action.allow and d.risk == 0.0 and "clean" in d.reason
    assert judge.calls == 0


async def test_clean_text_does_not_wake_judge(policy, tmp_path):
    await ready_index(tmp_path)
    judge = FakeJudge(0.99)
    injection_semantic.configure(SemanticSettings(model="fake"), judge)
    res = await run_stage(policy, ctx("q-clean"), Stage.input)
    assert res.action == Action.allow and judge.calls == 0


@pytest.mark.parametrize("profile, expected", [("strict", Action.block), ("balanced", Action.allow)])
async def test_thresholds_follow_profile(policy, tmp_path, profile, expected):
    await ready_index(tmp_path)
    res = await run_stage(policy, ctx("q-strict", profile=profile), Stage.input)
    assert decision(res).action == expected


async def test_permissive_flags(policy, tmp_path):
    await ready_index(tmp_path)
    res = await run_stage(policy, ctx("q-attack", profile="permissive"), Stage.input)
    assert decision(res).action == Action.flag


async def test_attack_in_long_tool_result_is_found(policy, tmp_path):
    emb = FakeEmbedder()
    await ready_index(tmp_path, emb, max_chars=300, max_chunks=4)
    text = "Ordinary product description. " * 100 + " q-attack"
    c = ctx(text, origin=Origin.tool_result).model_copy(update={"stage": Stage.tool_result})
    res = await run_stage(policy, c, Stage.tool_result)
    assert decision(res).action == Action.block
    assert all(len(t) <= 300 for t in emb.calls[-1])


# --------------------------------------------------------------------------- index lifecycle


async def test_index_is_cached_on_disk(tmp_path):
    first = FakeEmbedder()
    await ready_index(tmp_path, first)
    assert len(first.calls) == 1  # corpus embedded once
    second = FakeEmbedder()
    ix = EmbeddingIndex(settings(tmp_path), second)
    await ix.build()
    assert ix.ready and second.calls == []  # served from the cache


async def test_corpus_edit_is_hot_reloaded(policy, tmp_path):
    emb = FakeEmbedder()
    ix = await ready_index(tmp_path, emb)
    res = await run_stage(policy, ctx("q-third-axis"), Stage.input)
    assert decision(res).action == Action.allow
    write_corpus(ix.settings.corpus_path, version="t2", extra=[
        {"id": "T-A-2", "label": "attack", "category": "exfil", "text": "new attack example"}])
    ix.maybe_refresh()  # what evaluate() does on each request
    await ix._task
    assert ix.corpus_version == "t2"
    res = await run_stage(policy, ctx("q-third-axis"), Stage.input)
    assert decision(res).action == Action.block and "T-A-2" in decision(res).reason


async def test_invalid_corpus_keeps_last_good(tmp_path):
    ix = await ready_index(tmp_path)
    ix.settings.corpus_path.write_text("corpus_version: x\nexamples: [{id: 1}]\n", encoding="utf-8")
    await ix.build()
    assert ix.ready and ix.corpus_version == "t1"
    assert "invalid corpus" in ix.error


async def test_backend_down_at_build_is_skipped_then_retried(policy, tmp_path):
    emb = FakeEmbedder(fail=True)
    ix = EmbeddingIndex(settings(tmp_path), emb)
    await ix.build()
    injection_embedding.configure(ix.settings, ix)
    res = await run_stage(policy, ctx("q-attack"), Stage.input)
    d = decision(res)
    assert d.skipped and "backend down" in d.reason
    emb.fail = False
    ix.maybe_refresh()
    await ix._task
    assert ix.ready


async def test_backend_failure_on_request_is_fail_open(policy, tmp_path):
    emb = FakeEmbedder()
    await ready_index(tmp_path, emb)
    emb.fail = True
    res = await run_stage(policy, ctx("q-attack"), Stage.input)
    assert res.action == Action.allow
    assert any(e.startswith("C-INJ-EMB") for e in res.errors)


# --------------------------------------------------------------------------- backend + wiring


async def test_ollama_embedder_contract():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"], seen["body"] = request.url.path, json.loads(request.content)
        return httpx.Response(200, json={"embeddings": [[0.1, 0.2], [0.3, 0.4]]})

    e = OllamaEmbedder("http://ollama:11434", "bge-m3", client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    assert await e.embed(["a", "b"]) == [[0.1, 0.2], [0.3, 0.4]]
    assert seen["path"] == "/api/embed"
    assert seen["body"]["model"] == "bge-m3" and seen["body"]["input"] == ["a", "b"]
    await e.aclose()


@pytest.mark.parametrize("response", [
    httpx.Response(500),
    httpx.Response(200, json={"embeddings": [[0.1]]}),  # one vector for two texts
    httpx.Response(200, json={"error": "model not found"}),
])
async def test_ollama_embedder_errors(response):
    e = OllamaEmbedder("http://ollama", "m", client=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: response)))
    with pytest.raises(EmbeddingError):
        await e.embed(["a", "b"])
    await e.aclose()


async def test_ollama_embedder_without_url():
    with pytest.raises(EmbeddingError, match="no embedding URL"):
        await OllamaEmbedder("", "m").embed(["a"])


def test_listener_builds_index_from_policy(tmp_path):
    listener = embedding_listener({"AICL_OLLAMA_URL": "http://ollama:11434"}, REPO)
    listener(_policy(backend="ollama", model="bge-m3"))
    ix = injection_embedding._STATE.index
    assert ix is not None and ix.settings.corpus_path == CORPUS.resolve()
    listener(_policy(backend="ollama", model="bge-m3", sim_block=0.9))  # thresholds: no rebuild
    assert injection_embedding._STATE.index is ix
    listener(_policy(backend="none"))
    assert detector_status()["embedding"]["backend"] == "none"


# --------------------------------------------------------------------------- the shipped corpus


def _probes() -> list[str]:
    spec = importlib.util.spec_from_file_location("check_semantic", REPO / "scripts" / "check_semantic.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    stack = yaml.safe_load((REPO / "scripts" / "stack_cases.yaml").read_text(encoding="utf-8"))["cases"]
    return [text for _, text, _ in mod.PROBES] + [c["text"] for c in stack]


def test_shipped_corpus_is_valid_and_multilingual():
    corpus, _ = load_corpus(CORPUS)
    attacks = [e for e in corpus.examples if e.label == "attack"]
    benign = [e for e in corpus.examples if e.label == "benign"]
    assert len(attacks) >= 30 and len(benign) >= 30
    assert {"en", "pl", "de", "es"} <= {e.lang for e in attacks}
    assert {"en", "pl"} <= {e.lang for e in benign if e.category == "hard_negative"}


def test_held_out_probes_are_not_in_the_corpus():
    """The probes in scripts/check_semantic.py and the cases in scripts/stack_cases.yaml measure
    generalization: copying them (or near-copies) into the corpus would make it meaningless."""
    corpus, _ = load_corpus(CORPUS)

    def norm(s: str) -> str:
        return " ".join("".join(c.lower() for c in s if c.isalnum() or c.isspace()).split())

    texts = [norm(e.text) for e in corpus.examples]
    for probe in _probes():
        p = norm(probe)
        assert not any(p in t or t in p for t in texts), probe
        words = set(p.split())
        for t in texts:  # no near-copies: at most 60% shared words
            shared = len(words & set(t.split())) / max(1, min(len(words), len(t.split())))
            assert shared <= 0.6, (probe, t)


async def test_top_k_averages_the_closest_examples(tmp_path):
    """One accidentally close attack example among distant ones counts less with top_k > 1."""
    extra = [{"id": "T-A-2", "label": "attack", "text": "new attack example"}]
    ix = EmbeddingIndex(settings(tmp_path, top_k=2), FakeEmbedder())
    write_corpus(ix.settings.corpus_path, extra=extra)
    await ix.build()
    (m,) = await ix.match(["q-attack"])  # 0.95 to T-A-1, 0.0 to T-A-2
    assert m.s_attack == pytest.approx(0.475, abs=0.01)
    assert m.attack_id == "T-A-1"  # still reports the closest example


async def test_leave_group_out_skips_own_group(tmp_path):
    extra = [{"id": "T-A-2", "label": "attack", "group": "g", "text": "q-attack"},
             {"id": "T-A-3", "label": "attack", "group": "g", "text": "q-attack again"}]
    ix = EmbeddingIndex(settings(tmp_path), FakeEmbedder())
    write_corpus(ix.settings.corpus_path, extra=extra)
    await ix.build()
    scored = {ex.id: m for ex, m in ix.leave_group_out()}
    # T-A-2's twin T-A-3 is in its group, so its closest attack is T-A-1 (0.95), not the twin (1.0)
    assert scored["T-A-2"].attack_id == "T-A-1"
    assert scored["T-A-2"].s_attack == pytest.approx(0.95, abs=0.01)


def test_calibrate_respects_false_positive_targets():
    from aicl.semantic.embedding import calibrate

    attacks = [(True, 0.80, 0.20)] * 6 + [(True, 0.66, 0.05)] * 4
    benign = [(False, 0.70, 0.10)] + [(False, 0.50, -0.20)] * 99
    t = calibrate(attacks + benign, max_block_fpr=0.0, max_escalation=0.05)
    assert t.block_fpr == 0.0 and t.escalation <= 0.05
    assert t.block_recall == pytest.approx(0.6)
    assert t.total_recall == pytest.approx(1.0)
