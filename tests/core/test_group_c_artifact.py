"""Group C tests: Glued/concatenated pickles, dangerous globals detection across STOP, and non-blocking evaluate."""

from __future__ import annotations

import pickle

import pytest

from aicl.controls.artifact import ArtifactScanControl, Scan, scan_pickle
from aicl.models import Action, Origin, RequestContext, Segment, Stage


def test_glued_pickles_dangerous_globals():
    # Innocent pickle + malicious pickle
    p1 = pickle.dumps("innocent string payload")
    # Malicious pickle calling os.system
    p2 = pickle.dumps(__import__("os").system)
    combined = p1 + p2

    scan = Scan(
        dangerous_feed={},
        reject_unparseable=True,
        max_entries=100,
        max_unpacked=100000,
    )
    scan_pickle(combined, scan)

    blocking = [f for f in scan.findings if f.level == "block"]
    assert len(blocking) > 0
    assert any("dangerous_global" in f.code for f in blocking)
    # Checks that os or nt (Windows) was blocked
    assert any("system" in f.detail for f in blocking)


def test_pickle_with_trailing_unparseable_data():
    p1 = pickle.dumps({"key": "value"})
    combined = p1 + b"THIS_IS_CORRUPTED_TRAILING_GARBAGE"

    scan = Scan(
        dangerous_feed={},
        reject_unparseable=True,
        max_entries=100,
        max_unpacked=100000,
    )
    scan_pickle(combined, scan)

    trailing = [f for f in scan.findings if f.code == "trailing_data"]
    assert len(trailing) == 1
    assert trailing[0].level == "warn"


@pytest.mark.asyncio
async def test_artifact_control_evaluate_non_blocking():
    p1 = pickle.dumps("innocent data")
    p2 = pickle.dumps(__import__("os").system)
    combined = p1 + p2

    ctrl = ArtifactScanControl()
    ctx = RequestContext(
        request_id="req_art",
        session_id="s1",
        endpoint="artifact_scan",
        stage=Stage.artifact,
        identity="user1",
        role="agent",
        profile="strict",
        model=None,
        policy_version="1",
        segments=[Segment(idx=0, text="model.pkl", norm="model.pkl", origin=Origin.artifact)],
        artifact=combined,
    )

    cfg = {"action": "block", "threat_ids": ["TH-14"]}
    dec = await ctrl.evaluate(ctx, cfg)

    assert dec.action == Action.block
    assert dec.severity == "critical"
    assert "unsafe artifact" in dec.reason
