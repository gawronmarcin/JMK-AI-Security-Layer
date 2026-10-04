from pathlib import Path

import pytest

from aicl.feeds import EMPTY, FeedError, FeedStore, parse_feed
from aicl.policy.schema import FeedRef

REPO = Path(__file__).parents[2]

FEED = """
feed_version: "v1"
signatures:
  - {id: SIG-PKL-001, set: artifact, kind: pickle_global, pattern: os.system, severity: critical}
  - {id: SIG-INJ-001, set: injection, kind: regex, pattern: "(?i)ignore (all )?previous instructions", severity: high}
  - {id: SIG-SC-001, set: supply_chain, kind: sha256, pattern: "%s", severity: high}
""" % ("ab" * 32)


def write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def events():
    return []


@pytest.fixture
def store(tmp_path, events):
    write(tmp_path / "attacks.yaml", FEED)
    s = FeedStore(base_dir=tmp_path, on_event=lambda detail, error: events.append((detail, error)))
    s.configure([FeedRef(name="historical", path="attacks.yaml")])
    return s


def test_repo_feed_is_valid():
    feed = parse_feed((REPO / "feeds" / "attacks.yaml").read_text(encoding="utf-8"))
    assert feed.signatures


def test_load_groups_by_set_and_compiles_regex(store, events):
    snap = store.current()
    assert snap.version == "v1" and snap.sources == {"historical": "v1"}
    assert [s.id for s in snap.for_set("artifact")] == ["SIG-PKL-001"]
    assert snap.for_set("exfil") == ()
    assert snap.regex("SIG-INJ-001").search("Please IGNORE previous instructions")
    assert snap.regex("SIG-PKL-001") is None
    assert events == [
        ({"feed": "historical", "status": "loaded", "feed_version": "v1", "signatures": 3}, None)
    ]


@pytest.mark.parametrize(
    "bad, expected",
    [
        (
            "feed_version: v2\nsignatures: [{id: X, set: nope, kind: regex, pattern: a, severity: low}]",
            "signatures.0.set",
        ),
        (
            "feed_version: v2\nsignatures: [{id: X, set: injection, kind: regex, pattern: '(', severity: low}]",
            "invalid regex",
        ),
        (
            "feed_version: v2\nsignatures: [{id: X, set: artifact, kind: sha256, pattern: abc, severity: low}]",
            "64 hex",
        ),
        (
            "feed_version: v2\nsignatures: [{id: X, set: injection, kind: regex, pattern: a, severity: low, extra: 1}]",
            "extra",
        ),
        (
            (
                "feed_version: v2\nsignatures:\n"
                "  - {id: X, set: injection, kind: regex, pattern: a, severity: low}\n"
                "  - {id: X, set: injection, kind: regex, pattern: b, severity: low}"
            ),
            "duplicate signature ids: X",
        ),
        ("signatures: []", "feed_version"),
        ("- just a list", "mapping"),
        ("feed_version: [unclosed", "YAML syntax"),
    ],
)
def test_invalid_feeds_are_rejected(bad, expected):
    with pytest.raises(FeedError) as exc:
        parse_feed(bad)
    assert expected in str(exc.value)


def test_unquoted_numeric_version_stays_text():
    assert parse_feed("feed_version: 2026.10\nsignatures: []").feed_version == "2026.1"


def test_invalid_reload_keeps_last_good(store, events, tmp_path):
    write(tmp_path / "attacks.yaml", "feed_version: v2\nsignatures: [{id: X}]")
    store.reload()
    assert store.current().version == "v1"
    detail, error = events[-1]
    assert (
        detail == {"feed": "historical", "status": "rejected", "kept_version": "v1"}
        and "signatures.0" in error
    )


def test_valid_reload_replaces(store, tmp_path):
    write(tmp_path / "attacks.yaml", "feed_version: v2\nsignatures: []")
    store.reload_path(tmp_path / "attacks.yaml")
    assert store.current().version == "v2" and store.current().signatures == ()


def test_missing_file_with_empty_policy(tmp_path, events):
    s = FeedStore(base_dir=tmp_path, on_event=lambda d, e: events.append((d, e)))
    s.configure([FeedRef(name="f", path="missing.yaml", on_unavailable="empty")])
    assert s.current() is EMPTY
    assert events[-1][1] == "cannot read feed: FileNotFoundError"


def test_empty_policy_drops_last_good_on_failure(store, tmp_path):
    store.configure([FeedRef(name="historical", path="attacks.yaml", on_unavailable="empty")])
    assert store.current().version == "v1"
    (tmp_path / "attacks.yaml").unlink()
    store.reload()
    assert store.current() is EMPTY


def test_unreachable_url_feed_is_rejected(tmp_path, events):
    s = FeedStore(base_dir=tmp_path, on_event=lambda d, e: events.append((d, e)))
    s.configure([FeedRef(name="remote", url="https://feeds.invalid/attacks.yaml")], force=True)  # RFC 2606
    assert s.current() is EMPTY and "cannot read feed" in events[-1][1]


def test_configure_only_reloads_changed_feeds(store, events, tmp_path):
    n = len(events)
    store.configure([FeedRef(name="historical", path="attacks.yaml")])  # unchanged
    assert len(events) == n
    store.configure([])  # feed removed from policy
    assert store.current() is EMPTY and store.paths() == []


def test_multiple_feeds_merge_and_first_wins(tmp_path):
    write(
        tmp_path / "a.yaml",
        'feed_version: "1"\nsignatures: [{id: S1, set: exfil, kind: url_pattern, pattern: a, severity: low}]',
    )
    write(
        tmp_path / "b.yaml",
        'feed_version: "7"\nsignatures: [{id: S1, set: exfil, kind: url_pattern, pattern: b, severity: high}]',
    )
    s = FeedStore(base_dir=tmp_path)
    s.configure([FeedRef(name="b", path="b.yaml"), FeedRef(name="a", path="a.yaml")])
    snap = s.current()
    assert snap.version == "a@1+b@7"
    assert [x.pattern for x in snap.for_set("exfil")] == ["a"]
    assert sorted(p.name for p in s.paths()) == ["a.yaml", "b.yaml"]


def test_broken_event_handler_does_not_break_loading(tmp_path):
    write(tmp_path / "f.yaml", FEED)
    s = FeedStore(base_dir=tmp_path, on_event=lambda d, e: 1 / 0)
    s.configure([FeedRef(name="f", path="f.yaml")])
    assert s.current().version == "v1"
