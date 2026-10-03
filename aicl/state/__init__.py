from aicl.state.base import SessionState, StateStore, ToolCallRecord, UsageCounters, window_bucket
from aicl.state.memory import InMemoryStore

_current_store: StateStore = InMemoryStore()


def get_store() -> StateStore:
    """Return the process-wide active StateStore (defaults to an InMemoryStore)."""
    return _current_store


def set_store(store: StateStore) -> None:
    """Set the process-wide active StateStore (e.g. at app startup or in tests)."""
    global _current_store
    _current_store = store


__all__ = [
    "InMemoryStore",
    "SessionState",
    "StateStore",
    "ToolCallRecord",
    "UsageCounters",
    "get_store",
    "set_store",
    "window_bucket",
]
