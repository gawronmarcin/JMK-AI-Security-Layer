"""Control registry. Controls register themselves; the engine discovers them.

Usage in aicl/controls/<name>.py:

    @register_control
    class InjectionPatterns:
        id = "C-INJ-PAT"
        stages = (Stage.input, Stage.tool_result)
        priority = 20

        async def evaluate(self, ctx, cfg) -> Decision: ...
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import TypeVar

from aicl.models import Control, Stage

_CONTROLS: dict[str, Control] = {}

T = TypeVar("T")


def register_control(cls: type[T]) -> type[T]:
    """Class decorator: instantiates the control (no-arg constructor) and registers it by id."""
    instance = cls()
    if not isinstance(instance, Control):
        raise TypeError(
            f"{cls.__name__} does not implement the Control protocol (id, stages, priority, evaluate)"
        )
    if not instance.stages or not all(isinstance(s, Stage) for s in instance.stages):
        raise TypeError(f"{cls.__name__}.stages must be a non-empty tuple of Stage")
    existing = _CONTROLS.get(instance.id)
    if existing is not None and type(existing) is not cls:
        raise ValueError(
            f"duplicate control id {instance.id!r}: {type(existing).__name__} and {cls.__name__}"
        )
    _CONTROLS[instance.id] = instance
    return cls


def discover(package: str = "aicl.controls") -> None:
    """Import every module in the controls package so their decorators run."""
    pkg = importlib.import_module(package)
    for mod in pkgutil.walk_packages(pkg.__path__, prefix=f"{package}."):
        importlib.import_module(mod.name)


def get_control(control_id: str) -> Control | None:
    return _CONTROLS.get(control_id)


def all_controls() -> dict[str, Control]:
    return dict(_CONTROLS)


def unregister(control_id: str) -> None:
    """For tests registering throwaway controls."""
    _CONTROLS.pop(control_id, None)
