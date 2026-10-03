import pytest

from aicl import registry
from aicl.models import Action, Decision, Stage


def test_register_and_lookup():
    @registry.register_control
    class Dummy:
        id = "C-TEST-DUMMY"
        stages = (Stage.input,)
        priority = 50

        async def evaluate(self, ctx, cfg):
            return Decision(control_id=self.id, threat_ids=[], action=Action.allow)

    try:
        assert isinstance(registry.get_control("C-TEST-DUMMY"), Dummy)
        assert "C-TEST-DUMMY" in registry.all_controls()
    finally:
        registry.unregister("C-TEST-DUMMY")


def test_rejects_non_controls_and_duplicates():
    with pytest.raises(TypeError):

        @registry.register_control
        class NoEvaluate:
            id = "C-TEST-BAD"
            stages = (Stage.input,)
            priority = 1

    @registry.register_control
    class First:
        id = "C-TEST-DUP"
        stages = (Stage.input,)
        priority = 1

        async def evaluate(self, ctx, cfg): ...

    try:
        with pytest.raises(ValueError, match="duplicate"):

            @registry.register_control
            class Second:
                id = "C-TEST-DUP"
                stages = (Stage.output,)
                priority = 1

                async def evaluate(self, ctx, cfg): ...
    finally:
        registry.unregister("C-TEST-DUP")


def test_every_control_class_in_package_is_registered():
    """Catches controls decorated with something other than the real register_control."""
    import importlib
    import inspect
    import pkgutil

    import aicl.controls

    registry.discover()
    found = []
    for mod in pkgutil.walk_packages(aicl.controls.__path__, prefix="aicl.controls."):
        module = importlib.import_module(mod.name)
        for _, cls in inspect.getmembers(module, inspect.isclass):
            cid = getattr(cls, "id", None)
            if cls.__module__ == mod.name and isinstance(cid, str) and hasattr(cls, "evaluate"):
                found.append(cid)
                assert isinstance(registry.get_control(cid), cls), f"{cls.__name__} ({cid}) is not registered"
    assert found, "no controls found in aicl.controls"
