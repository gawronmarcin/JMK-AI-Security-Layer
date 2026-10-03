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


def test_discover_imports_controls_package():
    registry.discover()  # empty package for now; must not fail
