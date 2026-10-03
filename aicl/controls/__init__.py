"""Controls package: one module per control family, auto-discovered by `aicl.registry.discover()`.

Register controls with `aicl.registry.register_control`. It is re-exported here only for
modules that import it from this package.
"""

from aicl.registry import register_control

__all__ = ["register_control"]
