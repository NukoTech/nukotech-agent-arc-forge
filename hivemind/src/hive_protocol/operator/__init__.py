"""Read-only operator projections and single-root lifecycle controls."""

from .projection import OperatorProjection
from .lifecycle import safe_uninstall

__all__ = ["OperatorProjection", "safe_uninstall"]
