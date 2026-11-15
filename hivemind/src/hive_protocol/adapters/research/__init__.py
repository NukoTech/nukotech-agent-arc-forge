"""Provider-neutral local research capture and citation adapter."""

from .bounded import BoundedResearchAdapter
from .notebook import LocalResearchNotebook

__all__ = ["BoundedResearchAdapter", "LocalResearchNotebook"]
