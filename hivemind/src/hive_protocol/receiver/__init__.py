"""Bounded receiver-matrix primitives for the existing fleet communication seam."""

from .matrix import (
    ACTIVE_MAILBOX_NAMES,
    LEGACY_ROUTE_NAMES,
    ReceiverMatrix,
    RuntimeAuthorityBinding,
    SurfaceEnrollment,
    default_enrollments,
)
from .containment import GovernedRoot, validate_identifier
from .transport import (
    DiscoveredWork,
    ExistingTransportAdapter,
    FileRouteDiscovery,
    GitHubAssignmentDiscovery,
    MachineAppIdentity,
    SingleWriterGitTransport,
)

__all__ = [
    "ACTIVE_MAILBOX_NAMES",
    "LEGACY_ROUTE_NAMES",
    "ReceiverMatrix",
    "RuntimeAuthorityBinding",
    "SurfaceEnrollment",
    "default_enrollments",
    "GovernedRoot",
    "validate_identifier",
    "DiscoveredWork",
    "ExistingTransportAdapter",
    "FileRouteDiscovery",
    "GitHubAssignmentDiscovery",
    "MachineAppIdentity",
    "SingleWriterGitTransport",
]
