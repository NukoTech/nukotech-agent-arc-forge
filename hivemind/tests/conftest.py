"""Shared fixtures. Tests use a fixture identity; the checked-in one is bound to the public repo."""

from __future__ import annotations

import pytest

from hive_protocol.release_identity import bound_release_repository

BOUND_RELEASE_REPOSITORY = "example-org/example-repo"


@pytest.fixture
def bound_release_repository_value() -> str:
    return BOUND_RELEASE_REPOSITORY


@pytest.fixture(autouse=True)
def bind_default_release_identity(request, bound_release_repository_value):
    """Inject a bound fixture identity so existing turn/release tests can run.

    Tests marked release_identity_unbound see the checked-in placeholder instead.
    """

    if request.node.get_closest_marker("release_identity_unbound"):
        yield None
        return
    with bound_release_repository(bound_release_repository_value):
        yield bound_release_repository_value


def pytest_configure(config) -> None:
    config.addinivalue_line(
        "markers",
        "release_identity_unbound: use the checked-in placeholder identity",
    )
