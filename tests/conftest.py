"""Shared fixtures.

Every fixture is parameterised over all available group backends, so the whole
suite runs twice: once on Ristretto255 via libsodium, once on NIST P-256 via
OpenSSL. Two unrelated curves in two unrelated libraries must agree on every
result and every operation count; a divergence would indicate a bug in one of
them rather than a property of the scheme.
"""

import pytest

from cbas.backend import BACKENDS, CountingBackend

BACKEND_IDS = sorted(BACKENDS)


@pytest.fixture(params=BACKEND_IDS, scope="session")
def raw_backend(request):
    """An uninstrumented backend.

    Session-scoped because Hypothesis rejects function-scoped fixtures: they
    are not reset between generated examples, so a test could silently depend
    on state left by an earlier one. Backends are stateless, so sharing is safe.
    """
    return BACKENDS[request.param]()


@pytest.fixture(params=BACKEND_IDS)
def be(request):
    """A fresh counting backend per test, so counts never leak across tests."""
    return CountingBackend(BACKENDS[request.param]())


@pytest.fixture
def backend_name(request):
    return getattr(request, "param", None)
