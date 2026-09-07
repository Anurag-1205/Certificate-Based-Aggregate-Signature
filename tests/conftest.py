import pytest

from cbas.backend import CountingBackend, SodiumBackend


@pytest.fixture(scope="session")
def raw_backend():
    return SodiumBackend()


@pytest.fixture
def be():
    """A fresh counting backend per test, so op counts never leak across tests."""
    return CountingBackend(SodiumBackend())
