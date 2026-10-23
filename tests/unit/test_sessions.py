import pytest

from apisix.plugins.sessions import Session, SessionStore


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def store(clock):
    return SessionStore(clock=clock)


def session(clock, lifetime=3600, idle=600):
    return Session(expires_at=clock.now + lifetime, idle_timeout=idle)


def test_ids_are_random_and_long(store, clock):
    ids = {store.create(session(clock)) for _ in range(100)}

    assert len(ids) == 100
    assert all(len(i) >= 43 for i in ids)


def test_ids_are_not_stored_in_clear(store, clock):
    session_id = store.create(session(clock))

    assert session_id not in store._sessions


def test_get_and_delete(store, clock):
    s = session(clock)
    session_id = store.create(s)

    assert store.get(session_id) is s
    assert store.delete(session_id) is s
    assert store.get(session_id) is None
    assert store.get(None) is None
    assert store.get("unknown") is None


def test_idle_timeout(store, clock):
    session_id = store.create(session(clock, idle=600))

    clock.now += 599
    assert store.get(session_id) is not None
    # activity resets the idle timer
    clock.now += 599
    assert store.get(session_id) is not None
    clock.now += 600
    assert store.get(session_id) is None


def test_absolute_lifetime(store, clock):
    session_id = store.create(session(clock, lifetime=1000, idle=600))

    for _ in range(3):
        clock.now += 300
        assert store.get(session_id) is not None
    clock.now += 100
    assert store.get(session_id) is None


def test_expired_sessions_are_purged(store, clock):
    store.create(session(clock, lifetime=10))
    clock.now += 20

    store.create(session(clock))

    assert len(store) == 1
