"""
Server-side session store of the BFF.

The browser only ever holds an opaque, random session id in a cookie; tokens
stay in this store [BBA 6.1.2.3 server-side sessions]. Because nothing but the
id leaves the gateway, the cookie needs no encryption (the "SHOULD encrypt"
of BBA 6.1.3.2 applies to client-side sessions).

Kept in memory of the runner process: APISIX runs one runner and the runner
serves every connection in a thread of that process, so all workers share it.
It is lost on runner restart (users have to log in again) and is not shared
between gateway instances; a production deployment needs a shared store
(e.g. Redis) behind the same interface.
"""
import hashlib
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Session:
    # absolute deadline and idle timeout, enforced on every lookup [OWASP Session: timeouts]
    expires_at: float
    idle_timeout: float
    last_seen: float = field(default_factory=time.time)

    # pending login: the authorization request is in flight
    state: Optional[str] = None
    nonce: Optional[str] = None
    code_verifier: Optional[str] = None
    return_to: str = "/"

    # authenticated: claims shown to the SPA, tokens that never leave the BFF
    user: Optional[dict] = None
    id_token: Optional[str] = None
    access_token: Optional[str] = None
    access_token_expires_at: Optional[float] = None
    refresh_token: Optional[str] = None

    # serializes token refreshes of one session: with refresh token rotation a
    # second, parallel refresh would use an already spent refresh token
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    @property
    def authenticated(self) -> bool:
        return self.user is not None

    @property
    def pending(self) -> bool:
        return self.state is not None


def _key(session_id: str) -> str:
    # store a hash of the id, so a dump of the store holds no usable cookie values
    return hashlib.sha256(session_id.encode()).hexdigest()


class SessionStore:

    def __init__(self, clock=time.time):
        self._sessions = {}
        self._lock = threading.Lock()
        self._clock = clock

    def create(self, session: Session) -> str:
        """Stores `session` under a fresh id and returns the id for the cookie."""
        # 256 bits from the OS CSPRNG [OWASP Session: session ID entropy >= 64 bits]
        session_id = secrets.token_urlsafe(32)
        now = self._clock()
        session.last_seen = now
        with self._lock:
            self._purge(now)
            self._sessions[_key(session_id)] = session
        return session_id

    def get(self, session_id: Optional[str]) -> Optional[Session]:
        """The live session for `session_id`, or None. Counts as activity for the idle timeout."""
        if not session_id:
            return None
        now = self._clock()
        with self._lock:
            session = self._sessions.get(_key(session_id))
            if session is None:
                return None
            if self._expired(session, now):
                del self._sessions[_key(session_id)]
                return None
            session.last_seen = now
            return session

    def delete(self, session_id: Optional[str]) -> Optional[Session]:
        if not session_id:
            return None
        with self._lock:
            return self._sessions.pop(_key(session_id), None)

    def __len__(self):
        return len(self._sessions)

    @staticmethod
    def _expired(session: Session, now: float) -> bool:
        return now >= session.expires_at or now - session.last_seen >= session.idle_timeout

    def _purge(self, now: float):
        for key in [k for k, s in self._sessions.items() if self._expired(s, now)]:
            del self._sessions[key]
