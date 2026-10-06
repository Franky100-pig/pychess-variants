from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import aiohttp_session
from aiohttp import web
from pychess_global_app_state_utils import get_app_state
from pymongo import ReturnDocument
from settings import MAX_AGE

if TYPE_CHECKING:
    from aiohttp_session import Session
    from pychess_global_app_state import PychessGlobalAppState
    from user import User

AUTH_VERSION_SESSION_KEY = "auth_version"
AUTH_VERSION_DB_PATH = "security.sessionVersion"
AUTHENTICATED_AT_SESSION_KEY = "authenticated_at"

Handler = Callable[[web.Request], Awaitable[web.StreamResponse]]


def auth_version_from_user_document(user_doc: Mapping[str, Any]) -> int:
    security = user_doc.get("security")
    if not isinstance(security, Mapping):
        return 0
    value = security.get("sessionVersion", 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def authenticate_session(session: Session, username: str, auth_version: int) -> None:
    session["user_name"] = username
    session[AUTH_VERSION_SESSION_KEY] = auth_version
    session[AUTHENTICATED_AT_SESSION_KEY] = int(datetime.now(UTC).timestamp())


async def revoke_user_sessions(user: User) -> None:
    """Invalidate every browser session previously issued for one registered user.

    Browser sessions are encrypted client-side cookies, so deleting one browser's
    cookie cannot invalidate a copied cookie.  The durable per-user generation is
    stored in Mongo and mirrored on the cached User.  Every authenticated request
    must present the same generation in its encrypted cookie.
    """

    if user.anon:
        return

    version = await revoke_user_sessions_for_username(user.app_state, user.username)
    # In-memory test identities may have no corresponding Mongo document.
    user.auth_version = (
        max(user.auth_version, version) if version is not None else user.auth_version + 1
    )


async def revoke_user_sessions_for_username(
    app_state: PychessGlobalAppState, username: str
) -> int | None:
    """Persist revocation even when the account has no cached User object."""
    if app_state.db is None:
        return None
    doc = await app_state.db.user.find_one_and_update(
        {"_id": username},
        {"$inc": {AUTH_VERSION_DB_PATH: 1}},
        projection={AUTH_VERSION_DB_PATH: 1},
        return_document=ReturnDocument.AFTER,
    )
    if doc is None:
        return None

    version = auth_version_from_user_document(doc)
    # A User may have been loaded during the database await. Also avoid moving
    # its generation backwards if concurrent revocations return out of order.
    cached_user = app_state.users.data.get(username)
    if cached_user is not None:
        cached_user.auth_version = max(cached_user.auth_version, version)
    return version


def _session_auth_version(session: Session) -> int | None:
    value = session.get(AUTH_VERSION_SESSION_KEY, 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _session_authentication_is_recent(session: Session) -> bool:
    # Legacy cookies have no separate login timestamp. Use their signed creation
    # time rather than granting another full lifetime on first use.
    authenticated_at = session.get(AUTHENTICATED_AT_SESSION_KEY, session.created)
    if type(authenticated_at) is not int:
        return False
    age = int(datetime.now(UTC).timestamp()) - authenticated_at
    return 0 <= age < MAX_AGE


def session_matches_user(session: Session, user: User) -> bool:
    session_user = session.get("user_name")
    if not isinstance(session_user, str) or session_user != user.username or not user.enabled:
        return False
    if user.anon:
        return True
    return _session_auth_version(
        session
    ) == user.auth_version and _session_authentication_is_recent(session)


def session_expiry_timeout(session: Session, user: User) -> asyncio.Timeout:
    """Bound a live connection to its original login lifetime, even while idle.

    The caller must keep connection cleanup outside this timeout. Anonymous
    connections have no registered-account authority and no login deadline.
    """
    if not session_matches_user(session, user):
        raise web.HTTPUnauthorized(text="Session is no longer valid. Please sign in again.")
    remaining = None
    if not user.anon:
        authenticated_at = session.get(AUTHENTICATED_AT_SESSION_KEY, session.created)
        remaining = max(0.0, authenticated_at + MAX_AGE - datetime.now(UTC).timestamp())
    return asyncio.timeout(remaining)


def _is_websocket_handshake(request: web.Request) -> bool:
    return request.headers.get("Upgrade", "").lower() == "websocket"


@web.middleware
async def session_security_middleware(request: web.Request, handler: Handler) -> web.StreamResponse:
    """Reject browser cookies invalidated by logout/account administration.

    Missing auth_version means version 0 for compatibility with cookies issued
    before this mechanism was deployed.  The first logout increments the user's
    durable version, which also invalidates any copied legacy cookie.
    """

    session = await aiohttp_session.get_session(request)
    session_user = session.get("user_name")
    if not isinstance(session_user, str) or not session_user:
        return await handler(request)

    app_state = get_app_state(request.app)
    user = await app_state.users.get(session_user)

    if not user.anon and AUTHENTICATED_AT_SESSION_KEY not in session:
        # Session.__setitem__ resets created, so pin the original timestamp
        # before views update last_visit or generate a CSRF token.
        session[AUTHENTICATED_AT_SESSION_KEY] = session.created

    if not session_matches_user(session, user):
        session.invalidate()

        # Do not let an invalid authenticated cookie silently become a fresh
        # anonymous identity on mutations or WebSocket handshakes.
        if request.method not in {"GET", "HEAD", "OPTIONS", "TRACE"} or _is_websocket_handshake(
            request
        ):
            raise web.HTTPUnauthorized(text="Session is no longer valid. Please sign in again.")

    return await handler(request)
