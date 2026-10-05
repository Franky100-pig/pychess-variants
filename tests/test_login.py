import asyncio
import json
import time
from typing import ClassVar
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlencode, urlparse

from aiohttp import WSMsgType, WSServerHandshakeError
from aiohttp.test_utils import AioHTTPTestCase
from mongomock_motor import AsyncMongoMockClient
from oauth_config import oauth_config
from pychess_global_app_state_utils import get_app_state
from user import User

from server import make_app


class FakeTokenResponse:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None

    async def json(self):
        return {"access_token": "test-access-token"}


class FakeClientSession:
    requests: ClassVar[list[dict[str, str]]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None

    def post(self, _url, *, data, headers):
        self.requests.append(data)
        return FakeTokenResponse()


class LoginRouteTestCase(AioHTTPTestCase):
    async def get_application(self):
        return make_app(db_client=AsyncMongoMockClient(tz_aware=True), simple_cookie_storage=True)

    async def tearDownAsync(self):
        await self.client.close()

    async def asyncSetUp(self):
        await super().asyncSetUp()
        FakeClientSession.requests.clear()
        self.client_secret = "fake-client-secret"
        self.oauth_config_patch = patch.dict(
            oauth_config["discord"], {"client_secret": self.client_secret}
        )
        self.oauth_config_patch.start()

    async def asyncTearDown(self):
        self.oauth_config_patch.stop()
        await super().asyncTearDown()

    def set_session_data(self, data: dict[str, object]) -> None:
        session_data = {"session": data, "created": int(time.time())}
        self.client.session.cookie_jar.update_cookies({"AIOHTTP_SESSION": json.dumps(session_data)})

    def set_session_user(self, username: str, auth_version: int | None = None) -> None:
        data: dict[str, object] = {"user_name": username}
        if auth_version is not None:
            data["auth_version"] = auth_version
        self.set_session_data(data)

    async def start_discord_oauth(self):
        response = await self.client.get("/oauth/discord", allow_redirects=False)
        self.assertEqual(response.status, 302)
        location = response.headers["Location"]
        state = parse_qs(urlparse(location).query)["state"][0]
        return location, state

    async def finish_discord_oauth(self, state: str, code: str):
        query = urlencode({"state": state, "code": code})
        return await self.client.get(f"/oauth/discord?{query}", allow_redirects=False)

    async def test_provider_neutral_login_opens_provider_chooser(self):
        response = await self.client.get("/login", allow_redirects=False)

        self.assertEqual(response.status, 302)
        self.assertEqual(response.headers.get("Location"), "/#login")

    async def test_logout_requires_csrf_protected_post(self):
        app_state = get_app_state(self.app)
        user = User(app_state, username="alice")
        app_state.users[user.username] = user
        self.set_session_user("alice")

        get_response = await self.client.get("/logout", allow_redirects=False)
        self.assertEqual(405, get_response.status)

        cross_site = await self.client.post(
            "/logout",
            headers={
                "Origin": "https://attacker.test",
                "Sec-Fetch-Site": "cross-site",
            },
            allow_redirects=False,
        )
        self.assertEqual(403, cross_site.status)

        origin = str(self.client.make_url("/")).rstrip("/")
        logout_response = await self.client.post(
            "/logout",
            headers={"Origin": origin, "Sec-Fetch-Site": "same-origin"},
            allow_redirects=False,
        )
        self.assertEqual(302, logout_response.status)
        self.assertEqual("/", logout_response.headers.get("Location"))

        account_response = await self.client.get("/account", allow_redirects=False)
        self.assertEqual(302, account_response.status)
        self.assertEqual("/login", account_response.headers.get("Location"))

    async def test_logout_closes_existing_authenticated_channels(self):
        app_state = get_app_state(self.app)
        user = User(app_state, username="alice")
        app_state.users[user.username] = user

        ws = AsyncMock()
        user.authenticated_sockets.add(ws)
        queue: asyncio.Queue[str] = asyncio.Queue()
        user.notify_channels.add(queue)
        self.set_session_user("alice")

        origin = str(self.client.make_url("/")).rstrip("/")
        response = await self.client.post(
            "/logout",
            headers={"Origin": origin, "Sec-Fetch-Site": "same-origin"},
            allow_redirects=False,
        )

        self.assertEqual(302, response.status)
        ws.send_str.assert_awaited_once_with('{"type":"logout"}')
        ws.close.assert_awaited_once()
        with self.assertRaises(asyncio.QueueShutDown):
            queue.put_nowait("still-open")

    async def test_websockets_reject_untrusted_or_missing_origins(self):
        app_state = get_app_state(self.app)
        user = User(app_state, username="alice")
        app_state.users[user.username] = user
        origin = str(self.client.make_url("/")).rstrip("/")
        for authenticated in (False, True):
            self.client.session.cookie_jar.clear()
            if authenticated:
                self.set_session_user("alice")
            for headers in (
                {},
                {"Origin": "null"},
                {"Origin": "http://attacker.test", "Sec-Fetch-Site": "same-site"},
                {"Origin": "http://attacker.test", "Sec-Fetch-Site": "cross-site"},
                {"Origin": "http://localhost:invalid"},
                {"Origin": origin, "Sec-Fetch-Site": "cross-site"},
            ):
                with self.subTest(authenticated=authenticated, headers=headers):
                    for path in ("/wsl", "/wsr/abcd1234", "/wst", "/wss", "/wsstudy/abcd1234"):
                        with self.assertRaises(WSServerHandshakeError) as error:
                            await self.client.ws_connect(path, headers=headers)
                        self.assertEqual(403, error.exception.status)

    async def test_same_origin_websocket_accepts_valid_session(self):
        app_state = get_app_state(self.app)
        user = User(app_state, username="alice")
        app_state.users[user.username] = user
        self.set_session_user("alice")
        origin = str(self.client.make_url("/")).rstrip("/")
        ws = await self.client.ws_connect("/wsl", headers={"Origin": origin})
        try:
            self.assertEqual(1, len(user.authenticated_sockets))
            message = await ws.receive(timeout=1)
            self.assertEqual(WSMsgType.TEXT, message.type)
        finally:
            await ws.close()

    async def test_same_origin_websocket_rejects_revoked_session(self):
        app_state = get_app_state(self.app)
        app_state.users["alice"] = User(app_state, username="alice", auth_version=1)
        self.set_session_user("alice", auth_version=0)
        origin = str(self.client.make_url("/")).rstrip("/")
        with self.assertRaises(WSServerHandshakeError) as error:
            await self.client.ws_connect("/wsl", headers={"Origin": origin})
        self.assertEqual(401, error.exception.status)

    async def test_logout_revokes_copied_cookie_server_side(self):
        app_state = get_app_state(self.app)
        await app_state.db.user.insert_one(
            {
                "_id": "alice",
                "enabled": True,
                "perfs": {},
                "pperfs": {},
                "security": {"sessionVersion": 0},
            }
        )
        self.set_session_user("alice")  # Legacy pre-version cookie is generation 0.

        cookie = self.client.session.cookie_jar.filter_cookies(self.client.make_url("/"))[
            "AIOHTTP_SESSION"
        ]
        copied_cookie = cookie.value

        origin = str(self.client.make_url("/")).rstrip("/")
        logout_response = await self.client.post(
            "/logout",
            headers={"Origin": origin, "Sec-Fetch-Site": "same-origin"},
            allow_redirects=False,
        )
        self.assertEqual(302, logout_response.status)

        user_doc = await app_state.db.user.find_one({"_id": "alice"})
        self.assertEqual(1, user_doc["security"]["sessionVersion"])
        del app_state.users["alice"]  # Force the next request to reload the durable generation.

        # Simulate an attacker replaying the exact encrypted/stateless cookie
        # copied before logout.  The durable generation now rejects it.
        self.client.session.cookie_jar.clear()
        self.client.session.cookie_jar.update_cookies({"AIOHTTP_SESSION": copied_cookie})
        stale_post = await self.client.post(
            "/logout",
            headers={"Origin": origin, "Sec-Fetch-Site": "same-origin"},
            allow_redirects=False,
        )
        self.assertEqual(401, stale_post.status)

        self.client.session.cookie_jar.clear()
        self.client.session.cookie_jar.update_cookies({"AIOHTTP_SESSION": copied_cookie})
        stale_page = await self.client.get("/account", allow_redirects=False)
        self.assertEqual(302, stale_page.status)
        self.assertEqual("/login", stale_page.headers.get("Location"))

    async def test_login_uses_current_server_side_session_generation(self):
        app_state = get_app_state(self.app)
        await app_state.db.user.insert_one(
            {
                "_id": "alice",
                "oauth_id": "discord-user-id",
                "oauth_provider": "discord",
                "enabled": True,
                "perfs": {},
                "pperfs": {},
                "security": {"sessionVersion": 7},
            }
        )
        self.set_session_data({"token": "oauth-access-token"})

        with patch(
            "login.get_user_data",
            new=AsyncMock(
                return_value={
                    "id": "discord-user-id",
                    "username": "alice",
                }
            ),
        ):
            response = await self.client.get("/login/discord", allow_redirects=False)

        self.assertEqual(302, response.status)
        self.assertEqual("/", response.headers.get("Location"))

        # If login had reused generation 0, the session middleware would reject
        # this immediately because Mongo says the current generation is 7.
        account_response = await self.client.get("/account", allow_redirects=False)
        self.assertEqual(200, account_response.status)

    async def test_oauth_state_is_random_and_does_not_expose_client_secret(self):
        first_location, first_state = await self.start_discord_oauth()
        second_location, second_state = await self.start_discord_oauth()

        self.assertNotEqual(first_state, second_state)
        self.assertNotIn(self.client_secret, first_location)
        self.assertNotIn(self.client_secret, second_location)

    async def test_oauth_flows_support_concurrent_logins_and_reject_replay(self):
        _, first_state = await self.start_discord_oauth()
        _, second_state = await self.start_discord_oauth()

        with patch("login.aiohttp.ClientSession", FakeClientSession):
            first_response = await self.finish_discord_oauth(first_state, "first-code")
            replay_response = await self.finish_discord_oauth(first_state, "replayed-code")
            second_response = await self.finish_discord_oauth(second_state, "second-code")

        self.assertEqual(first_response.headers.get("Location"), "/login/discord")
        self.assertEqual(replay_response.headers.get("Location"), "/")
        self.assertEqual(second_response.headers.get("Location"), "/login/discord")
        self.assertEqual(len(FakeClientSession.requests), 2)
        self.assertEqual(
            [request["code"] for request in FakeClientSession.requests],
            ["first-code", "second-code"],
        )
        self.assertNotEqual(
            FakeClientSession.requests[0]["code_verifier"],
            FakeClientSession.requests[1]["code_verifier"],
        )
        self.assertTrue(
            all(
                request["client_secret"] == self.client_secret
                for request in FakeClientSession.requests
            )
        )

    async def test_lichess_token_request_omits_client_secret(self):
        response = await self.client.get("/oauth/lichess", allow_redirects=False)
        state = parse_qs(urlparse(response.headers["Location"]).query)["state"][0]
        query = urlencode({"state": state, "code": "lichess-code"})

        with patch("login.aiohttp.ClientSession", FakeClientSession):
            callback_response = await self.client.get(
                f"/oauth/lichess?{query}", allow_redirects=False
            )

        self.assertEqual(callback_response.headers.get("Location"), "/login/lichess")
        self.assertEqual(len(FakeClientSession.requests), 1)
        self.assertNotIn("client_secret", FakeClientSession.requests[0])
