import urllib.parse
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from mailagent.mail.auth import (
    AccessRevoked,
    InvalidState,
    MailAuth,
    UnsupportedMailbox,
    _now,
)
from mailagent.store.crypto import TokenCipher, generate_key
from mailagent.store.db import engine, session_factory
from mailagent.store.models import Account

pytestmark = pytest.mark.asyncio(loop_scope="session")


def make(email="user@mail.ru", refresh_status=200):
    calls = []

    def handler(req: httpx.Request):
        body = urllib.parse.parse_qs(req.content.decode())
        calls.append((str(req.url), body))
        if req.url.path == "/token":
            if body["grant_type"] == ["refresh_token"]:
                if refresh_status != 200:
                    return httpx.Response(refresh_status, json={"error": "invalid_grant"})
                return httpx.Response(200, json={"access_token": "A2", "expires_in": 3600})
            return httpx.Response(200, json={"access_token": "A1", "refresh_token": "R1", "expires_in": 3600})
        return httpx.Response(200, json={"email": email})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    auth = MailAuth("cid", "sec", "https://x/cb", "openid email mail.imap", TokenCipher(generate_key()), client)
    return auth, calls


@pytest.fixture
async def session():
    try:
        async with engine.begin() as c:
            await c.execute(text("delete from accounts where channel = 'test'"))
            await c.execute(text("delete from oauth_states where channel = 'test'"))
    except (OSError, DBAPIError):
        pytest.skip("Postgres недоступен")
    async with session_factory() as s:
        yield s


def state_of(url):
    return urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["state"][0]


async def test_flow_encrypts_tokens_and_state_is_single_use(session):
    auth, calls = make()
    url = await auth.start(session, "test", "u1")
    q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert q["code_challenge_method"] == ["S256"] and "profile" not in q["scope"][0]
    acc = await auth.finish(session, state_of(url), "code1")
    assert acc.email == "user@mail.ru" and b"A1" not in acc.access_enc and b"R1" not in acc.refresh_enc
    # code_verifier ушёл в обмен кода и подходит к challenge
    assert calls[0][1]["code_verifier"][0]
    assert await auth.access_token(session, acc.id) == "A1"
    with pytest.raises(InvalidState):
        await auth.finish(session, state_of(url), "code1")  # replay
    with pytest.raises(InvalidState):
        await auth.finish(session, "unknown", "c")


async def test_expired_state_rejected(session):
    auth, _ = make()
    url = await auth.start(session, "test", "u2")
    await session.execute(text("update oauth_states set expires_at = now() - interval '1 minute' where channel='test'"))
    await session.commit()
    with pytest.raises(InvalidState):
        await auth.finish(session, state_of(url), "c")


async def test_vk_mailbox_rejected_and_not_stored(session):
    auth, _ = make(email="user@vk.com")
    url = await auth.start(session, "test", "u3")
    with pytest.raises(UnsupportedMailbox):
        await auth.finish(session, state_of(url), "c")
    assert (await session.execute(select(Account).where(Account.channel == "test"))).first() is None


async def test_refresh_keeps_old_refresh_token_and_revoke(session):
    auth, _ = make()
    acc = await auth.finish(session, state_of(await auth.start(session, "test", "u4")), "c")
    acc.expires_at = _now() - timedelta(minutes=1)
    await session.commit()
    assert await auth.access_token(session, acc.id) == "A2"
    # refresh_token не вернулся -> старый сохранён
    assert auth._cipher.decrypt(acc.refresh_enc, f"account:{acc.id}") == "R1"

    bad, _ = make(refresh_status=400)
    bad._cipher = auth._cipher
    acc.expires_at = _now() - timedelta(minutes=1)
    await session.commit()
    with pytest.raises(AccessRevoked):
        await bad.access_token(session, acc.id)


async def test_disconnect_deletes_account(session):
    auth, _ = make()
    acc = await auth.finish(session, state_of(await auth.start(session, "test", "u5")), "c")
    await auth.disconnect(session, "test", "u5")
    session.expire_all()
    assert await session.get(Account, acc.id) is None
