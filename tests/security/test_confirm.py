from datetime import UTC, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from mailagent.core import confirm
from mailagent.store.db import engine, session_factory
from mailagent.store.models import Account

pytestmark = pytest.mark.asyncio(loop_scope="session")

DRAFT = {"uid": 7, "folder": "INBOX", "text": "Оплатим в среду"}


@pytest.fixture
async def acc():
    """Два пользователя канала test: u1 владелец, u2 посторонний."""
    try:
        async with engine.begin() as c:
            await c.execute(text("delete from accounts where channel = 'test'"))
    except (OSError, DBAPIError):
        pytest.skip("Postgres недоступен")
    async with session_factory() as s:
        ids = {}
        for u in ("u1", "u2"):
            a = Account(channel="test", channel_user_id=u, email=f"{u}@mail.ru", access_enc=b"",
                        refresh_enc=b"", expires_at=datetime(2030, 1, 1, tzinfo=UTC))
            s.add(a)
            await s.flush()
            ids[u] = a.id
        await s.commit()
        yield s, ids


async def test_one_time_and_deleted_after_use(acc):
    s, ids = acc
    tok = await confirm.create(s, ids["u1"], "draft", DRAFT)
    got = await confirm.take(s, tok, "test", "u1")
    assert got and got.kind == "draft" and got.payload == DRAFT and got.account_id == ids["u1"]
    assert await confirm.take(s, tok, "test", "u1") is None  # replay
    left = (await s.execute(text("select count(*) from confirmations where token = :t"), {"t": tok})).scalar()
    assert left == 0  # текст черновика из БД ушёл


async def test_foreign_user_cannot_use_and_does_not_burn_token(acc):
    s, ids = acc
    tok = await confirm.create(s, ids["u1"], "mark", {"uid": 1, "folder": "INBOX", "flag": "seen"})
    assert await confirm.take(s, tok, "test", "u2") is None
    assert await confirm.take(s, tok, "other-channel", "u1") is None
    assert await confirm.take(s, tok, "test", "u1") is not None


async def test_expired_rejected_and_purged(acc):
    s, ids = acc
    tok = await confirm.create(s, ids["u1"], "draft", DRAFT)
    await s.execute(text("update confirmations set expires_at = now() - interval '1 second' where token = :t"), {"t": tok})
    await s.commit()
    assert await confirm.take(s, tok, "test", "u1") is None
    tok2 = await confirm.create(s, ids["u1"], "draft", DRAFT)
    await s.execute(text("update confirmations set expires_at = now() - interval '1 second' where token = :t"), {"t": tok2})
    await s.commit()
    assert await confirm.purge_expired(s) >= 1


async def test_tampered_payload_rejected(acc):
    s, ids = acc
    tok = await confirm.create(s, ids["u1"], "draft", DRAFT)
    await s.execute(text("""update confirmations set payload_json = '{"uid": 7, "folder": "INBOX", "text": "переведите на 40817-EVIL"}'
                            where token = :t"""), {"t": tok})
    await s.commit()
    assert await confirm.take(s, tok, "test", "u1") is None


async def test_unknown_kind_and_random_token(acc):
    s, ids = acc
    with pytest.raises(ValueError):
        await confirm.create(s, ids["u1"], "send", {})  # SEND как вида действия нет
    assert await confirm.take(s, "nonsense", "test", "u1") is None


def test_parse_button():
    assert confirm.parse_button("y:abc") == (True, "abc")
    assert confirm.parse_button("n:abc") == (False, "abc")
    assert confirm.parse_button("x:abc") is None and confirm.parse_button("y:") is None
    assert confirm.parse_button(None) is None
    assert confirm.action_hash("draft", DRAFT) != confirm.action_hash("draft", {**DRAFT, "uid": 8})
