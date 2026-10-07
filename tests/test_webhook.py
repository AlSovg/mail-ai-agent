import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from mailagent.adapters.telegram import TelegramAdapter
from mailagent.api import app, get_messenger
from mailagent.store.db import engine

H = {"X-Telegram-Bot-Api-Secret-Token": "s3cret-value"}
BODY = json.dumps({"update_id": 1, "message": {
    "from": {"id": 7, "is_bot": False}, "chat": {"id": 7, "type": "private"}, "text": "привет"}})


@pytest.fixture
def client():
    app.dependency_overrides[get_messenger] = lambda: TelegramAdapter("t", "s3cret-value")
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_forged_webhook_rejected(client):
    assert client.post("/webhook/telegram", content=BODY).status_code == 401
    bad = {"X-Telegram-Bot-Api-Secret-Token": "x"}
    assert client.post("/webhook/telegram", content=BODY, headers=bad).status_code == 401
    assert client.post("/webhook/max", content=BODY, headers=H).status_code == 404


@pytest.mark.asyncio(loop_scope="session")
async def test_dedup_against_postgres():
    """Нужен Postgres из docker-compose с применённой миграцией."""
    from mailagent.api import is_new_event
    from mailagent.store.db import session_factory

    try:
        async with engine.begin() as c:
            await c.execute(text("delete from events where event_id = 'test-dedup-1'"))
    except (OSError, DBAPIError):
        pytest.skip("Postgres недоступен")
    async with session_factory() as s:
        assert await is_new_event(s, "test-dedup-1") is True
        assert await is_new_event(s, "test-dedup-1") is False
