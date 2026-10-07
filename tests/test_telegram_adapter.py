import json

import httpx
import pytest

from mailagent.adapters.base import ChatRef, InvalidSignature, split_text
from mailagent.adapters.telegram import TelegramAdapter

H = {"X-Telegram-Bot-Api-Secret-Token": "s3cret-value"}
USER = {"id": 7, "is_bot": False}
PRIVATE = {"id": 7, "type": "private"}


def upd(**kw):
    return json.dumps(kw).encode()


def test_bad_or_missing_secret_rejected():
    a = TelegramAdapter("t", "s3cret-value")
    with pytest.raises(InvalidSignature):
        a.parse_event({}, upd(update_id=1))
    with pytest.raises(InvalidSignature):
        a.parse_event({"X-Telegram-Bot-Api-Secret-Token": "wrong"}, upd(update_id=1))
    with pytest.raises(ValueError):
        TelegramAdapter("t", "")


def test_parse_events():
    a = TelegramAdapter("t", "s3cret-value")
    msg = a.parse_event(H, upd(update_id=1, message={"from": USER, "chat": PRIVATE, "text": "сводка"}))
    assert (msg.kind, msg.user_id, msg.text, msg.event_id, msg.chat.chat_id) == ("text", "7", "сводка", "tg:1", "7")
    st = a.parse_event(H, upd(update_id=2, message={"from": USER, "chat": PRIVATE, "text": "/start"}))
    assert st.kind == "started" and st.payload is None
    cb = a.parse_event(H, upd(update_id=3, callback_query={
        "id": "c1", "from": USER, "data": "y:tok", "message": {"chat": PRIVATE}}))
    assert (cb.kind, cb.payload, cb.callback_id) == ("button", "y:tok", "c1")
    # боты, группы и не-текст игнорируем
    assert a.parse_event(H, upd(update_id=4, message={"from": {"id": 1, "is_bot": True}, "chat": PRIVATE,
                                                      "text": "x"})) is None
    assert a.parse_event(H, upd(update_id=5, message={"from": USER, "chat": {"id": -5, "type": "group"},
                                                      "text": "сводка"})) is None
    assert a.parse_event(H, upd(update_id=6, message={"from": USER, "chat": PRIVATE})) is None


async def test_confirm_subscribe_answer_requests():
    seen = []

    def handler(req: httpx.Request):
        seen.append((req.url.path, json.loads(req.content)))
        return httpx.Response(200, json={"ok": True, "result": True})

    a = TelegramAdapter("t", "s3cret-value", httpx.AsyncClient(
        base_url="https://x/bott", transport=httpx.MockTransport(handler)))
    await a.confirm(ChatRef("telegram", "7", "7"), "Создать черновик?", "tok")
    await a.subscribe("https://bot.example/webhook/telegram")
    await a.answer_callback("cb1", "ок")
    (p1, b1), (p2, b2), (p3, b3) = seen
    btns = b1["reply_markup"]["inline_keyboard"][0]
    assert p1.endswith("/sendMessage") and b1["chat_id"] == "7" and "parse_mode" not in b1
    assert [b["callback_data"] for b in btns] == ["y:tok", "n:tok"]
    assert p2.endswith("/setWebhook") and b2["secret_token"] == "s3cret-value"
    assert p3.endswith("/answerCallbackQuery") and b3 == {"callback_query_id": "cb1", "text": "ок"}


async def test_errors_do_not_leak_token():
    a = TelegramAdapter("SECRET-BOT-TOKEN", "s3cret-value", httpx.AsyncClient(
        base_url="https://x/botSECRET-BOT-TOKEN", transport=httpx.MockTransport(lambda r: httpx.Response(500))))
    with pytest.raises(RuntimeError) as e:
        await a.send(ChatRef("telegram", "7"), "x")
    assert "SECRET-BOT-TOKEN" not in str(e.value) and e.value.__cause__ is None


def test_confirm_payload_fits_callback_data():
    import secrets
    assert len(f"y:{secrets.token_urlsafe(24)}".encode()) <= 64


async def test_connect_errors_are_retried_but_other_errors_are_not(monkeypatch):
    monkeypatch.setattr("mailagent.adapters.base.RETRY_DELAYS", (0, 0))
    calls = []

    def handler(req: httpx.Request):
        calls.append(1)
        if len(calls) < 3:
            raise httpx.ConnectTimeout("t")
        return httpx.Response(200, json={"ok": True})

    a = TelegramAdapter("t", "s3cret-value", httpx.AsyncClient(
        base_url="https://x/bott", transport=httpx.MockTransport(handler)))
    await a.send(ChatRef("telegram", "7"), "x")
    assert len(calls) == 3
    calls.clear()
    a._client = httpx.AsyncClient(base_url="https://x/bott", transport=httpx.MockTransport(
        lambda r: (calls.append(1), httpx.Response(500))[1]))
    with pytest.raises(RuntimeError):
        await a.send(ChatRef("telegram", "7"), "x")
    assert len(calls) == 1


def test_split_text():
    parts = split_text(("слово " * 1500).strip(), 4096)
    assert len(parts) > 1 and all(len(p) <= 4096 for p in parts)
