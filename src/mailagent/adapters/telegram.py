import hmac
import json
import logging
from collections.abc import Mapping

import httpx

from mailagent.adapters.base import Button, ChatRef, Event, InvalidSignature, post_retry, split_text

CHANNEL = "telegram"
TEXT_LIMIT = 4096  # sendMessage.text
SECRET_HEADER = "x-telegram-bot-api-secret-token"
logging.getLogger("httpx").setLevel(logging.WARNING)  # INFO-лог httpx пишет URL с токеном бота


class TelegramAdapter:
    """Bot API: https://core.telegram.org/bots/api. Текст без parse_mode — разметка из писем не исполняется."""

    def __init__(self, token: str, webhook_secret: str, client: httpx.AsyncClient | None = None,
                 base_url: str = "https://api.telegram.org"):
        if not webhook_secret:
            raise ValueError("TELEGRAM_WEBHOOK_SECRET обязателен (1–256 символов A-Za-z0-9_-)")
        self._secret = webhook_secret.encode()
        self._client = client or httpx.AsyncClient(base_url=f"{base_url}/bot{token}", timeout=15)

    def parse_event(self, headers: Mapping[str, str], body: bytes) -> Event | None:
        got = {k.lower(): v for k, v in headers.items()}.get(SECRET_HEADER, "")
        if not hmac.compare_digest(got.encode(), self._secret):
            raise InvalidSignature
        u = json.loads(body)
        eid = f"tg:{u['update_id']}"
        if m := u.get("message"):
            sender, text = m.get("from") or {}, m.get("text")
            if not sender or not text or sender.get("is_bot") or m["chat"].get("type") != "private":
                return None
            uid = str(sender["id"])
            chat = ChatRef(CHANNEL, uid, str(m["chat"]["id"]))
            if text.startswith("/start"):
                return Event(eid, CHANNEL, uid, chat, "started", text=text, payload=text[7:] or None)
            return Event(eid, CHANNEL, uid, chat, "text", text=text)
        if cb := u.get("callback_query"):
            uid = str(cb["from"]["id"])
            chat_id = ((cb.get("message") or {}).get("chat") or {}).get("id")
            chat = ChatRef(CHANNEL, uid, str(chat_id or uid))
            return Event(eid, CHANNEL, uid, chat, "button", payload=cb.get("data"), callback_id=cb["id"])
        return None

    async def _call(self, method: str, body: dict) -> dict:
        try:
            r = await post_retry(self._client, f"/{method}", json=body)
            r.raise_for_status()
            data = r.json()
        except httpx.HTTPError as e:  # в URL токен бота, а исключение httpx его содержит — наружу не отдаём
            raise RuntimeError(f"{method}: {type(e).__name__}") from None
        if not data.get("ok"):
            raise RuntimeError(f"{method} отклонён")  # без тела ответа
        return data

    async def send(self, chat: ChatRef, text: str, buttons: list[Button] | None = None) -> None:
        parts = split_text(text, TEXT_LIMIT) or [""]
        for i, part in enumerate(parts):
            body: dict = {"chat_id": chat.chat_id or chat.user_id, "text": part,
                          "link_preview_options": {"is_disabled": True}}
            if buttons and i == len(parts) - 1:  # клавиатура только под последней частью
                body["reply_markup"] = {"inline_keyboard": [
                    [{"text": b.text, "callback_data": b.payload} for b in buttons]]}
            await self._call("sendMessage", body)

    async def confirm(self, chat: ChatRef, prompt: str, token: str) -> None:
        # callback_data ≤ 64 байт: "y:" + token_urlsafe(24) = 34
        await self.send(chat, prompt, [Button("Да", f"y:{token}"), Button("Нет", f"n:{token}")])

    async def answer_callback(self, callback_id: str, text: str) -> None:
        await self._call("answerCallbackQuery", {"callback_query_id": callback_id, "text": text})

    async def subscribe(self, url: str) -> None:
        await self._call("setWebhook", {"url": url, "secret_token": self._secret.decode(),
                                        "allowed_updates": ["message", "callback_query"]})
