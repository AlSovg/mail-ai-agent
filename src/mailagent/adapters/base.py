import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, Protocol

import httpx

RETRY_DELAYS = (1.0, 3.0)


class InvalidSignature(Exception):
    """Webhook не прошёл проверку подлинности."""


async def post_retry(client: httpx.AsyncClient, url: str, **kw) -> httpx.Response:
    """POST с повтором только при ошибке соединения: запрос до сервера не дошёл, дубля не будет."""
    for delay in (*RETRY_DELAYS, None):
        try:
            return await client.post(url, **kw)
        except (httpx.ConnectError, httpx.ConnectTimeout):
            if delay is None:
                raise
            await asyncio.sleep(delay)
    raise AssertionError  # недостижимо


def split_text(text: str, limit: int) -> list[str]:
    """Режет по абзацам/строкам/пробелам, чтобы части влезали в лимит мессенджера."""
    parts: list[str] = []
    while len(text) > limit:
        cut = max(text.rfind("\n\n", 0, limit), text.rfind("\n", 0, limit), text.rfind(" ", 0, limit))
        cut = cut if cut > 0 else limit
        parts.append(text[:cut].rstrip())
        text = text[cut:].lstrip()
    return [*parts, text] if text else parts


@dataclass(frozen=True)
class ChatRef:
    channel: str
    user_id: str
    chat_id: str | None = None


@dataclass(frozen=True)
class Button:
    text: str
    payload: str


@dataclass(frozen=True)
class Event:
    """Нейтральное событие: ядро агента не знает про конкретный мессенджер."""

    event_id: str
    channel: str
    user_id: str
    chat: ChatRef
    kind: Literal["text", "button", "started"]
    text: str | None = None
    payload: str | None = None
    callback_id: str | None = None


class MessengerAdapter(Protocol):
    def parse_event(self, headers: Mapping[str, str], body: bytes) -> Event | None:
        """Проверяет подпись (InvalidSignature) и разбирает событие; None — событие не нужно."""

    async def send(self, chat: ChatRef, text: str, buttons: list[Button] | None = None) -> None: ...

    async def confirm(self, chat: ChatRef, prompt: str, token: str) -> None:
        """Кнопки «Да/Нет»; payload несёт одноразовый токен."""

    async def subscribe(self, url: str) -> None:
        """Регистрирует webhook на стороне платформы."""

    async def answer_callback(self, callback_id: str, text: str) -> None:
        """Закрывает «часики» на кнопке; text — одноразовое уведомление."""
