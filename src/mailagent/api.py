import asyncio
import logging
from contextlib import asynccontextmanager
from functools import lru_cache
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from mailagent.adapters.base import ChatRef, InvalidSignature, MessengerAdapter
from mailagent.adapters.telegram import CHANNEL, TelegramAdapter
from mailagent.config import get_settings
from mailagent.core.agent import IMAP_HELP, Agent, purge_loop
from mailagent.core.llm import OpenAICompatLLM
from mailagent.mail.auth import InvalidState, MailAuth, MailAuthError, UnsupportedMailbox
from mailagent.mail.connector import check_login
from mailagent.store.crypto import TokenCipher
from mailagent.store.db import get_session, session_factory
from mailagent.store.models import Event as EventRow
from mailagent.store.models import OAuthState

log = logging.getLogger("mailagent")


class _DropQuery(logging.Filter):
    """Access-лог uvicorn без query: там OAuth code и state."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple) and len(record.args) == 5:  # client, method, path, http, status
            a = list(record.args)
            a[2] = str(a[2]).split("?", 1)[0]
            record.args = tuple(a)
        return True


logging.basicConfig(level=logging.INFO)  # иначе INFO-логи mailagent не видны под uvicorn
logging.getLogger("uvicorn.access").addFilter(_DropQuery())
_tasks: set[asyncio.Task] = set()  # сильные ссылки: иначе задачу может собрать GC


@asynccontextmanager
async def lifespan(_: FastAPI):
    s = get_settings()
    if s.telegram_webhook_url:
        try:
            await get_messenger().subscribe(s.telegram_webhook_url)
        except Exception:  # недоступность платформы не должна ронять приложение; тело ответа в лог не идёт
            log.exception("telegram subscribe failed")
    task = asyncio.create_task(purge_loop(session_factory))
    yield
    task.cancel()


app = FastAPI(title="mailagent", lifespan=lifespan)


@lru_cache
def get_messenger() -> MessengerAdapter:
    s = get_settings()
    return TelegramAdapter(s.telegram_bot_token.get_secret_value(), s.telegram_webhook_secret.get_secret_value())


@lru_cache
def get_mail_auth() -> MailAuth:
    s = get_settings()
    return MailAuth(s.mail_client_id, s.mail_client_secret.get_secret_value(), s.mail_redirect_uri,
                    s.mail_scope, TokenCipher(s.token_encryption_key.get_secret_value()))


async def is_new_event(session: AsyncSession, event_id: str) -> bool:
    """Дедуп: мессенджер повторяет доставку, пока не получит 200, пока не получит 200."""
    res = await session.execute(
        insert(EventRow).values(event_id=event_id).on_conflict_do_nothing().returning(EventRow.event_id))
    await session.commit()
    return res.scalar() is not None


@lru_cache
def get_agent() -> Agent:
    s = get_settings()
    llm = OpenAICompatLLM(s.llm_base_url, s.llm_api_key.get_secret_value(), s.llm_model)
    return Agent(get_messenger(), llm, get_mail_auth(), session_factory)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/webhook/{channel}")
async def webhook(channel: str, request: Request, adapter: Annotated[MessengerAdapter, Depends(get_messenger)],
                  session: Annotated[AsyncSession, Depends(get_session)]) -> dict[str, bool]:
    if channel != CHANNEL:
        raise HTTPException(404)
    try:
        event = adapter.parse_event(request.headers, await request.body())
    except InvalidSignature:
        raise HTTPException(401) from None
    if event is not None and await is_new_event(session, event.event_id):
        log.info("event %s kind=%s", event.event_id, event.kind)  # тело и текст в лог не пишем
        task = asyncio.create_task(get_agent().handle(event))  # 200 нужен быстрее 30 с
        _tasks.add(task)
        task.add_done_callback(_tasks.discard)
    return {"ok": True}


@app.get("/oauth/callback", response_class=PlainTextResponse)
async def oauth_callback(state: str, auth: Annotated[MailAuth, Depends(get_mail_auth)],
                         adapter: Annotated[MessengerAdapter, Depends(get_messenger)],
                         session: Annotated[AsyncSession, Depends(get_session)],
                         code: str | None = None, error: str | None = None) -> str:
    st = await session.get(OAuthState, state)  # адресат нужен до finish: тот гасит state
    chat = ChatRef(st.channel, st.channel_user_id) if st else None
    if error or not code:
        if chat:
            await adapter.send(chat, "Доступ к почте не предоставлен. Подключить можно в любой момент заново.")
        return "Доступ не предоставлен. Можно закрыть вкладку."
    try:
        acc = await auth.finish(session, state, code)
    except InvalidState:
        raise HTTPException(400, "Ссылка устарела или уже использована. Запросите новую в чате.") from None
    except UnsupportedMailbox:
        if chat:
            await adapter.send(chat, "Этот ящик не поддерживается: для адресов vk.com недоступен IMAP.")
        return "Ящик не поддерживается. Можно закрыть вкладку."
    except (MailAuthError, httpx.HTTPError):
        log.exception("oauth finish failed")
        raise HTTPException(502, "Не удалось подключить ящик. Попробуйте ещё раз.") from None
    imap_ok = True
    try:
        imap_ok = await asyncio.to_thread(check_login, acc.email, await auth.access_token(session, acc.id))
    except Exception:  # сеть/токен: проверку пропускаем, ошибка всплывёт при первой команде
        log.exception("imap check failed")
    await adapter.send(ChatRef(acc.channel, acc.channel_user_id),
                       f"Почта {acc.email} подключена. Что сделать?" if imap_ok
                       else f"Вход в {acc.email} выполнен. " + IMAP_HELP)
    # страницу видит тот, кто открыл ссылку, а не обязательно владелец чата (02-security T5)
    return (f"Ящик {acc.email} подключён к чату в мессенджере. Если вы этого не запрашивали, отзовите "
            "доступ: https://account.mail.ru/oauth/applications")
