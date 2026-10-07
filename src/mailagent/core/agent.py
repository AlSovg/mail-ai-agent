"""Цикл запроса: событие → роутер команд → сценарий → ответ; кнопка → confirm.take → коннектор.

Роутер на правилах, LLM права не выбирает (03-architecture). Изменяющее действие одно — запись
черновика, и только после «Да» по одноразовому токену, привязанному к владельцу.
"""
import asyncio
import imaplib
import logging
import re
from collections.abc import Callable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from mailagent.adapters.base import ChatRef, Event, MessengerAdapter
from mailagent.core import confirm, scenarios
from mailagent.core.llm import LLM, LLMError
from mailagent.core.ratelimit import RateLimiter
from mailagent.mail.auth import AccessRevoked, MailAuth
from mailagent.mail.connector import MailboxError, MailConnector, MessageMeta, SearchQuery
from mailagent.store.models import Account, AuditLog

log = logging.getLogger("mailagent")

HELP = ("Что умею:\n• «сводка» — непрочитанные письма с пересказом\n• «нужен ответ» — письма, "
        "которые ждут ответа\n• «найди <запрос>» — поиск\n• «перескажи 2» / «черновик 2» — по номеру "
        "из последнего списка\n• «отключить» — удалить доступ к почте\n\nЯ ничего не отправляю и не удаляю: "
        "черновик сохраняется только после вашего «Да».")
IMAP_STEPS = ("Включите IMAP в Почте Mail:\n1. Откройте раздел «Внешние сервисы»: https://account.mail.ru/oauth/applications\n2. Переведите переключатель «Доступ к Почте по IMAP, POP и SMTP» во включённое положение.")
ONBOARD = ("Я читаю вашу почту Mail (только чтение), пересказываю письма и готовлю черновики. Тексты "
           "писем обрабатывает LLM-провайдер. Письма не отправляю и не удаляю. Ящики vk.com не "
           "поддерживаются.\n\n" + IMAP_STEPS + "\n\nЗатем подключите доступ (если Mail покажет ошибку redirect_uri, откройте ссылку ещё раз): ")
IMAP_HELP = "Mail не пустил по IMAP. " + IMAP_STEPS + "\nЗатем повторите запрос."
TOO_MANY = "Слишком много запросов. Подождите немного и повторите."
NOT_SHOWN = "Нет такого номера в последнем списке. Сначала запросите «сводку» или «найди …»."


def _command(text: str) -> str | None:
    """Команды, которые вызывают LLM."""
    if re.search(r"нужен ответ|нужно ответить|требу\w+ ответ|/reply", text):
        return "reply"
    if re.search(r"сводк|важн|что нового|/digest", text):
        return "digest"
    if re.match(r"/?(?:перескажи|thread)\b", text):
        return "thread"
    if re.match(r"/?(?:черновик|draft)\b", text):
        return "draft"
    return None


def _num(text: str) -> int | None:
    m = re.search(r"\d+", text)
    return int(m.group()) if m else None


class Agent:
    def __init__(self, adapter: MessengerAdapter, llm: LLM, auth: MailAuth,
                 sessions: async_sessionmaker[AsyncSession],
                 connect: Callable[[str, str], MailConnector] = MailConnector,
                 msg_limit: RateLimiter | None = None, llm_limit: RateLimiter | None = None):
        self._a, self._llm, self._auth, self._sessions, self._connect = adapter, llm, auth, sessions, connect
        self._msg_limit = msg_limit or RateLimiter(20, 600)  # любые сообщения: 20 за 10 мин
        self._llm_limit = llm_limit or RateLimiter(10, 3600)  # команды с LLM: 10 в час (сводка = до 10 вызовов)
        # ponytail: последний список в памяти процесса (теряется при рестарте, один воркер);
        # при нескольких воркерах — в БД
        self._last: dict[tuple[str, str], list[MessageMeta]] = {}

    async def handle(self, ev: Event) -> None:
        try:
            async with self._sessions() as s:
                if ev.kind == "button":
                    await self._button(s, ev)
                else:
                    await self._text(s, ev)
        except Exception:  # одно событие не должно ронять обработчик; тела писем в лог не идут
            log.exception("handle failed kind=%s", ev.kind)
            await self._say(ev.chat, "Что-то пошло не так. Попробуйте ещё раз позже.")

    async def _say(self, chat: ChatRef, text: str) -> None:
        try:
            await self._a.send(chat, text)
        except Exception:
            log.exception("send failed channel=%s user=%s", chat.channel, chat.user_id)

    async def _account(self, s: AsyncSession, ev: Event) -> Account | None:
        return (await s.execute(select(Account).where(
            Account.channel == ev.channel, Account.channel_user_id == ev.user_id))).scalar_one_or_none()

    async def _text(self, s: AsyncSession, ev: Event) -> None:
        text = (ev.text or "").strip().lower()
        acc = await self._account(s, ev)
        key = (ev.channel, ev.user_id)
        if not self._msg_limit.allow(key) and not re.match(r"/?(отключить|disconnect)", text):
            return await self._say(ev.chat, TOO_MANY)  # «отключить» не блокируем: это отзыв доступа
        if re.match(r"/?(отключить|disconnect)", text):
            await self._auth.disconnect(s, ev.channel, ev.user_id)
            self._last.pop(key, None)
            return await self._say(ev.chat, "Доступ отключён, токены и подтверждения удалены.")
        if acc is None:
            link = await self._auth.start(s, ev.channel, ev.user_id)
            return await self._say(ev.chat, ONBOARD + link)
        if ev.kind == "started" or not text or text in ("/start", "помощь", "/help"):
            return await self._say(ev.chat, HELP)
        try:
            token = await self._auth.access_token(s, acc.id)
        except AccessRevoked:
            link = await self._auth.start(s, ev.channel, ev.user_id)
            return await self._say(ev.chat, "Доступ к почте отозван или истёк. Подключите заново: " + link)
        try:
            conn = await asyncio.to_thread(self._connect, acc.email, token)
        except imaplib.IMAP4.error:
            return await self._say(ev.chat, IMAP_HELP)
        except OSError:
            log.exception("mailbox connect failed")
            return await self._say(ev.chat, "Почта сейчас не отвечает. Попробуйте позже.")
        try:
            await self._route(s, ev, acc, conn, text)
        except (MailboxError, OSError):
            log.exception("mailbox error")
            await self._say(ev.chat, "Почта сейчас не отвечает. Попробуйте позже.")
        except LLMError as e:
            log.error("llm error: %s", e)
            await self._say(ev.chat, "Модель сейчас недоступна. Попробуйте позже.")
        finally:
            await asyncio.to_thread(conn.close)

    async def _route(self, s: AsyncSession, ev: Event, acc: Account, conn: MailConnector, text: str) -> None:
        key = (ev.channel, ev.user_id)
        if m := re.match(r"/?(?:найди|поиск|search)\s+(.+)", text):
            metas = await scenarios.search(conn, m.group(1))
            self._last[key] = metas
            return await self._say(ev.chat, scenarios.render_metas(metas))
        cmd = _command(text)
        if cmd and not self._llm_limit.allow(key):  # search выше — без LLM, не считается
            return await self._say(ev.chat, TOO_MANY)
        if cmd in ("reply", "digest"):
            return await self._digest(ev, key, conn, only_reply=cmd == "reply")
        if cmd in ("thread", "draft"):
            meta = self._pick(key, text)
            if meta is None:
                return await self._say(ev.chat, NOT_SHOWN)
            if cmd == "thread":
                return await self._say(ev.chat, await scenarios.thread_summary(conn, self._llm, meta))
            shown, payload = await scenarios.propose_draft(conn, self._llm, meta)
            if payload is None:
                return await self._say(ev.chat, shown)
            tok = await confirm.create(s, acc.id, "draft", {**payload, "uid": meta.uid, "folder": meta.folder})
            return await self._a.confirm(ev.chat, shown + "\n\nСохранить в «Черновики»? Письмо не уйдёт.", tok)
        await self._say(ev.chat, HELP)

    def _pick(self, key: tuple[str, str], text: str) -> MessageMeta | None:
        n, last = _num(text), self._last.get(key, [])
        return last[n - 1] if n and 0 < n <= len(last) else None

    async def _digest(self, ev: Event, key: tuple[str, str], conn: MailConnector, only_reply: bool = False) -> None:
        items = await scenarios.triage(conn, self._llm, SearchQuery(unseen=True, limit=scenarios.DIGEST_LIMIT),
                                       only_reply)
        self._last[key] = [i.meta for i in items]
        await self._say(ev.chat, scenarios.render_items(items))

    async def _button(self, s: AsyncSession, ev: Event) -> None:
        parsed = confirm.parse_button(ev.payload)
        if parsed is None:
            return await self._answer(ev, "Неизвестная кнопка.")
        yes, token = parsed
        got = await confirm.take(s, token, ev.channel, ev.user_id)  # «Нет» и replay текст тоже не оставляют
        if got is None:
            return await self._answer(ev, "Подтверждение устарело или уже использовано.")
        if not yes:
            return await self._answer(ev, "Отменено.")
        acc = await s.get(Account, got.account_id)
        if acc is None or got.kind != "draft":
            return await self._answer(ev, "Это действие не поддерживается.")
        result = "error"
        try:
            conn = await asyncio.to_thread(self._connect, acc.email, await self._auth.access_token(s, acc.id))
            try:
                await scenarios.save_draft(conn, acc.email, got.payload)
                result = "ok"
            finally:
                await asyncio.to_thread(conn.close)
        except (AccessRevoked, MailboxError, imaplib.IMAP4.error, OSError):
            log.exception("draft save failed")
        s.add(AuditLog(account_id=acc.id, action="draft", uid=str(got.payload.get("uid")), result=result))
        await s.commit()
        await self._answer(ev, "Черновик сохранён." if result == "ok" else "Не удалось сохранить черновик.")

    async def _answer(self, ev: Event, text: str) -> None:
        try:
            await self._a.answer_callback(ev.callback_id or "", text)
            await self._a.send(ev.chat, text)
        except Exception:
            log.exception("answer failed")


async def purge_loop(sessions: async_sessionmaker[AsyncSession], every: int = 600) -> None:
    while True:
        await asyncio.sleep(every)
        try:
            async with sessions() as s:
                await confirm.purge_expired(s)
        except Exception:
            log.exception("purge failed")
