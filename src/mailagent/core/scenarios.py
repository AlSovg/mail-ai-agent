"""Сценарии: сводка/«требуют ответа», поиск, пересказ цепочки, черновик (01-product, 02-security §5.1).

Поток каждого сценария: письма из коннектора → шлюз (флаг модели ИЛИ правила) → LLM по схеме →
фильтр вывода. Подозрительное письмо в вывод модели не попадает: пользователю — предупреждение
из метаданных. Черновик здесь только предлагается; запись в «Черновики» — save_draft после кнопки.
"""
import asyncio
from dataclasses import dataclass

from pydantic import BaseModel

from mailagent.core.guard import is_suspicious, warning
from mailagent.core.llm import LLM
from mailagent.core.outfilter import filter_out
from mailagent.mail.connector import Draft, MailConnector, Message, MessageMeta, SearchQuery

MAX_CHARS = 6000  # на письмо в промпт: лимит токенов (T11)
DIGEST_LIMIT = 10

SYS_ANALYZE = ("Ты ИИ-ассистент почты. Кратко перескажи письмо по-русски в 1–3 предложениях с ключевыми "
               "фактами (суммы, даты, сроки). needs_reply=true, только если отправитель ждёт ответа "
               "от получателя.")
SYS_THREAD = ("Ты ИИ-ассистент почты. Перескажи переписку по-русски: о чём договорились, что решено, "
              "что осталось открытым, сроки и суммы. Письма идут в хронологическом порядке.")
SYS_DRAFT = ("Ты ИИ-ассистент почты. Напиши короткий вежливый черновик ответа на письмо на языке "
             "письма. Не давай обязательств по деньгам и срокам, которых нет в письме.")


class Analysis(BaseModel):
    summary: str
    needs_reply: bool
    suspicious: bool


class ThreadOut(BaseModel):
    summary: str
    suspicious: bool


class DraftOut(BaseModel):
    draft: str
    suspicious: bool


@dataclass(frozen=True)
class Item:
    meta: MessageMeta
    summary: str | None  # None — письмо заблокировано шлюзом
    needs_reply: bool = False


def mail_text(m: Message) -> str:
    return f"От: {m.meta.sender}\nТема: {m.meta.subject}\n\n{m.text}"[:MAX_CHARS]


async def _io(fn, *a):
    return await asyncio.to_thread(fn, *a)  # imaplib блокирующий


async def analyze(llm: LLM, m: Message) -> Item:
    text = mail_text(m)
    out = await llm.complete(SYS_ANALYZE, [text], Analysis)
    if is_suspicious(out.suspicious, text):
        return Item(m.meta, None)
    summary, _ = filter_out(text, out.summary)
    return Item(m.meta, summary, out.needs_reply)


async def triage(conn: MailConnector, llm: LLM, q: SearchQuery, only_reply: bool = False) -> list[Item]:
    # ponytail: письма по очереди; параллельно, если сводка станет медленной
    items = []
    for meta in await _io(conn.search, q):
        item = await analyze(llm, await _io(conn.fetch, meta.uid, meta.folder))
        if item.summary is None or item.needs_reply or not only_reply:  # блок показываем всегда
            items.append(item)
    return items


def render_items(items: list[Item]) -> str:
    if not items:
        return "Ничего не нашлось."
    lines = []
    for i, it in enumerate(items, 1):
        head = f"{i}. {it.meta.sender} — {it.meta.subject}"
        if it.summary is None:
            lines.append(f"{head}\n{warning(it.meta.sender, it.meta.subject)}")
        else:
            lines.append(f"{head}\n{it.summary}" + ("\n↩ нужен ответ" if it.needs_reply else ""))
    return "\n\n".join(lines)


async def search(conn: MailConnector, text: str, limit: int = 10) -> list[MessageMeta]:
    """Без LLM: результат — метаданные, собранные кодом."""
    return await _io(conn.search, SearchQuery(text=text, limit=limit))


def render_metas(metas: list[MessageMeta]) -> str:
    if not metas:
        return "Ничего не нашлось."
    return "\n".join(f"{i}. {m.sender} — {m.subject}" + (f" ({m.date:%d.%m.%Y})" if m.date else "")
                     for i, m in enumerate(metas, 1))


async def thread_summary(conn: MailConnector, llm: LLM, meta: MessageMeta) -> str:
    msgs = await _io(conn.thread, meta.uid, meta.folder)
    texts = [mail_text(m) for m in msgs]
    out = await llm.complete(SYS_THREAD, texts, ThreadOut)
    if is_suspicious(out.suspicious, "\n".join(texts)):
        return warning(meta.sender, meta.subject)
    return filter_out("\n".join(texts), out.summary)[0]


async def propose_draft(conn: MailConnector, llm: LLM, meta: MessageMeta) -> tuple[str, dict | None]:
    """(текст для чата, payload подтверждения). payload None — письмо заблокировано."""
    m = await _io(conn.fetch, meta.uid, meta.folder)
    text = mail_text(m)
    out = await llm.complete(SYS_DRAFT, [text], DraftOut)
    if is_suspicious(out.suspicious, text):
        return warning(meta.sender, meta.subject), None
    _, warn = filter_out(text, "", out.draft)
    subject = m.meta.subject if m.meta.subject.lower().startswith("re:") else f"Re: {m.meta.subject}"
    payload = {"to": m.meta.sender, "subject": subject, "body": out.draft,
               "in_reply_to": m.message_id, "references": [*m.references, m.message_id]}
    shown = f"Черновик ответа — проверьте перед отправкой:\n\n{out.draft}"
    if warn:
        shown += "\n\n⚠️ В черновике есть ссылка, адрес или код из письма — проверьте, что это уместно."
    return shown, payload


async def save_draft(conn: MailConnector, sender: str, payload: dict) -> int:
    """Вызывается только после «Да» (confirm.take). Возвращает UID черновика."""
    d = Draft(sender=sender, to=payload["to"], subject=payload["subject"], body=payload["body"],
              in_reply_to=payload["in_reply_to"], references=tuple(payload["references"]))
    return await _io(conn.append_draft, d)
