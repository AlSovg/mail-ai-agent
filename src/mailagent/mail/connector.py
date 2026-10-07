"""IMAP-коннектор Mail. Синхронный (imaplib): из async-кода вызывать через asyncio.to_thread.

Ограничения MVP закреплены кодом, а не соглашением: у класса нет методов отправки, удаления,
копирования и перемещения; IMAP-соединение приватное, а команда STORE принимает только
флаги из ALLOWED_FLAGS. Чтение идёт через EXAMINE и BODY.PEEK, письма не помечаются прочитанными.
"""

import base64
import imaplib
import re
import time
from dataclasses import dataclass, field
from datetime import date, datetime
from email import message_from_bytes, policy
from email.message import EmailMessage
from email.utils import formatdate, make_msgid, parsedate_to_datetime
from html.parser import HTMLParser
from typing import Literal

HOST = "imap.mail.ru"
MAX_BODY_BYTES = 200_000  # читаем не больше: большие письма и вложения не нужны
ALLOWED_FLAGS = {"seen": "\\Seen", "flagged": "\\Flagged"}
Flag = Literal["seen", "flagged"]


class MailboxError(Exception):
    pass


@dataclass(frozen=True)
class Folder:
    name: str  # как на проводе (modified UTF-7), его же передавать в search/fetch
    title: str  # для показа
    attrs: tuple[str, ...]


@dataclass(frozen=True)
class SearchQuery:
    folder: str = "INBOX"
    text: str | None = None
    sender: str | None = None
    since: date | None = None
    unseen: bool = False
    limit: int = 20


@dataclass(frozen=True)
class MessageMeta:
    uid: int
    folder: str
    subject: str
    sender: str
    date: datetime | None
    unseen: bool


@dataclass(frozen=True)
class Message:
    meta: MessageMeta
    to: str
    message_id: str
    in_reply_to: str
    references: tuple[str, ...]
    text: str  # недоверенные данные: в промпт только отдельным блоком
    attachments: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Draft:
    sender: str
    to: str
    subject: str
    body: str
    in_reply_to: str | None = None
    references: tuple[str, ...] = ()


def decode_mutf7(s: str) -> str:
    def repl(m: re.Match) -> str:
        if m.group(1) == "":
            return "&"
        b64 = m.group(1).replace(",", "/")
        return base64.b64decode(b64 + "=" * (-len(b64) % 4)).decode("utf-16-be")

    return re.sub(r"&([^-]*)-", repl, s)


def _quote(name: str) -> str:
    name = re.sub(r"[\x00-\x1f\x7f]", " ", name)  # CR/LF в команде = вторая IMAP-команда (imaplib не проверяет)
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


class _Html(HTMLParser):
    def __init__(self):
        super().__init__()
        self.out: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag in ("br", "p", "div", "tr", "li"):
            self.out.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.out.append(data)


def html_to_text(html: str) -> str:
    p = _Html()
    p.feed(html)
    return re.sub(r"\n\s*\n+", "\n\n", "".join(p.out)).strip()


def _body_text(msg: EmailMessage) -> tuple[str, tuple[str, ...]]:
    attachments = tuple(p.get_filename() or "без имени" for p in msg.iter_attachments())
    part = msg.get_body(preferencelist=("plain", "html"))
    if part is None:
        return "", attachments
    text = part.get_content()
    return (html_to_text(text) if part.get_content_type() == "text/html" else text).strip(), attachments


def _date(msg) -> datetime | None:
    try:
        return parsedate_to_datetime(str(msg["Date"])) if msg["Date"] else None
    except (TypeError, ValueError):
        return None


class MailConnector:
    def __init__(self, email: str, access_token: str, host: str = HOST, conn=None):
        self._email = email
        if conn is None:
            conn = imaplib.IMAP4_SSL(host, 993, timeout=30)
            auth = f"user={email}\x01auth=Bearer {access_token}\x01\x01".encode()
            conn.authenticate("XOAUTH2", lambda _: auth)
        self._c = conn
        self._drafts: str | None = None

    def close(self) -> None:
        try:
            self._c.logout()
        except (imaplib.IMAP4.error, OSError):
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # --- READ ---

    def list_folders(self) -> list[Folder]:
        typ, data = self._c.list()
        if typ != "OK":
            raise MailboxError("LIST")
        folders = []
        for raw in data:
            m = re.match(rb'\((.*?)\) "(.*?)" (.*)$', raw or b"")
            if m:
                name = m.group(3).decode().strip('"')
                attrs = tuple(m.group(1).decode().split())
                folders.append(Folder(name, decode_mutf7(name), attrs))
        return folders

    def search(self, q: SearchQuery) -> list[MessageMeta]:
        self._select(q.folder, readonly=True)
        crit: list = []
        if q.unseen:
            crit.append("UNSEEN")
        if q.since:
            crit += ["SINCE", q.since.strftime("%d-%b-%Y")]
        if q.sender:
            crit += ["FROM", _quote(q.sender)]
        if q.text:
            crit += ["TEXT", _quote(q.text)]
        charset = ("CHARSET", "UTF-8") if any(not str(c).isascii() for c in crit) else ()
        args = [*charset, *(c.encode() if charset else c for c in crit)] or ["ALL"]
        typ, data = self._c.uid("SEARCH", None, *args)
        if typ != "OK":
            raise MailboxError("SEARCH")
        uids = [int(u) for u in data[0].split()][-q.limit:][::-1]  # свежие первыми
        return [self._meta(uid, q.folder) for uid in uids]

    def fetch(self, uid: int, folder: str) -> Message:
        self._select(folder, readonly=True)
        raw, flags = self._fetch_raw(uid, f"(FLAGS BODY.PEEK[]<0.{MAX_BODY_BYTES}>)")
        msg = message_from_bytes(raw, policy=policy.default)
        text, attachments = _body_text(msg)
        meta = MessageMeta(uid, folder, str(msg["Subject"] or ""), str(msg["From"] or ""),
                           _date(msg), "\\Seen" not in flags)
        return Message(meta, str(msg["To"] or ""), str(msg["Message-ID"] or "").strip(),
                       str(msg["In-Reply-To"] or "").strip(),
                       tuple(str(msg["References"] or "").split()), text, attachments)

    def thread(self, uid: int, folder: str, limit: int = 20) -> list[Message]:
        """У Mail нет THREAD: собираем по Message-ID / References в папке и в «Отправленных»."""
        first = self.fetch(uid, folder)
        ids = {i for i in (first.message_id, first.in_reply_to, *first.references) if i}
        found = {(folder, uid): first}
        sent = [f.name for f in self.list_folders() if "\\Sent" in f.attrs]
        for fld in dict.fromkeys([folder, *sent]):
            self._select(fld, readonly=True)
            for mid in ids:
                typ, data = self._c.uid("SEARCH", None, "OR", "HEADER", "Message-ID", _quote(mid),
                                        "HEADER", "References", _quote(mid))
                for u in (data[0].split() if typ == "OK" and data and data[0] else []):
                    if (fld, int(u)) not in found and len(found) < limit:
                        found[(fld, int(u))] = self.fetch(int(u), fld)
        return sorted(found.values(), key=lambda m: m.meta.date.timestamp() if m.meta.date else 0)

    # --- DRAFT ---

    def append_draft(self, draft: Draft) -> int:
        """Кладёт письмо в «Черновики» с флагом \\Draft. Возвращает UID из APPENDUID (SEARCH у Mail отстаёт)."""
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = draft.sender, draft.to, draft.subject
        msg["Date"], msg["Message-ID"] = formatdate(localtime=True), make_msgid()
        if draft.in_reply_to:
            msg["In-Reply-To"] = draft.in_reply_to
            msg["References"] = " ".join((*draft.references, draft.in_reply_to))
        msg.set_content(draft.body)
        typ, resp = self._c.append(_quote(self._drafts_folder()), "\\Draft",
                                   imaplib.Time2Internaldate(time.time()), msg.as_bytes())
        m = re.search(rb"APPENDUID \d+ (\d+)", b" ".join(r for r in resp if isinstance(r, bytes)))
        if typ != "OK" or not m:
            raise MailboxError("APPEND без APPENDUID: запись черновика не подтверждена")
        return int(m.group(1))

    # --- MUTATE (вызывать только после проверенного подтверждения пользователя) ---

    def mark(self, uid: int, folder: str, flag: Flag) -> None:
        self._select(folder, readonly=False)
        typ, _ = self._c.uid("STORE", str(uid), "+FLAGS", f"({ALLOWED_FLAGS[flag]})")
        if typ != "OK":
            raise MailboxError("STORE")

    # --- внутреннее ---

    def _drafts_folder(self) -> str:
        if self._drafts is None:
            folders = self.list_folders()
            by_attr = next((f.name for f in folders if "\\Drafts" in f.attrs), None)
            by_name = next((f.name for f in folders if f.title.lower() in ("черновики", "drafts")), None)
            self._drafts = by_attr or by_name
            if not self._drafts:
                raise MailboxError("папка черновиков не найдена")
        return self._drafts

    def _select(self, folder: str, readonly: bool) -> None:
        typ, _ = self._c.select(_quote(folder), readonly=readonly)
        if typ != "OK":
            raise MailboxError(f"SELECT {folder}")

    def _fetch_raw(self, uid: int, items: str) -> tuple[bytes, str]:
        typ, data = self._c.uid("FETCH", str(uid), items)
        if typ != "OK":
            raise MailboxError("FETCH")
        for part in data:
            if isinstance(part, tuple):
                return part[1], part[0].decode(errors="replace")
        raise MailboxError(f"письмо {uid} не найдено")

    def _meta(self, uid: int, folder: str) -> MessageMeta:
        raw, head = self._fetch_raw(uid, "(FLAGS BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE)])")
        msg = message_from_bytes(raw, policy=policy.default)
        return MessageMeta(uid, folder, str(msg["Subject"] or ""), str(msg["From"] or ""),
                           _date(msg), "\\Seen" not in head)


def check_login(email: str, access_token: str) -> bool:
    """False — Mail отверг вход (обычно IMAP не включён в ящике). Сетевые сбои (OSError) не глотаем."""
    try:
        MailConnector(email, access_token).close()
    except imaplib.IMAP4.error:
        return False
    return True
