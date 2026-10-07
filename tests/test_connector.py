from datetime import date

import pytest

from mailagent.mail.connector import (
    ALLOWED_FLAGS,
    Draft,
    MailboxError,
    MailConnector,
    SearchQuery,
    decode_mutf7,
    html_to_text,
)

RAW = (b"From: Maria <m@x.ru>\r\nTo: me@mail.ru\r\nSubject: =?utf-8?B?0KHRh9GR0YI=?=\r\n"
       b"Date: Mon, 29 Sep 2026 10:00:00 +0300\r\nMessage-ID: <a1@x>\r\nReferences: <r0@x>\r\n"
       b"Content-Type: text/plain; charset=utf-8\r\n\r\nPay by Wednesday\r\n")


class FakeImap:
    """Записывает все команды; ответы сценарные."""

    def __init__(self, append_resp=None):
        self.cmds = []
        self.append_resp = append_resp or [b"[APPENDUID 1 42] Append done"]

    def list(self):
        return "OK", [b'(\\HasNoChildren \\Inbox) "/" "INBOX"',
                      b'(\\HasNoChildren \\Drafts) "/" "&BCcENQRABD0EPgQyBDgEOgQ4-"',
                      b'(\\HasNoChildren \\Sent) "/" "Sent"']

    def select(self, folder, readonly=False):
        self.cmds.append(("EXAMINE" if readonly else "SELECT", folder))
        return "OK", [b"1"]

    def uid(self, cmd, *args):
        self.cmds.append((f"UID {cmd}", *args))
        if cmd == "SEARCH":
            return "OK", [b"3 7 9"]
        if cmd == "FETCH":
            return "OK", [(b"7 (UID 7 FLAGS (\\Seen) BODY[] {10}", RAW), b")"]
        return "OK", [b"done"]

    def append(self, folder, flags, date_time, msg):
        self.cmds.append(("APPEND", folder, flags, msg))
        return "OK", self.append_resp

    def logout(self):
        pass


def conn(fake=None):
    f = fake or FakeImap()
    return MailConnector("me@mail.ru", "t", conn=f), f


def test_search_is_readonly_and_peek():
    c, f = conn()
    metas = c.search(SearchQuery(sender="maria", since=date(2026, 9, 1), unseen=True, limit=2))
    assert [m.uid for m in metas] == [9, 7]  # свежие первыми, limit
    assert ("EXAMINE", '"INBOX"') in f.cmds and not any(x[0] == "SELECT" for x in f.cmds)
    fetches = [x for x in f.cmds if x[0] == "UID FETCH"]
    assert fetches and all("PEEK" in x[2] for x in fetches)
    assert metas[0].subject == "Счёт" and metas[0].unseen is False


def test_fetch_parses_text():
    c, _ = conn()
    m = c.fetch(7, "INBOX")
    assert m.text == "Pay by Wednesday" and m.message_id == "<a1@x>" and m.references == ("<r0@x>",)


def test_append_draft_returns_appenduid_and_uses_drafts_folder():
    c, f = conn()
    uid = c.append_draft(Draft("me@mail.ru", "m@x.ru", "Re: Счёт", "Оплатим в среду", in_reply_to="<a1@x>"))
    assert uid == 42
    cmd = next(x for x in f.cmds if x[0] == "APPEND")
    assert cmd[1] == '"&BCcENQRABD0EPgQyBDgEOgQ4-"' and cmd[2] == "\\Draft"
    assert b"In-Reply-To: <a1@x>" in cmd[3]


def test_append_without_appenduid_is_error():
    c, _ = conn(FakeImap(append_resp=[b"Append done"]))
    with pytest.raises(MailboxError):
        c.append_draft(Draft("a@mail.ru", "b@x.ru", "s", "b"))


def test_mark_only_allowed_flags_and_no_destructive_api():
    c, f = conn()
    c.mark(7, "INBOX", "seen")
    assert ("UID STORE", "7", "+FLAGS", "(\\Seen)") in f.cmds
    assert set(ALLOWED_FLAGS.values()) == {"\\Seen", "\\Flagged"}
    with pytest.raises(KeyError):
        c.mark(7, "INBOX", "deleted")  # type: ignore[arg-type]
    public = {n for n in dir(MailConnector) if not n.startswith("_")}
    assert public == {"close", "list_folders", "search", "fetch", "thread", "append_draft", "mark"}


def test_helpers():
    assert decode_mutf7("&BCcENQRABD0EPgQyBDgEOgQ4-") == "Черновики"
    assert decode_mutf7("A&-B") == "A&B"
    assert html_to_text("<p>Hi</p><script>x()</script><div>there</div>") == "Hi\nthere"
