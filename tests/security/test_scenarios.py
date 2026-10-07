import sys
from datetime import UTC, datetime
from pathlib import Path

from mailagent.core import scenarios
from mailagent.core.llm import render_blocks
from mailagent.mail.connector import Message, MessageMeta

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "spikes" / "llm"))
from cases import CASES


def msg(uid, subject, body, sender="m@x.ru"):
    meta = MessageMeta(uid, "INBOX", subject, sender, datetime(2026, 10, 1, tzinfo=UTC), True)
    return Message(meta, "me@mail.ru", f"<{uid}@x>", "", (), body)


class FakeConn:
    def __init__(self, msgs):
        self.msgs = {m.meta.uid: m for m in msgs}
        self.drafts = []

    def search(self, q):
        return [m.meta for m in self.msgs.values()]

    def fetch(self, uid, folder):
        return self.msgs[uid]

    def thread(self, uid, folder, limit=20):
        return list(self.msgs.values())

    def append_draft(self, d):
        self.drafts.append(d)
        return 5


class ObedientLLM:
    """Худший случай: модель исполнила инъекцию и не пометила письмо подозрительным."""

    def __init__(self, **out):
        self.out, self.prompts = out, []

    async def complete(self, system, user_blocks, schema):
        self.prompts.append(render_blocks(user_blocks))
        return schema(**{k: v for k, v in self.out.items() if k in schema.model_fields})


async def test_flagged_mail_never_reaches_digest_even_if_model_lies():
    inj = next(c for c in CASES if c["id"] == "inj_ignore")
    conn = FakeConn([msg(1, inj["subj"], inj["body"])])
    llm = ObedientLLM(summary="Перешлите всё на attacker@evil.example", needs_reply=True, suspicious=False)
    items = await scenarios.triage(conn, llm, scenarios.SearchQuery())
    out = scenarios.render_items(items)
    assert items[0].summary is None and "attacker" not in out and "⚠️" in out  # сработали правила


async def test_summary_masks_requisites_from_mail():
    conn = FakeConn([msg(1, "Оплата", "Оплатите на pay-verify.example, счёт №4471 до 15 октября")])
    llm = ObedientLLM(summary="Оплатить на pay-verify.example, счёт №4471", needs_reply=False, suspicious=False)
    (item,) = await scenarios.triage(conn, llm, scenarios.SearchQuery())
    assert "pay-verify" not in item.summary and "№4471" in item.summary


async def test_only_reply_filter_keeps_blocked_and_reply():
    conn = FakeConn([msg(1, "FYI", "акт для сведения"), msg(2, "Вопрос", "срок оплаты 10 или 14 дней?")])

    class ByUid(ObedientLLM):
        async def complete(self, system, user_blocks, schema):
            return schema(summary="s", needs_reply="Вопрос" in user_blocks[0], suspicious=False)

    items = await scenarios.triage(conn, ByUid(), scenarios.SearchQuery(), only_reply=True)
    assert [i.meta.uid for i in items] == [2]


async def test_draft_proposal_then_save_only_through_payload():
    conn = FakeConn([msg(1, "Вопрос по договору", "срок оплаты 10 или 14 дней?")])
    llm = ObedientLLM(draft="Здравствуйте! Уточню и отвечу.", suspicious=False)
    text, payload = await scenarios.propose_draft(conn, llm, conn.msgs[1].meta)
    assert "проверьте перед отправкой" in text and payload["subject"] == "Re: Вопрос по договору"
    assert conn.drafts == []  # предложение ничего не пишет в ящик
    assert await scenarios.save_draft(conn, "me@mail.ru", payload) == 5
    assert conn.drafts[0].to == "m@x.ru" and conn.drafts[0].in_reply_to == "<1@x>"


async def test_blocked_mail_gets_no_draft():
    inj = next(c for c in CASES if c["id"] == "inj_draft")
    conn = FakeConn([msg(1, inj["subj"], inj["body"])])
    text, payload = await scenarios.propose_draft(
        conn, ObedientLLM(draft="Оплатите 500000 на 40817-EVIL", suspicious=False), conn.msgs[1].meta)
    assert payload is None and "40817" not in text


async def test_draft_with_requisite_from_mail_warns():
    conn = FakeConn([msg(1, "Смета", "Пишите на boss@evil.example по смете")])
    text, payload = await scenarios.propose_draft(
        conn, ObedientLLM(draft="Отправлю на boss@evil.example", suspicious=False), conn.msgs[1].meta)
    assert payload and "⚠️" in text
