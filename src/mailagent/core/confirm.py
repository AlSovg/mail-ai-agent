"""Одноразовые подтверждения изменяющих действий (02-security.md T6, §5.1).

Токен привязан к аккаунту-владельцу, виду действия и action_hash от точного содержимого действия.
Строка живёт 5 минут и удаляется при первом же обращении: нажатие «Да», «Нет» или повтор не оставляют
текста черновика в БД.
"""

import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from mailagent.store.models import Account, Confirmation

TTL = timedelta(minutes=5)
KINDS = frozenset({"draft", "mark"})


@dataclass(frozen=True)
class Confirmed:
    kind: str
    payload: dict
    account_id: int


def action_hash(kind: str, payload: dict) -> str:
    canon = json.dumps({"kind": kind, "payload": payload}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canon.encode()).hexdigest()


def parse_button(data: str | None) -> tuple[bool, str] | None:
    """'y:<токен>' / 'n:<токен>' → (да?, токен); всё остальное — не наша кнопка."""
    if data and data[:2] in ("y:", "n:") and len(data) > 2:
        return data[0] == "y", data[2:]
    return None


async def create(session: AsyncSession, account_id: int, kind: str, payload: dict) -> str:
    if kind not in KINDS:
        raise ValueError(f"неизвестный вид действия: {kind}")
    token = secrets.token_urlsafe(24)
    session.add(Confirmation(
        token=token, account_id=account_id, action_hash=action_hash(kind, payload), kind=kind,
        payload_json=payload, expires_at=datetime.now(UTC) + TTL))
    await session.commit()
    return token


async def take(session: AsyncSession, token: str, channel: str, user_id: str) -> Confirmed | None:
    """Забирает подтверждение: атомарно удаляет строку, если она живая и принадлежит этому пользователю.

    None — токена нет, он просрочен, уже использован или чужой. Чужая попытка строку не трогает.
    Вызывающий исполняет действие только при «Да»; при «Нет» результат просто отбрасывается.
    """
    owner = select(Account.id).where(Account.channel == channel, Account.channel_user_id == user_id)
    row = (await session.execute(
        delete(Confirmation)
        .where(Confirmation.token == token, Confirmation.expires_at > datetime.now(UTC),
               Confirmation.account_id.in_(owner))
        .returning(Confirmation))).scalar_one_or_none()
    await session.commit()
    if row is None or row.kind not in KINDS or row.action_hash != action_hash(row.kind, row.payload_json):
        return None
    return Confirmed(row.kind, row.payload_json, row.account_id)


async def purge_expired(session: AsyncSession) -> int:
    res = await session.execute(delete(Confirmation).where(Confirmation.expires_at <= datetime.now(UTC)))
    await session.commit()
    return res.rowcount
