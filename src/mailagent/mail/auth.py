import base64
import hashlib
import secrets
import urllib.parse
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import delete, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from mailagent.store.crypto import TokenCipher
from mailagent.store.models import Account, OAuthState

AUTH_URL = "https://oauth.mail.ru/login"
TOKEN_URL = "https://oauth.mail.ru/token"
USERINFO_URL = "https://oauth.mail.ru/api/v1/oidc/userinfo"
STATE_TTL = timedelta(minutes=10)
REFRESH_SKEW = timedelta(seconds=60)
# ящики vk.com недоступны по IMAP (ответ поддержки Mail 2026-09-30)
SUPPORTED_DOMAINS = {"mail.ru", "bk.ru", "inbox.ru", "list.ru", "internet.ru", "xmail.ru"}


class MailAuthError(Exception):
    """Базовая ошибка подключения ящика."""


class InvalidState(MailAuthError):
    """state неизвестен, просрочен или уже использован."""


class UnsupportedMailbox(MailAuthError):
    """Домен ящика не поддерживается (например, vk.com)."""


class AccessRevoked(MailAuthError):
    """refresh_token отозван: нужно подключить ящик заново."""


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _now() -> datetime:
    return datetime.now(UTC)


class MailAuth:
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str, scope: str,
                 cipher: TokenCipher, client: httpx.AsyncClient | None = None):
        self._id, self._redirect, self._scope, self._cipher = client_id, redirect_uri, scope, cipher
        basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        self._headers = {"Authorization": f"Basic {basic}"}
        self._http = client or httpx.AsyncClient(timeout=30)

    async def start(self, session: AsyncSession, channel: str, user_id: str) -> str:
        """Ссылка OAuth. state и code_verifier одноразовые, живут 10 минут."""
        state = secrets.token_urlsafe(32)  # Mail требует 256 бит
        verifier = _b64url(secrets.token_bytes(48))
        session.add(OAuthState(
            state=state, channel=channel, channel_user_id=user_id,
            verifier_enc=self._cipher.encrypt(verifier, f"oauth:{state}"),
            expires_at=_now() + STATE_TTL))
        await session.commit()
        return AUTH_URL + "?" + urllib.parse.urlencode({
            "response_type": "code", "client_id": self._id, "scope": self._scope,
            "prompt": "consent", "redirect_uri": self._redirect, "state": state,
            "code_challenge": _b64url(hashlib.sha256(verifier.encode()).digest()),
            "code_challenge_method": "S256"})

    async def finish(self, session: AsyncSession, state: str, code: str) -> Account:
        # атомарно гасим state: повторный callback с тем же state не пройдёт
        row = (await session.execute(
            update(OAuthState)
            .where(OAuthState.state == state, OAuthState.used.is_(False), OAuthState.expires_at > _now())
            .values(used=True).returning(OAuthState))).scalar_one_or_none()
        await session.commit()
        if row is None:
            raise InvalidState
        verifier = self._cipher.decrypt(row.verifier_enc, f"oauth:{state}")
        tok = await self._token({"grant_type": "authorization_code", "code": code,
                                 "code_verifier": verifier, "redirect_uri": self._redirect})
        r = await self._http.post(USERINFO_URL, headers={"Authorization": f"Bearer {tok['access_token']}"})
        r.raise_for_status()
        email = r.json()["email"].lower()
        if email.rpartition("@")[2] not in SUPPORTED_DOMAINS:
            raise UnsupportedMailbox(email.rpartition("@")[2])
        # строка нужна до шифрования: id входит в aad
        acc_id = (await session.execute(
            insert(Account).values(
                channel=row.channel, channel_user_id=row.channel_user_id, email=email,
                access_enc=b"", refresh_enc=b"", expires_at=_now())
            .on_conflict_do_update(index_elements=["channel", "channel_user_id"], set_={"email": email})
            .returning(Account.id))).scalar_one()
        acc = await session.get(Account, acc_id)
        self._store(acc, tok, tok["refresh_token"])
        await session.commit()
        return acc

    async def access_token(self, session: AsyncSession, account_id: int) -> str:
        acc = await session.get(Account, account_id)
        if acc is None:
            raise AccessRevoked
        aad = f"account:{acc.id}"
        if acc.expires_at - REFRESH_SKEW > _now():
            return self._cipher.decrypt(acc.access_enc, aad)
        refresh = self._cipher.decrypt(acc.refresh_enc, aad)
        try:
            tok = await self._token({"grant_type": "refresh_token", "refresh_token": refresh})
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (400, 401):  # invalid_grant
                raise AccessRevoked from e
            raise
        self._store(acc, tok, tok.get("refresh_token", refresh))  # refresh может не вернуться
        await session.commit()
        return tok["access_token"]

    async def disconnect(self, session: AsyncSession, channel: str, user_id: str) -> None:
        """Удаляет аккаунт, токены и подтверждения (CASCADE). Журнал остаётся без привязки к ящику."""
        await session.execute(delete(Account).where(
            Account.channel == channel, Account.channel_user_id == user_id))
        await session.execute(delete(OAuthState).where(
            OAuthState.channel == channel, OAuthState.channel_user_id == user_id))
        await session.commit()

    async def _token(self, data: dict) -> dict:
        r = await self._http.post(TOKEN_URL, data=data, headers=self._headers)
        r.raise_for_status()
        return r.json()

    def _store(self, acc: Account, tok: dict, refresh: str) -> None:
        aad = f"account:{acc.id}"
        acc.access_enc = self._cipher.encrypt(tok["access_token"], aad)
        acc.refresh_enc = self._cipher.encrypt(refresh, aad)
        acc.expires_at = _now() + timedelta(seconds=int(tok.get("expires_in", 3600)))


__all__ = ["AccessRevoked", "InvalidState", "MailAuth", "MailAuthError", "UnsupportedMailbox"]
