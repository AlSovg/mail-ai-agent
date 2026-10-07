from datetime import datetime, time

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    LargeBinary,
    String,
    Time,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def _now():
    return mapped_column(DateTime(timezone=True), server_default=func.now())


class Event(Base):
    """Дедуп webhook; строки старше 7 дней чистятся."""

    __tablename__ = "events"
    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    received_at: Mapped[datetime] = _now()


class Account(Base):
    """Один чат = один ящик. Токены шифруются AES-GCM, aad = f"account:{id}"."""

    __tablename__ = "accounts"
    __table_args__ = (UniqueConstraint("channel", "channel_user_id"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    channel: Mapped[str] = mapped_column(String(16))
    channel_user_id: Mapped[str] = mapped_column(String(64))
    email: Mapped[str] = mapped_column(String(320))
    access_enc: Mapped[bytes] = mapped_column(LargeBinary)
    refresh_enc: Mapped[bytes] = mapped_column(LargeBinary)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _now()
    push_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    push_time: Mapped[time | None] = mapped_column(Time, nullable=True)


class OAuthState(Base):
    """Nonce для OAuth: TTL 10 мин, одноразовый."""

    __tablename__ = "oauth_states"
    state: Mapped[str] = mapped_column(String(128), primary_key=True)
    channel: Mapped[str] = mapped_column(String(16))
    channel_user_id: Mapped[str] = mapped_column(String(64))
    verifier_enc: Mapped[bytes] = mapped_column(LargeBinary)  # PKCE code_verifier, AES-GCM, aad = f"oauth:{state}"
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class Confirmation(Base):
    """Одноразовое подтверждение действия: TTL 5 мин. payload — только метаданные действия."""

    __tablename__ = "confirmations"
    token: Mapped[str] = mapped_column(String(128), primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("accounts.id", ondelete="CASCADE"))
    action_hash: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(32))
    payload_json: Mapped[dict] = mapped_column(JSON)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class AuditLog(Base):
    """Без тел писем и адресов; хранение 90 дней. account_id без FK: журнал переживает удаление аккаунта."""

    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    ts: Mapped[datetime] = _now()
    account_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    action: Mapped[str] = mapped_column(String(32))
    uid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result: Mapped[str] = mapped_column(String(32))
