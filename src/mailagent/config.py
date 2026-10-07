from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+asyncpg://mailagent:mailagent@localhost:5434/mailagent"
    telegram_bot_token: SecretStr = SecretStr("")
    telegram_webhook_secret: SecretStr = SecretStr("")  # X-Telegram-Bot-Api-Secret-Token, A-Za-z0-9_-
    telegram_webhook_url: str = ""  # публичный https://…/webhook/telegram; пусто — не подписываться
    token_encryption_key: SecretStr = SecretStr("")  # AES-GCM, 32 байта в base64
    mail_client_id: str = ""
    mail_client_secret: SecretStr = SecretStr("")
    mail_redirect_uri: str = ""  # публичный https://…/oauth/callback, как в приложении o2.mail.ru
    mail_scope: str = "openid email mail.imap offline_access"  # без profile: минимум ПДн
    llm_base_url: str = ""
    llm_api_key: SecretStr = SecretStr("")
    llm_model: str = ""


def get_settings() -> Settings:
    return Settings()
