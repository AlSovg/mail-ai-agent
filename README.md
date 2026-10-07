# Mail AI Agent

ИИ-агент в Telegram для Почты Mail: сводка непрочитанных писем, поиск на естественном языке, пересказ цепочек, список писем, требующих ответа, и черновики ответов. Агент только читает почту; черновик сохраняется в ящик лишь после явного подтверждения пользователя.

MVP для проверки спроса (кейс VK). Продуктовые и экономические материалы — в [`docs/`](docs/).

## Возможности

| Команда | Что делает |
|---|---|
| `сводка` | непрочитанные письма с кратким пересказом |
| `нужен ответ` | письма, которые ждут ответа |
| `найди <запрос>` | поиск по ящику |
| `перескажи N` | пересказ цепочки письма N из последнего списка |
| `черновик N` | черновик ответа; сохраняется в «Черновики» после кнопки «Да» |
| `отключить` | удаление токенов и привязки ящика |

## Безопасность

- **Нет отправки и удаления.** IMAP-коннектор не реализует `SEND`, `DELETE`, `EXPUNGE`; письма читаются через `BODY.PEEK` (не меняют флаг «прочитано»).
- **Подтверждения.** Любое изменение (сохранение черновика) — только по одноразовой кнопке: привязана к владельцу, живёт 5 минут.
- **Письма — недоверенные данные.** Шлюз (модель + правила) не пускает подозрительные письма в сводку и черновик; фильтр вывода маскирует ссылки, адреса, реквизиты и коды из писем. Набор атак — в `tests/security/`.
- **Секреты.** OAuth-токены Mail хранятся зашифрованными (AES-256-GCM), webhook проверяется секретом, запросы ограничены rate limit.

Модель угроз — [`docs/02-security.md`](docs/02-security.md).

## Архитектура

```
Telegram ──webhook──▶ FastAPI ──▶ Agent ──▶ Mail (OAuth 2.0 PKCE + IMAP XOAUTH2)
                                    │
                                    ├──▶ LLM (OpenAI-совместимый API)
                                    └──▶ PostgreSQL (события, токены, подтверждения)
```

Ядро не зависит от мессенджера: адаптер реализует приём события, отправку ответа и показ подтверждения. Подробно — [`docs/03-architecture.md`](docs/03-architecture.md).

**Стек:** Python 3.12, FastAPI, SQLAlchemy (async) + asyncpg, Alembic, PostgreSQL 16, httpx, cryptography; uv, ruff, pytest.

## Структура

```
src/mailagent/
  api.py           # /health, /webhook/{channel}, /oauth/callback
  config.py        # настройки из .env
  adapters/        # мессенджеры (Telegram)
  core/            # агент, сценарии, LLM, шлюз, фильтр вывода, подтверждения, rate limit
  mail/            # OAuth Mail и IMAP-коннектор
  store/           # модели БД, шифрование токенов
migrations/        # Alembic
tests/             # unit + security
spikes/            # исследовательские скрипты (IMAP, сравнение LLM)
docs/              # продукт, безопасность, архитектура, экономика
```

## Запуск

Нужны: Python 3.12, [uv](https://docs.astral.sh/uv/), Docker, бот в Telegram (@BotFather), приложение на [o2.mail.ru](https://o2.mail.ru/), ключ LLM-провайдера.

```bash
uv sync
cp .env.example .env          # заполнить значения
docker compose up -d db
uv run alembic upgrade head
uv run uvicorn mailagent.api:app --port 8000
```

Ключ шифрования:

```bash
python -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())"
```

Telegram и Mail требуют публичный HTTPS. Для локальной разработки — туннель ngrok (`NGROK_AUTHTOKEN`, `NGROK_DOMAIN` в `.env`):

```bash
docker compose --profile tunnel up -d ngrok
```

`TELEGRAM_WEBHOOK_URL=https://<домен>/webhook/telegram` — webhook регистрируется при старте приложения; `MAIL_REDIRECT_URI=https://<домен>/oauth/callback` — тот же адрес указать в приложении Mail.

## Тесты

```bash
uv run ruff check .
uv run pytest
```

Тесты с БД пропускаются без PostgreSQL. CI (GitHub Actions): `ruff`, `pytest`, `pip-audit`.

## Ограничения

- Ящики `@vk.com` не поддерживаются (OAuth Mail их не обслуживает).
- Для публичного запуска нужно согласование доступа к API Почты Mail.
- LLM в MVP — через OpenRouter (Qwen3-30B-A3B); для продакшена нужен российский провайдер, чтобы письма не уходили за рубеж.
- Ежедневная сводка по расписанию, действия с письмами и командные ящики — не реализованы.
