# 03. Архитектура

Статус: v1 (2026-10-01). Опирается на `02-security.md` (модель угроз, §5.1 меры), `04-mvp-scope.md`, `research/02-spike-mail.md` (поведение Mail IMAP). Адаптер мессенджера — Telegram (MAX убран 2026-10-02: регистрация бота недоступна).

## Выбор стека (решение 2026-10-01)
Критерии — требования `02-security.md` §8, не удобство разработчика.

**Python 3.12 + FastAPI + pydantic, PostgreSQL.**

| Потребность | Решение | Почему |
|---|---|---|
| IMAP XOAUTH2 + `APPEND`, без SEND/DELETE, минимум зависимостей (T13) | stdlib `imaplib` за классом `MailConnector` | Ровно эти операции подтверждены спайком (`spikes/mail/spike.py`: XOAUTH2, `LIST`, чтение, `APPEND`); ноль внешних зависимостей. Для сравнения, `imapflow` (TS) тянет 8 прямых зависимостей. SMTP не подключаем. Блокирующий API — вызываем в потоках, соединение на запрос |
| Фильтр вывода и регрессионный набор инъекций (§5.1, критерий приёмки) | Python | `spikes/llm/outfilter.py` и `cases.py` уже написаны и проверены, переписывать защитный код — новый источник ошибок |
| Структурированный вывод LLM (T1) | `pydantic` v2 | Схема действия `{action, message_uid}` проверяется кодом |
| Telegram | тонкий `MessengerAdapter` на `httpx` поверх Bot API (приём события, ответ, кнопки подтверждения) | API нужен узкий (3 метода + подписка), SDK не берём |
| Webhook: 200 за 30 с, ретраи, дубли | FastAPI: проверить `X-Telegram-Bot-Api-Secret-Token` (`hmac.compare_digest`), записать id события в Postgres (уникальный ключ), ответить 200, обработать в фоне | Идемпотентность по id события (`update_id`) |
| Секреты (A1, A4) | `cryptography` (AES-GCM), ключ из env/secret-store | |
| Подмена LLM (T7, 152-ФЗ) | интерфейс `LLM` поверх OpenAI-совместимого API | Подходят и локальная модель, и РФ-провайдер; выбор провайдера отдельно |
| Push без `IDLE` у Mail | опрос по расписанию в одном процессе (на старте), только по подписке | Очередь и брокер не вводим, пока не упрёмся в нагрузку |
| Аудит зависимостей | `uv` + lock-файл, `pip-audit` в CI | |
| Деплой | VPS в РФ, HTTPS 443, доверенный сертификат | Webhook Telegram принимает только HTTPS |

**Отвергнуто: TypeScript.** Плюсы: официальные SDK мессенджеров, `zod`, `imapflow` (v2.2.1, свежий релиз). Минусы для наших потребностей: больше зависимостей в IMAP-цепочке, переписывание проверенного фильтра вывода и тестов.

**Оговорки:** `imaplib` не умеет `IDLE`, но у Mail его нет и так; один процесс — потолок по числу пользователей, масштабирование (очередь, пул) — после пилота.

## Схема

```
Telegram ──webhook──▶ [API: FastAPI]  ──▶ events (dedup) ──▶ [Адаптер Telegram]
                                                            │ нейтральное событие
                                                            ▼
                                          ┌──────────── [Ядро агента] ────────────┐
                                          │ роутер намерений → сценарии           │
                                          │ шлюз suspicious → LLM → фильтр вывода │
                                          │ политика подтверждений (токены)       │
                                          └───┬───────────────┬──────────────┬────┘
                                              ▼               ▼              ▼
                                     [MailConnector]       [LLM]       [Хранилище]
                                      READ/DRAFT/MUTATE   (интерфейс)   Postgres
                                              │
                                        [MailAuth] ──▶ o2.mail.ru / imap.mail.ru:993
```

Ядро не импортирует ничего про мессенджер; адаптер не знает про сценарии. Исходящие соединения только к `api.telegram.org`, Mail (OAuth + IMAP) и LLM (allowlist, T15).

## Структура кода (`src/`)
```
src/mailagent/
  api.py            FastAPI: /webhook/telegram, /oauth/callback, /health
  adapters/
    base.py         MessengerAdapter (Protocol), нейтральные события
    telegram.py     реализация Telegram Bot API (httpx)
  core/
    agent.py        цикл запроса: контекст → шлюз → LLM → фильтр → ответ
    scenarios.py    сводка, поиск, пересказ, «требуют ответа», черновик
    guard.py        шлюз по suspicious + правила (§5.1 п. 1, 4)
    outfilter.py    фильтр вывода (из spikes/llm/outfilter.py)
    confirm.py      токены подтверждения
    llm.py          LLM (Protocol) + OpenAI-совместимый клиент
  mail/
    auth.py         MailAuth: PKCE, обмен, refresh
    connector.py    MailConnector: READ / DRAFT / MUTATE
  store/
    db.py, models.py, crypto.py (AES-GCM)
tests/
  security/         инъекции (cases.py inj_*), replay подтверждения, поддельный webhook
```

## Интерфейсы

```python
# adapters/base.py: адаптер мессенджера, 3 метода (AGENTS.md)
class MessengerAdapter(Protocol):
    def parse_event(self, headers: Mapping, body: bytes) -> Event | None:  # проверка подписи внутри
    async def send(self, chat: ChatRef, text: str, buttons: list[Button] | None = None) -> None
    async def confirm(self, chat: ChatRef, prompt: str, token: str) -> None  # кнопки Да/Нет, payload=token

@dataclass
class Event:  # нейтральное событие
    event_id: str; channel: str; user_id: str; chat: ChatRef
    kind: Literal["text", "button", "started"]; text: str | None; payload: str | None
```

```python
# mail/auth.py
class MailAuth(Protocol):
    def start(self, channel: str, user_id: str) -> str          # ссылка OAuth, state=nonce, TTL 10 мин
    async def finish(self, state: str, code: str) -> MailAccount  # шифрует и сохраняет токены
    async def access_token(self, account_id: int) -> str       # refresh при истечении; ошибка → ReauthRequired
    async def disconnect(self, account_id: int) -> None         # удалить токены и данные

# mail/connector.py: операций SEND и DELETE нет (не написаны)
class MailConnector(Protocol):
    def list_folders(self) -> list[Folder]
    def search(self, q: SearchQuery) -> list[MessageMeta]
    def fetch(self, uid: int, folder: str) -> Message          # тело без вложений
    def thread(self, uid: int) -> list[Message]
    def append_draft(self, draft: Draft) -> int                # возвращает UID из APPENDUID
    def mark(self, uid: int, flag: Flag) -> None               # MUTATE, только с токеном (проверяет confirm)
```

`LLM`: `complete(system, user_blocks, schema: type[BaseModel]) -> BaseModel`. Ответ только в схеме; свободный текст из письма в промпт попадает отдельным блоком «недоверенные данные».

## Данные (PostgreSQL)

| Таблица | Поля | Заметки |
|---|---|---|
| `events` | `event_id` (PK), `received_at` | дедуп webhook; чистка > 7 дней |
| `accounts` | `id`, `channel`, `channel_user_id` (unique pair), `email`, `access_enc`, `refresh_enc`, `expires_at`, `created_at`, `push_enabled`, `push_time` | токены AES-GCM, ключ вне БД; один чат = один ящик |
| `oauth_states` | `state` (PK), `channel_user_id`, `expires_at`, `used` | nonce, TTL 10 мин, одноразовый |
| `confirmations` | `token` (PK), `account_id`, `action_hash`, `kind`, `payload_json`, `expires_at`, `used` | TTL 5 мин; payload — только метаданные действия (uid, папка, текст черновика) |
| `audit_log` | `ts`, `account_id`, `action`, `uid`, `result` | без тела и адресов, хранение 90 дней |

Тела писем, сводки и черновики на диск не пишутся (`02-security.md` §6). Исключение: текст черновика в `confirmations.payload_json` до нажатия кнопки или истечения TTL (5 мин), затем строка удаляется.

## Основные потоки

**Онбординг.** `started` → бот объясняет, что читается и куда уходит (LLM-провайдер), что агент не отправляет и не удаляет, как включить IMAP («Внешние сервисы» в настройках ящика), что ящики `vk.com` не поддерживаются → `MailAuth.start` → пользователь открывает ссылку (scope `openid email mail.imap offline_access`), `finish` по callback; при `bad redirect_uri` бот просит повторить → бот сообщает «подключён ящик X».

**Запрос (pull).** Событие `text` → роутер намерений → сценарий → `MailConnector` (ограниченное число писем) → `guard` (флаг `suspicious` модели ИЛИ правила): подозрительное письмо в сводку и черновик не идёт, пользователю предупреждение из метаданных → `LLM` по схеме → `outfilter` → ответ ≤ 4000 символов, длиннее режем на части ≤ 2 сообщений/с.

**Черновик.** Сценарий показывает текст в чате («проверьте перед отправкой») и создаёт `confirmation` (kind=`draft`, `action_hash` от uid + текста) → кнопки «Создать черновик / Отмена», payload = токен → `button`: проверить владельца, TTL, `used`, `action_hash` → `append_draft`, проверка по `APPENDUID` (не через `SEARCH`, он отстаёт после `APPEND`) → ответ. Текст подтверждения собирает код из метаданных.

**Push по подписке.** Включается только командой пользователя после его первого сообщения; планировщик (в процессе) по `push_time` опрашивает INBOX (нет `IDLE`), строит сводку тем же путём, что pull. Ошибка токена → одно сообщение «нужно повторно подключить ящик», дальше push выключается. Риск п. 1.5 принят (`04-mvp-scope.md`).

**Отключение.** `/disconnect` → `MailAuth.disconnect`, удаление токенов, подписки и confirmation. Отзыв в id.mail.ru даёт ошибку токена и тот же ответ пользователю.

## Ошибки и ограничения
- IMAP `AUTHENTICATIONFAILED`: IMAP не включён в ящике или токен отозван → инструкция + `ReauthRequired`.
- Лимит запросов на пользователя и на письмо/токены (T11), таймауты IMAP и LLM, вложения не читаются.
- Webhook отвечает 200 сразу; повторные доставки отсекаются по `events`. При старте процесса подписка (`setWebhook`) вызывается заново.
- Логи: id письма, тип действия, результат; без тел и адресов (T12).

## Деплой
Один контейнер приложения + PostgreSQL на VPS в РФ; обратный прокси с TLS (доверенный сертификат, порт 443); секреты (`MAIL_CLIENT_SECRET`, ключ AES, секрет webhook, токен бота) из env/secret-store. Проверить на целевом хостинге: исходящий IP не режется Mail на `imap.mail.ru:993` (находка 10 спайка). LLM: пока тест на Qwen3-14B через OpenAI-совместимый API; провайдер для боя выбирается отдельно (152-ФЗ).

## LLM-провайдер (предварительное решение 2026-10-01)
Требования: инфраструктура в РФ (письма содержат ПДн, `02-security.md` §7, T7); без логирования и обучения на запросах; OpenAI-совместимый API (интерфейс `LLM` не меняется); качество на нашем тесте не ниже Qwen3-14B (`07-llm-scenario-test.md`); защита от инъекций от модели не зависит (§5.1).

**Основной: Cloud.ru Evolution Foundation Models.** Открытые модели на российских серверах, OpenAI-совместимый API, по заявлению Cloud.ru запросы не логируются и не используются для обучения (блог Cloud.ru «ИИ и 152-ФЗ», 2026-08-07; это слова вендора, не договор). Прайс каталога на 2026-10-01 (за 1 млн токенов, вход/выход): Qwen3-30B-A3B 16 / 65 ₽, Qwen3-32B 43 / 173 ₽, Qwen3-235B-A22B 120 / 478 ₽, контекст Qwen3-30B/32B — 40К. Оценка при ~0,5 млн токенов на активного пользователя в месяц (80% вход): ≈ 13 ₽ (30B-A3B) и ≈ 35 ₽ (32B) — на порядок ниже GigaChat Pro/YandexGPT Pro из `01-product.md` §6.

**Запасной:** Yandex AI Studio (в документации: данные не используются для обучения, если отключено логирование запросов; хранение по российскому законодательству) или своя модель на арендованном GPU (дороже при малой нагрузке, `06-economics.xlsx`). GigaChat API не берём основным: соглашение для физлиц, условия по данным запросов не проверены.

**Модель выбирается после прогона** `spikes/llm/run.py` на Qwen3-30B-A3B и Qwen3-32B через Cloud.ru (Qwen3-14B в каталоге нет): решения ≥ 0.9 и инъекции в черновике не хуже, чем на 14B. Нужен ключ `CLOUDRU_API_KEY` в `.env` (в чат не присылать); `run.py` пока умеет только OpenRouter (`or:`), потребуется ветка под base URL Cloud.ru.

**Своё железо (рассматривали в `01-product.md` §6 и `06-economics.xlsx` только как аренду GPU; покупку не считали).** Для MVP и пилота (5–10 пользователей) API дешевле на порядки: месяц пилота на API — единицы–сотни рублей против 35–80 тыс. ₽/мес за GPU. Точка безубыточности по цифрам выше: A100 80 ГБ за 80 тыс. ₽/мес равна API на Qwen3-32B (≈ 35 ₽/пользователь) при ≈ 2 300 активных пользователях, RTX 4090 за 35 тыс. ₽/мес — при ≈ 1 000 (если влезает модель нужного качества). Переход имеет смысл при устойчивой нагрузке такого порядка или если юрист/Mail (Прав. 1.3, передача третьим лицам) потребуют отсутствия внешнего провайдера. Интерфейс `LLM` позволяет переключиться без правок ядра. Цены покупки серверов и размещения (colocation) в РФ не проверены.

**До запуска на реальных пользователях:** прочитать договор/оферту Cloud.ru (роль оператора, поручение обработки ПДн, логирование, субподрядчики), вписать провайдера в согласие и политику ПДн; вопрос юристу по 152-ФЗ остаётся открытым.

## Открыто
- Подтверждение провайдера: прогон теста на Cloud.ru и чтение договора (см. выше).
- Хостинг и проверка IP для `imap.mail.ru`.
- Роутер намерений: правила или вызов LLM (решить при реализации сценариев; в любом случае LLM не выбирает права).
- Понадобится ли очередь после пилота.
