"""Spike 0: OAuth Mail (PKCE) -> IMAP XOAUTH2 -> LIST -> чтение -> APPEND черновика.

Только stdlib. Токены нигде не сохраняются и не печатаются.
Запуск: python spike.py  (из папки spikes/mail, .env лежит в корне проекта)
"""
import base64, hashlib, imaplib, json, os, re, secrets, sys, threading, time, urllib.parse, urllib.request, webbrowser
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
report = []


def log(step, ok, detail=""):
    report.append((step, ok, detail))
    print(f"[{'OK' if ok else 'FAIL'}] {step}" + (f": {detail}" if detail else ""))


def load_env():
    env = dict(os.environ)
    p = ROOT / ".env"
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                env.setdefault(k.strip(), v.strip().strip('"'))
    return env


env = load_env()
CLIENT_ID = env.get("MAIL_CLIENT_ID")
CLIENT_SECRET = env.get("MAIL_CLIENT_SECRET", "")
REDIRECT = env.get("MAIL_REDIRECT", "http://localhost:8899/callback/")
SCOPE = env.get("MAIL_SCOPE", "openid email mail.imap offline_access")  # без profile: минимум ПДн
if not CLIENT_ID:
    sys.exit("Нет MAIL_CLIENT_ID в .env (см. .env.example)")


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# 1. PKCE + получение кода
verifier = b64url(secrets.token_bytes(48))
challenge = b64url(hashlib.sha256(verifier.encode()).digest())
state = secrets.token_urlsafe(32)  # Mail требует 256 бит
got = {}


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        got.update({k: v[0] for k, v in q.items()})
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write("Готово, можно закрыть вкладку.".encode())

    def log_message(self, *a):
        pass


u = urllib.parse.urlparse(REDIRECT)
srv = HTTPServer((u.hostname, u.port or 80), H)
threading.Thread(target=srv.handle_request, daemon=True).start()
auth_url = "https://oauth.mail.ru/login?" + urllib.parse.urlencode({
    "response_type": "code", "client_id": CLIENT_ID, "scope": SCOPE, "prompt": "consent",
    "redirect_uri": REDIRECT, "state": state,
    "code_challenge": challenge, "code_challenge_method": "S256",
})
print("Открываю браузер. Если не открылся, перейди по ссылке:\n", auth_url)
webbrowser.open(auth_url)
for _ in range(300):
    if got:
        break
    time.sleep(1)
if not got.get("code") or got.get("state") != state:
    log("Авторизация", False, f"нет code или state не совпал: {sorted(got)} {got.get('error', '')} {got.get('error_description', '')}")
    sys.exit(1)
log("Авторизация: получен code, state совпал", True)

# 2. Обмен кода на токены
basic = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
req = urllib.request.Request(
    "https://oauth.mail.ru/token",
    data=urllib.parse.urlencode({
        "grant_type": "authorization_code", "code": got["code"],
        "code_verifier": verifier, "redirect_uri": REDIRECT,
    }).encode(),
    headers={"Content-Type": "application/x-www-form-urlencoded", "Authorization": f"Basic {basic}"},
)
try:
    tok = json.load(urllib.request.urlopen(req, timeout=30))
except Exception as e:
    body = getattr(e, "read", lambda: b"")().decode(errors="replace")
    log("Обмен кода на токен", False, f"{e} {body[:300]}")
    sys.exit(1)
access = tok["access_token"]
log("Токен получен", True,
    f"expires_in={tok.get('expires_in')}, scope='{tok.get('scope')}', refresh_token={'есть' if tok.get('refresh_token') else 'НЕТ'}")

# 2b. Обновление токена: дальше IMAP идёт уже с новым access, это доказывает, что refresh рабочий
access_refreshed = None
if tok.get("refresh_token"):
    rreq = urllib.request.Request(
        "https://oauth.mail.ru/token",
        data=urllib.parse.urlencode({"grant_type": "refresh_token", "refresh_token": tok["refresh_token"]}).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded", "Authorization": f"Basic {basic}"},
    )
    try:
        rt = json.load(urllib.request.urlopen(rreq, timeout=30))
        log("Refresh токена", True,
            f"expires_in={rt.get('expires_in')}, access изменился={rt['access_token'] != access}, "
            f"refresh_token вернулся={'да' if rt.get('refresh_token') else 'нет'}, "
            f"ротация={'да' if rt.get('refresh_token') and rt['refresh_token'] != tok['refresh_token'] else 'нет'}")
        access_refreshed = rt["access_token"]
    except Exception as e:
        body = getattr(e, "read", lambda: b"")().decode(errors="replace")
        log("Refresh токена", False, f"{e} {body[:300]}")

# 3. Адрес ящика
email_addr = env.get("MAIL_ADDRESS")
if not email_addr:
    try:
        r = urllib.request.Request("https://oauth.mail.ru/api/v1/oidc/userinfo", data=b"",
                                   headers={"Authorization": f"Bearer {access}"})
        email_addr = json.load(urllib.request.urlopen(r, timeout=30)).get("email")
    except Exception as e:
        log("userinfo", False, str(e))
if not email_addr:
    sys.exit("Не удалось определить адрес. Задай MAIL_ADDRESS в .env")
log("Адрес ящика определён", True, re.sub(r"^(.).*(@.*)$", r"\1***\2", email_addr))

# 4. IMAP XOAUTH2
M = None
for label, tk in (("исходный access", access), ("access после refresh", access_refreshed)):
    if not tk:
        continue
    conn = imaplib.IMAP4_SSL("imap.mail.ru", 993)
    xo = f"user={email_addr}\x01auth=Bearer {tk}\x01\x01".encode()
    try:
        typ, _ = conn.authenticate("XOAUTH2", lambda _: xo)
        log(f"IMAP XOAUTH2 ({label})", typ == "OK")
        M = conn
        break
    except Exception as e:
        log(f"IMAP XOAUTH2 ({label})", False, str(e))
if not M:
    print("\n=== ИТОГ ===")
    for s, ok, d in report:
        print(("OK  " if ok else "FAIL"), s, "|", d)
    sys.exit(1)
log("CAPABILITY", True, " ".join(M.capabilities))

# 5. LIST
typ, folders = M.list()
names = []
drafts = None
for f in folders:
    s = f.decode(errors="replace")
    print("   ", s)
    m = re.match(r'\((.*?)\) "(.*?)" (.*)$', s)
    if m:
        name = m.group(3).strip('"')
        names.append(name)
        if "\\Drafts" in m.group(1):
            drafts = name
log("LIST", typ == "OK", f"{len(names)} папок; \\Drafts по атрибуту: {drafts}")
if not drafts:
    drafts = next((n for n in names if n.lower() in ("черновики", "drafts")), None)
    log("Папка черновиков по имени", bool(drafts), str(drafts))

# 6. Чтение INBOX (только чтение, BODY.PEEK)
typ, _ = M.select("INBOX", readonly=True)
typ, data = M.uid("SEARCH", None, "ALL")
uids = data[0].split()
log("INBOX SELECT(readonly)/SEARCH", typ == "OK", f"{len(uids)} писем")
for uid in uids[-12:]:
    typ, d = M.uid("FETCH", uid, "(BODY.PEEK[HEADER.FIELDS (SUBJECT FROM)])")
    raw = d[0][1].decode(errors="replace") if d and d[0] else ""
    subj = re.search(r"^Subject:\s*(.*)$", raw, re.M | re.I)
    subj = str(make_header(decode_header(subj.group(1)))) if subj else "?"
    print(f"    uid {uid.decode()}: {subj[:70]}")
log("FETCH заголовков (BODY.PEEK)", True, "кодировка темы разобрана выше")

# 7. APPEND черновика
if drafts:
    marker = f"SPIKE-DRAFT-{secrets.token_hex(3)}"
    msg = EmailMessage()
    msg["From"] = email_addr
    msg["To"] = email_addr
    msg["Subject"] = f"{marker} черновик от агента"
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()
    msg.set_content("Тестовый черновик из spike. Не отправлять.")
    try:
        typ, resp = M.append(f'"{drafts}"' if " " in drafts else drafts, "\\Draft",
                             imaplib.Time2Internaldate(time.time()), msg.as_bytes())
        log("APPEND в черновики", typ == "OK", str(resp))
        typ, _ = M.select(f'"{drafts}"' if " " in drafts else drafts, readonly=True)
        log("SELECT папки черновиков", typ == "OK", drafts)
        # Проверка по UID из APPENDUID (SEARCH у Mail может отставать от индекса)
        m_uid = re.search(rb"APPENDUID \d+ (\d+)", resp[0])
        fetched = ""
        if m_uid:
            typ, d = M.uid("FETCH", m_uid.group(1), "(FLAGS BODY.PEEK[HEADER.FIELDS (SUBJECT)])")
            fetched = " ".join(p.decode(errors="replace") for x in d for p in (x if isinstance(x, tuple) else (x,)) if isinstance(p, bytes))
        log("Черновик виден по IMAP (FETCH по UID)", marker in fetched, fetched.replace("\r\n", " ")[:120])
        time.sleep(3)
        typ, data = M.uid("SEARCH", None, "SUBJECT", marker)
        log("Черновик найден через SEARCH", bool(data[0].split()), f"маркер {marker}")
        print(f"\nПроверь в веб-интерфейсе Mail: в 'Черновики' должно быть письмо '{marker} ...'.")
    except Exception as e:
        log("APPEND в черновики", False, str(e))
else:
    log("APPEND", False, "папка черновиков не найдена")

M.logout()
print("\n=== ИТОГ (токены не выводились) ===")
for s, ok, d in report:
    print(("OK  " if ok else "FAIL"), s, "|", d)
