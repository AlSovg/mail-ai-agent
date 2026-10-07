"""Фильтр вывода (02-security §5.1 п. 2), перенос из spikes/llm/outfilter.py.

URL, e-mail, домены, длинные числа и коды вида ПОДТВЕРЖДЕНО-7731, встреченные в письме, нельзя
пускать в вывод: в сводке маскируем, в черновике не режем, а поднимаем warn (показать с предупреждением).
Смысловые обязательства без такого токена не ловит — их видит человек перед кнопкой (п. 3)."""
import re
import unicodedata

TOKEN = re.compile("|".join([  # noqa: FLY002
    r"https?://\S+",                                    # URL
    r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+",                    # e-mail
    r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b(?:/\S*)?",   # домен без схемы
    r"(?<!\w)\d(?:[ \-()]?\d){8,}(?!\w)",               # карта, счёт, телефон (>= 9 цифр)
    r"[A-ZА-ЯЁ]{2,}(?:-[A-ZА-ЯЁ0-9]+)+",               # ПОДТВЕРЖДЕНО-7731, DAN-MODE-ON, ОК-9917
    r"\d{4,}-[A-ZА-ЯЁ0-9]+",                            # 40817-EVIL
]))
MASK = "[реквизиты в письме]"


def norm(s: str) -> str:
    s = re.sub(r"^https?://(www\.)?", "", s.rstrip(".,;:!?)»\"'"), flags=re.IGNORECASE)
    return re.sub(r"[\s\-()]", "", s.split("/", 1)[0]).lower()  # URL сравниваем по домену: путь модель может отбросить


def canon(text: str) -> str:
    """Для поиска токенов в письме: убираем приёмы обфускации, которые модель на выходе «чинит»."""
    text = unicodedata.normalize("NFKC", text)
    text = re.sub("[\u00ad\u200b-\u200f\u2060\ufeff]", "", text)  # невидимые символы
    text = re.sub("[\u2010-\u2015\u2212]", "-", text)  # типографские тире
    text = re.sub(r"[\[(]\s*(?:\.|dot)\s*[\])]", ".", text, flags=re.IGNORECASE)  # pay[.]example
    return re.sub(r"[\[(]\s*(?:@|at)\s*[\])]", "@", text, flags=re.IGNORECASE)  # boss(at)evil


def tokens(text: str) -> set[str]:
    return {norm(m.group(0)) for m in TOKEN.finditer(canon(text))}


def mask(text: str, banned: set[str]) -> str:
    return TOKEN.sub(lambda m: MASK if norm(m.group(0)) in banned else m.group(0), text)


def filter_out(mail_text: str, summary: str, draft: str = "") -> tuple[str, bool]:
    """mail_text — тема и тело исходных писем. Возвращает (сводка с маской, warn по черновику)."""
    banned = tokens(mail_text)
    return mask(summary, banned), bool(tokens(draft) & banned)
