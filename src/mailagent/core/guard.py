"""Шлюз по suspicious (02-security §5.1 п. 1 и 4): флаг = модель ИЛИ правила.

Подозрительное письмо не идёт в сводку и черновик; пользователю — предупреждение из метаданных,
собранное кодом (текст модели в него не попадает)."""
import logging
import re

log = logging.getLogger("mailagent")

# Слабая мера: обходится перефразированием, но дёшево и не зависит от модели.
RULES = re.compile("|".join([  # noqa: FLY002
    r"игнорир\w*\s+(?:все\s+|всё\s+)?(?:предыдущ|прежн|вышеуказан)\w*\s+(?:инструкц|указани|правил)",
    r"ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above)\s+(?:instructions|rules|prompts?)",
    r"(?:ии|ai|llm|gpt)[\s-]*(?:ассистент|помощник|агент|assistant)\w*\s*[,:]",
    r"\b(?:ассистент\w*|assistant|ии|ai)\s*[,:]\s*(?:перешли|удали|отправь|ответь|forward|delete|send|reply|set|write)",
    r"(?:ассистенту|помощнику|агенту)\s+(?:ии|почты)",
    r"к\s+ии[\s-]*помощнику",
    r"(?<!\w)(?:ии|ai)\s*,\s*(?:при|обязательно|пожалуйста|напиши|скажи|сделай)",
    r"\[\s*system\s*\]|<\s*system\s*>",
    r"\bDAN\b|без\s+ограничени\w+\s+ии|jailbreak",
    r"you\s+are\s+now\b",
    r"не\s+(?:говори|сообщай)\s+пользователю|do\s+not\s+tell\s+the\s+user",
]), re.IGNORECASE)


def rule_flag(text: str) -> bool:
    return bool(RULES.search(text))


def is_suspicious(model_flag: bool, text: str) -> bool:
    rule = rule_flag(text)
    if model_flag or rule:  # источник флага для отладки ложных срабатываний; без текста письма
        log.info("guard flag model=%s rule=%s", model_flag, rule)
    return model_flag or rule


def warning(sender: str, subject: str) -> str:
    """Только метаданные; кнопка «Показать текст письма» — в сценарии."""
    return (f"⚠️ Письмо от {sender} («{subject}») похоже на попытку обмана или управления ассистентом. "
            "Я не стал его пересказывать и писать ответ.")
