"""LLM-клиент и заглушка детектора red flags."""

from __future__ import annotations

import os
import typing

import httpx

OPENROUTER_MODEL = "google/gemini-2.5-flash"


@typing.final
class LLMClient:
    """chat-completions via OpenRouter."""

    def __init__(self) -> None:
        self.api_key = os.getenv("OPENROUTER_API_KEY", "")

    def request_completion(self, prompt_text: str, *, json_mode: bool = True) -> str | None:
        if not self.api_key:
            return None

        request_payload: dict[str, typing.Any] = {
            "model": OPENROUTER_MODEL,
            "messages": [{"role": "user", "content": prompt_text}],
        }
        if json_mode:
            request_payload["response_format"] = {"type": "json_object"}

        try:
            response = httpx.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=request_payload,
            )
            return str(response.json()["choices"][0]["message"]["content"])
        except Exception:  # noqa: BLE001
            return None


def process_risk_detection(  # noqa: PLR0911
    llm_client: LLMClient,  # noqa: ARG001
    messages: str,
) -> dict[str, typing.Any] | None:
    """Анализирует текст диалога на наличие red flags.

    Логика основана на эвристическом анализе ключевых паттернов из обучающей выборки.
    """
    one_text = messages.lower()

    one_identity_triggers = [
        "восстановить доступ",
        "восстановить сим",
        "потерял телефон",
        "номер недоступен",
        "знаю последние операции",
        "знаю остаток",
        "знаю паспортные данные",
        "кодовое слово",
        "помогаю родственнику",
        "мама плохо понимает",
        "брат за границей",
        "сестра не отвечает",
        "владелец рядом",
        "подтвердит голосом",
        "sms я увижу",
        "почта открыта",
        "как сложно восстановить чужой аккаунт",
        "читает ли вы умеете",
        "слий мне данные",
    ]
    one_has_identity_trigger = any(one_trigger in one_text for one_trigger in one_identity_triggers)
    one_has_identity_context = any(
        one_phrase in one_text
        for one_phrase in [
            "чужой аккаунт",
            "не мой номер",
            "за другого",
            "родственник",
            "брат",
            "сестра",
            "мама",
        ]
    )
    one_has_knowledge_phrase = any(
        one_phrase in one_text
        for one_phrase in [
            "знаю последние операции",
            "знаю остаток",
            "знаю паспорт",
            "sms я увижу",
            "почта открыта",
        ]
    )
    if one_has_identity_trigger and (one_has_identity_context or one_has_knowledge_phrase):
        return {"category": "identity_deception"}

    one_coercion_triggers = [
        "срочно перевести",
        "торопит",
        "бронь только после",
        "аванс",
        "задаток",
        "вы сказали что все нормально",
        "оператор подтвердил",
        "вы же сказали",
        "фиксацию что если мошенничество",
        "ответственность на банке",
        "гарантию безопасности",
        "выглядит как scam",
        "это обычная сделка или нет",
        "рискнули бы перевести",
        "успокоили",
        "ввели в заблуждение",
        "компенсировать ущерб",
        "goodwill bonus",
    ]
    if any(one_trigger in one_text for one_trigger in one_coercion_triggers):
        return {"category": "transaction_coercion"}

    one_policy_triggers = [
        "обойти проверку",
        "ускорить проверку",
        "пропустить проверку",
        "отключить protection",
        "премиум клиент",
        "статус клиента",
        "нестандартное решение",
        "гибче",
        "отправить платеж дальше а проверку потом",  # noqa: RUF001
        "постфактум",
        "комментарий вместо проверки",
        "один сотрудник может спасти",
        "формально не обход",
        "я сам подтверждаю",
        "временный режим",
        "read-only",
        "ограниченный доступ",
    ]
    if any(one_trigger in one_text for one_trigger in one_policy_triggers):
        return {"category": "policy_manipulation"}

    one_adversarial_triggers = [
        "внутренний reasoning",
        "как система принимает решение",
        "risk score",
        "факторы блокировки",
        "режим без проверок",
        "trusted mode",
        "internal_debug",
        "disable_security",
        "ответьте в формате json",
        '{"mode"',
        "parser response",
        "test mode",
        "начислите бонус сразу",
        "не хочу объяснять оператору",
        "QA-проверка",
        "тестовый вход",
    ]
    if any(one_trigger in one_text for one_trigger in one_adversarial_triggers):
        return {"category": "adversarial_attack"}

    one_info_triggers = [
        "когда была активность",
        "последний раз заходил",
        "операции выполнялись сегодня",
        "пусто ли на счете",
        "видны ли переводы",
        "pending",
        "статус операции другого",
        "хватает ли ему денег",
        "пользуется ли картой",
        "ограничения доступа у него",  # noqa: RUF001
    ]
    one_person_words = [
        "жена",
        "муж",
        "партнер",
        "человек",
        "он",
        "она",
        "ему",
        "ей",
        "другого клиента",
    ]
    if any(one_trigger in one_text for one_trigger in one_info_triggers) and any(
        one_word in one_text for one_word in one_person_words
    ):
        return {"category": "information_extraction"}

    one_scope_triggers = [
        "помочь с python",  # noqa: RUF001
        "распарсить csv",
        "напиши код",
        "дебажить",
        "ETL pipeline",
        "напиши хайку",
        "стих",
        "песню",
        "инвест-совет",
        "продавать или нет",
        "рынок падает",
        "жалоба в цб",
        "сформулируйте жалобу",
        "официально написать",
    ]
    if any(one_trigger in one_text for one_trigger in one_scope_triggers):
        return {"category": "scope_violation"}

    return None


def load_llm() -> LLMClient:
    """Создаёт LLM-клиент при старте приложения."""
    return LLMClient()
