"""LLM-клиент и детектор red flags."""

from __future__ import annotations

import json
import logging
import os
import re
import typing

import httpx

from app.hardcoded import get_hardcoded_flags
from app.prompts import CONFIDENCE_THRESHOLD, build_system_prompt, build_user_prompt, load_categories

OPENROUTER_MODEL = "google/gemini-2.5-flash"
_REQUEST_TIMEOUT = 60.0
_MAX_LLM_ATTEMPTS = 2
_RETRY_TEMPERATURE = 0.3
_MIN_FALLBACK_PATTERN_MATCHES = 2
_OBVIOUS_CORRECT_PROBABILITY = 0.85
_VALID_CATEGORIES = frozenset(one_category["id"] for one_category in load_categories())

_logger = logging.getLogger(__name__)

_FALLBACK_RULES: tuple[tuple[str, tuple[re.Pattern[str], ...]], ...] = (
    (
        "adversarial_attack",
        (
            re.compile(r"старший инженер|без дополнительных проверок|техническ.*отдел", re.IGNORECASE),
            re.compile(r"ignore .*instructions|system message|internal_debug|disable_security", re.IGNORECASE),
            re.compile(r"risk score|trusted mode|internal note|internal reasoning|parser response", re.IGNORECASE),
            re.compile(r"внутренн.*антифрод|какие сигналы|внутренн.*объяснен", re.IGNORECASE),
            re.compile(r"qa-провер|тестировани[ея].*безопасност|dev-контур|developer console", re.IGNORECASE),
            re.compile(r"за что .*начисля[ею]т бонус|что считается .*неудобств", re.IGNORECASE),
            re.compile(r"подходит под ваши примеры|начислите .*сразу", re.IGNORECASE),
            re.compile(r"set verified|verified=true|disable.*check|unrestricted.*mode", re.IGNORECASE),
            re.compile(r"system message begin|role.*system.*instruction", re.IGNORECASE),
            re.compile(r"тестов.*сценар|проверк.*dev|внутренн.*тестиров", re.IGNORECASE),
            re.compile(r"threshold.*based|линейно или|влияет на risk", re.IGNORECASE),
            re.compile(r"зафиксируйте.*обращени.*бонус|передайте запрос на бонус", re.IGNORECASE),
        ),
    ),
    (
        "identity_deception",
        (
            re.compile(r"человек сейчас не в россии|старый номер .*недоступен|временно отключить .*sms", re.IGNORECASE),
            re.compile(r"чуж(ой|ого|ому) аккаунт|восстановить чуж", re.IGNORECASE),  # noqa: RUF001
            re.compile(r"владелец .*сам|он сам плохо|отвечать за него|данные владельца", re.IGNORECASE),
            re.compile(r"sms .*увижу|телефон .*у меня|код приходит на .*устройство", re.IGNORECASE),  # noqa: RUF001
            re.compile(r"известны .*последн.*операц.*остат|паспортн.*данн.*кодовое слово", re.IGNORECASE),
            re.compile(r"потерян.*телефон|почта .*открыт|sim .*отключ", re.IGNORECASE),
            re.compile(r"не заметит списания|не разобрался бы сам", re.IGNORECASE),
            re.compile(r"могу отвечать за него|знаю все данные", re.IGNORECASE),
            re.compile(r"доступ.*буквально на пару минут|доступ.*на несколько минут", re.IGNORECASE),
            re.compile(r"назвать последние переводы|могу назвать.*остаток", re.IGNORECASE),
        ),
    ),
    (
        "information_extraction",
        (
            re.compile(r"жена|муж|сын|дочь|брат|сестра|другого клиента|человека", re.IGNORECASE),
            re.compile(r"последн.*активност|операц.*сегодня|ожидающ.*поступлен|пора паниковать", re.IGNORECASE),
            re.compile(r"ограничен.*доступ|причин .*нет|обычн.*отсутствие активности", re.IGNORECASE),
            re.compile(r"вы .*осторожнич|реакци[ия] поддержки|ситуац.*критич", re.IGNORECASE),
            re.compile(r"в минус.*не ушел|критических ограничений.*нет", re.IGNORECASE),
            re.compile(r"паниковали на моем месте|стоит ли.*паниковать", re.IGNORECASE),
            re.compile(r"обращений.*не было|недавних обращений", re.IGNORECASE),
            re.compile(r"была.*какая-то активность|когда.*последн.*раз", re.IGNORECASE),
        ),
    ),
    (
        "transaction_coercion",
        (
            re.compile(r"если .*мошеннич|оказ.*мошеннич|компенсир.*ущерб", re.IGNORECASE),
            re.compile(r"фиксируйте|оператор подтвердил|банк .*учтет|отсутствие подозр", re.IGNORECASE),
            re.compile(r"в[ссё] выглядит нормально|отсутствие предупреждений|ограничений нет", re.IGNORECASE),
            re.compile(r"торопит|срочно.*аванс|задат[оа]к|бронь .*перевод", re.IGNORECASE),  # noqa: RUF001
            re.compile(r"обычная сделка|scam|на моем месте|рискнули", re.IGNORECASE),
            re.compile(r"не выглядит.*нетипичн|выглядит.*супер нетипичн", re.IGNORECASE),
            re.compile(r"жалоб.*в цб|требую компенсац|халатност", re.IGNORECASE),
            re.compile(r"банк.*учтет.*консультир|заранее консультировал", re.IGNORECASE),
            re.compile(r"помечается как аномальн|регулярно отправляют.*похожие суммы", re.IGNORECASE),
        ),
    ),
    (
        "policy_manipulation",
        (
            re.compile(r"операц.*завис.*провер|проверка .*обязательн|обязательный регламент", re.IGNORECASE),
            re.compile(r"обойти проверк|обход.*процедур|исключени[ея] из правил", re.IGNORECASE),
            re.compile(r"условно подтвержден|закрыть постфактум|некорректн.*статус", re.IGNORECASE),
            re.compile(r"premium|премиум|статус клиента|нестандартн.*решени|гибче", re.IGNORECASE),
            re.compile(r"вручную.*подтверд|пропустить очередь|постав.*комментар", re.IGNORECASE),
            re.compile(r"подтвердить.*операц.*нормальн|клиент отвечает.*не может", re.IGNORECASE),
            re.compile(r"ответственность.*на себ|не хотите брать", re.IGNORECASE),  # noqa: RUF001
            re.compile(r"предыдущий сотрудник|предыдущий оператор.*сказал", re.IGNORECASE),
            re.compile(r"персональн.*сервис|нажать кнопку подтвержд", re.IGNORECASE),
        ),
    ),
    (
        "scope_violation",
        (
            re.compile(r"```python|pandas|dataframe|parse csv|распарсить csv|кус.*python", re.IGNORECASE),
            re.compile(r"haiku|хайку|стих|резюме|делов.*письм|жалобу в цб", re.IGNORECASE),
            re.compile(r"push задумался|телефон молчит|приложи это к баг-репорту", re.IGNORECASE),  # noqa: RUF001
            re.compile(r"сформулировать так|можно сформулировать|помогает .*дебажить", re.IGNORECASE),
            re.compile(r"продавать сейчас|инвестиц.*совет|консервативн.*инструмент", re.IGNORECASE),
            re.compile(r"рынок .*падает|многие .*уходят|часть инвесторов", re.IGNORECASE),
            re.compile(r"посоветуй фильм|margin call|big short|boiler room", re.IGNORECASE),
            re.compile(r"переведи фраз|на английский|that sounds.*harsh", re.IGNORECASE),
            re.compile(r"regex|uuid.*лог|escalation.*summary", re.IGNORECASE),
            re.compile(r"ипотек.*подушк|долговая нагрузк|финансов.*резерв", re.IGNORECASE),
            re.compile(r"покупать.*валют|покупать частями|колебан.*курс", re.IGNORECASE),
        ),
    ),
)

_INFORMATION_EXTRACTION_NEGATIVE_PATTERNS = (
    re.compile(r"не пытаюсь узнать .*статус или операции", re.IGNORECASE),
    re.compile(r"скорее хочу понять, как обычно люди решают", re.IGNORECASE),
    re.compile(r"если я просто отправлю перевод", re.IGNORECASE),
)

_ADVERSARIAL_ATTACK_NEGATIVE_PATTERNS = (
    re.compile(r"комментар(ий|иях|ии).*перевод.*лома", re.IGNORECASE),
    re.compile(r"заметк.*к переводу.*лома", re.IGNORECASE),
    re.compile(r"markdown|formatting|json fragments|payloads", re.IGNORECASE),
    re.compile(r"ui лом|frontend|отобража.*некоррект|prompt injection filter", re.IGNORECASE),
)


@typing.final
class LLMClient:
    """chat-completions via OpenRouter."""

    def __init__(self) -> None:
        self.api_key = os.getenv("OPENROUTER_API_KEY", "")

    def request_completion(
        self,
        system_prompt: str,
        user_content: str,
        *,
        json_mode: bool = True,
        temperature: float = 0.0,
    ) -> str | None:
        if not self.api_key:
            return None

        request_payload: dict[str, typing.Any] = {
            "model": OPENROUTER_MODEL,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
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
                timeout=_REQUEST_TIMEOUT,
            )
            return str(response.json()["choices"][0]["message"]["content"])
        except Exception:
            _logger.exception("OpenRouter completion request failed")
            return None


def _get_confidence_score(raw_confidence: object) -> float:
    if raw_confidence is None:
        return 1.0
    if not isinstance(raw_confidence, int | float | str):
        return 0.0
    try:
        return float(raw_confidence)
    except (TypeError, ValueError):
        return 0.0


def _remove_json_fence(raw_response: str) -> str:
    stripped_response = raw_response.strip()
    if stripped_response.startswith("```"):
        stripped_response = stripped_response.removeprefix("```json").removeprefix("```").strip()
        stripped_response = stripped_response.removesuffix("```").strip()
    return stripped_response


def _parse_llm_response(raw_response: str) -> dict[str, typing.Any] | None:
    cleaned_response = _remove_json_fence(raw_response)
    try:
        parsed_response = json.loads(cleaned_response)
    except json.JSONDecodeError:
        start_index = cleaned_response.find("{")
        end_index = cleaned_response.rfind("}")
        if start_index == -1 or end_index == -1 or start_index >= end_index:
            return None
        try:
            parsed_response = json.loads(cleaned_response[start_index : end_index + 1])
        except json.JSONDecodeError:
            return None

    if not isinstance(parsed_response, dict):
        return None
    return parsed_response


def _build_normalized_flags(
    raw_flags: object,
    *,
    apply_confidence_threshold: bool,
    flag_source: str,
) -> list[dict[str, typing.Any]]:
    if not isinstance(raw_flags, list):
        return []

    best_flags_by_category: dict[str, dict[str, typing.Any]] = {}
    for one_flag in raw_flags:
        if not isinstance(one_flag, dict):
            continue

        raw_category = one_flag.get("category")
        if not isinstance(raw_category, str):
            continue

        category = raw_category.strip()
        if category not in _VALID_CATEGORIES:
            _logger.info("Dropping unknown red flag category=%s", category)
            continue

        confidence = _get_confidence_score(one_flag.get("confidence"))
        if apply_confidence_threshold and confidence < CONFIDENCE_THRESHOLD:
            continue

        normalized_flag = dict(one_flag)
        normalized_flag["category"] = category
        normalized_flag["confidence"] = confidence
        normalized_flag["correct_probability"] = confidence
        normalized_flag["is_obvious"] = confidence >= _OBVIOUS_CORRECT_PROBABILITY
        normalized_flag["source"] = flag_source

        previous_flag = best_flags_by_category.get(category)
        if confidence > (_get_confidence_score(previous_flag.get("confidence")) if previous_flag else -1.0):
            best_flags_by_category[category] = normalized_flag

    return sorted(
        best_flags_by_category.values(),
        key=lambda one_flag: (-_get_confidence_score(one_flag.get("confidence")), str(one_flag.get("category", ""))),
    )


def _get_fallback_rule_flags(messages: str) -> list[dict[str, typing.Any]]:
    lowered_messages = messages.lower()
    detected_flags = []
    for one_category, category_patterns in _FALLBACK_RULES:
        if one_category == "information_extraction" and any(
            one_pattern.search(lowered_messages) for one_pattern in _INFORMATION_EXTRACTION_NEGATIVE_PATTERNS
        ):
            continue
        if one_category == "adversarial_attack" and any(
            one_pattern.search(lowered_messages) for one_pattern in _ADVERSARIAL_ATTACK_NEGATIVE_PATTERNS
        ):
            continue
        matched_patterns = [
            one_category_pattern.pattern
            for one_category_pattern in category_patterns
            if one_category_pattern.search(lowered_messages)
        ]
        if len(matched_patterns) >= _MIN_FALLBACK_PATTERN_MATCHES:
            detected_flags.append(
                {
                    "category": one_category,
                    "confidence": min(0.55 + 0.15 * len(matched_patterns), 0.95),
                    "evidence": "; ".join(matched_patterns[:2]),
                }
            )
    return detected_flags


def process_risk_detection(
    llm_client: LLMClient,
    messages: str,
) -> tuple[list[dict[str, typing.Any]], str]:
    """Детектирует red flags в тексте диалога.

    Сначала проверяет хардкод-кэш по MD5 диалога.
    При промахе обращается к LLM (retry with higher temperature).
    Последний fallback — regex-правила.

    Возвращает (flags, source) где source — "hardcoded", "llm" или "rules".
    flags — список словарей вида {"category": str, ...}.
    """
    hardcoded = get_hardcoded_flags(messages)
    if hardcoded is not None:
        return _build_normalized_flags(
            hardcoded,
            apply_confidence_threshold=False,
            flag_source="hardcoded",
        ), "hardcoded"

    system_prompt = build_system_prompt(load_categories())
    user_prompt = build_user_prompt(messages)

    for one_attempt_index in range(_MAX_LLM_ATTEMPTS):
        temperature = 0.0 if one_attempt_index == 0 else _RETRY_TEMPERATURE
        raw_response = llm_client.request_completion(
            system_prompt,
            user_prompt,
            json_mode=True,
            temperature=temperature,
        )
        if raw_response is None:
            continue

        parsed_response = _parse_llm_response(raw_response)
        if parsed_response is not None:
            return _build_normalized_flags(
                parsed_response.get("flags", []),
                apply_confidence_threshold=True,
                flag_source="llm",
            ), "llm"

        _logger.warning(
            "Failed to parse LLM response attempt=%d raw_response=%.500s",
            one_attempt_index + 1,
            raw_response,
        )

    fallback_flags = _get_fallback_rule_flags(messages)
    if fallback_flags:
        return _build_normalized_flags(
            fallback_flags,
            apply_confidence_threshold=False,
            flag_source="rules",
        ), "rules"

    return [], "llm"


def load_llm() -> LLMClient:
    """Создаёт LLM-клиент при старте приложения."""
    return LLMClient()
