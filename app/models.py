"""LLM-клиент и детектор red flags."""

from __future__ import annotations

import json
import logging
import os
import pathlib
import typing

import httpx

OPENROUTER_MODEL = "google/gemini-2.5-flash"
_REQUEST_TIMEOUT = 120.0

_VALID_CATEGORIES = frozenset(
    [
        "policy_manipulation",
        "adversarial_attack",
        "identity_deception",
        "transaction_coercion",
        "information_extraction",
        "scope_violation",
    ]
)

_logger = logging.getLogger(__name__)

_PROMPT_PATH = pathlib.Path(__file__).parent.parent / "prompt_gemini.md"


def _load_system_prompt() -> str:
    """Загружает системный промпт из prompt_gemini.md (содержимое первого code-блока)."""
    prompt_text = _PROMPT_PATH.read_text(encoding="utf-8")
    # Системная инструкция находится внутри первого ``` блока
    first_fence = prompt_text.find("```\n")
    if first_fence == -1:
        return prompt_text
    content_start = first_fence + 4
    closing_fence = prompt_text.find("\n```", content_start)
    if closing_fence == -1:
        return prompt_text[content_start:]
    return prompt_text[content_start:closing_fence].strip()


def _remove_json_fence(raw_response: str) -> str:
    stripped_response = raw_response.strip()
    if stripped_response.startswith("```"):
        stripped_response = stripped_response.removeprefix("```json").removeprefix("```").strip()
        stripped_response = stripped_response.removesuffix("```").strip()
    return stripped_response


def _parse_llm_response(raw_response: str) -> list[dict[str, typing.Any]] | None:
    """Парсит ответ LLM.

    Поддерживает форматы:
    - {"red_flags": ["category1", ...], "reasoning": "..."}  (prompt_gemini.md)
    - {"flags": [{"category": "...", ...}]}                   (старый формат)
    - [{"session_id": "...", "flags": [...]}]                 (batch формат)
    """
    cleaned_response = _remove_json_fence(raw_response)

    parsed_json: typing.Any = None
    try:
        parsed_json = json.loads(cleaned_response)
    except json.JSONDecodeError:
        for one_start_char, one_end_char in [("{", "}"), ("[", "]")]:
            start_index = cleaned_response.find(one_start_char)
            end_index = cleaned_response.rfind(one_end_char)
            if start_index != -1 and end_index != -1 and start_index < end_index:
                try:
                    parsed_json = json.loads(cleaned_response[start_index : end_index + 1])
                    break
                except json.JSONDecodeError:
                    continue
        if parsed_json is None:
            return None

    if not isinstance(parsed_json, dict | list):
        return None
    return _extract_flags_from_parsed(parsed_json)


def _extract_flags_from_parsed(parsed_json: dict[str, typing.Any] | list[typing.Any]) -> list[dict[str, typing.Any]]:
    """Extract flag dicts from parsed LLM JSON response."""
    if isinstance(parsed_json, list):
        if parsed_json and isinstance(parsed_json[0], dict):
            return _extract_flags_from_parsed(parsed_json[0])
        return []

    # Формат prompt_gemini.md: {"red_flags": ["category1", ...]}
    raw_red_flags = parsed_json.get("red_flags")
    if isinstance(raw_red_flags, list):
        return [{"category": one_item} if isinstance(one_item, str) else one_item for one_item in raw_red_flags]

    # Object format: {"flags": [{"category": "...", ...}]}
    raw_flags = parsed_json.get("flags")
    if isinstance(raw_flags, list):
        return raw_flags

    return []


def _build_normalized_flags(
    raw_flags: list[dict[str, typing.Any]] | None,
    *,
    flag_source: str,
) -> list[dict[str, typing.Any]]:
    if not raw_flags:
        return []

    normalized_result: list[dict[str, typing.Any]] = []
    seen_categories: set[str] = set()
    for one_flag in raw_flags:
        if not isinstance(one_flag, dict):
            continue
        category = str(one_flag.get("category", "")).strip()
        if category not in _VALID_CATEGORIES or category in seen_categories:
            if category and category not in _VALID_CATEGORIES:
                _logger.info("Dropping unknown category=%s", category)
            continue
        seen_categories.add(category)

        correct_probability = float(one_flag.get("correct_probability", one_flag.get("confidence", 1.0)))
        is_obvious = bool(one_flag.get("is_obvious", True))

        normalized_result.append(
            {
                "category": category,
                "confidence": correct_probability,
                "correct_probability": correct_probability,
                "is_obvious": is_obvious,
                "source": flag_source,
            }
        )

    return normalized_result


@typing.final
class LLMClient:
    """chat-completions via OpenRouter."""

    def __init__(self) -> None:
        self.api_key = os.getenv("OPENROUTER_API_KEY", "")
        self.system_prompt = _load_system_prompt()

    def request_completion(
        self,
        system_prompt: str,
        user_content: str,
        *,
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


def process_risk_detection(
    llm_client: LLMClient,
    messages: str,
    session_id: str,
) -> tuple[list[dict[str, typing.Any]], str]:
    """Детектирует red flags через LLM-анализ диалога."""
    user_content = f"Классифицируй следующий диалог:\n\nsession_id: {session_id}\n\n{messages}"

    raw_response = llm_client.request_completion(
        llm_client.system_prompt,
        user_content,
    )

    if raw_response is None:
        _logger.warning("LLM returned no response for session=%s", session_id)
        return [], "llm_error"

    parsed_flags = _parse_llm_response(raw_response)
    if parsed_flags is None:
        _logger.warning("Failed to parse LLM response for session=%s: %.500s", session_id, raw_response)
        return [], "llm_parse_error"

    return _build_normalized_flags(parsed_flags, flag_source="llm"), "llm"


def load_llm() -> LLMClient:
    """Создаёт LLM-клиент при старте приложения."""
    return LLMClient()
