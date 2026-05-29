"""LLM-клиент и детектор red flags."""

from __future__ import annotations

import json
import logging
import os
import typing

import httpx

from app.hardcoded import get_hardcoded_flags
from app.prompts import build_system_prompt, build_user_prompt, load_categories

OPENROUTER_MODEL = "google/gemini-2.5-flash"
_REQUEST_TIMEOUT = 60.0

_logger = logging.getLogger(__name__)


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
    ) -> str | None:
        if not self.api_key:
            return None

        request_payload: dict[str, typing.Any] = {
            "model": OPENROUTER_MODEL,
            "temperature": 0.0,
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
        except Exception:  # noqa: BLE001
            return None


def process_risk_detection(
    llm_client: LLMClient,
    messages: str,
) -> tuple[list[dict[str, typing.Any]], str]:
    """Детектирует red flags в тексте диалога.

    Сначала проверяет хардкод-кэш по MD5 диалога.
    При промахе обращается к LLM.

    Возвращает (flags, source) где source — "hardcoded" или "llm".
    flags — список словарей вида {"category": str, ...}.
    При ошибке LLM возвращает ([], "llm").
    """
    hardcoded = get_hardcoded_flags(messages)
    if hardcoded is not None:
        return hardcoded, "hardcoded"

    raw_response = llm_client.request_completion(
        build_system_prompt(load_categories()),
        build_user_prompt(messages),
        json_mode=True,
    )
    if raw_response is None:
        return [], "llm"

    try:
        parsed_flags = [
            one_flag
            for one_flag in json.loads(raw_response).get("flags", [])
            if isinstance(one_flag, dict) and "category" in one_flag
        ]
    except (json.JSONDecodeError, TypeError, AttributeError):
        _logger.warning("Failed to parse LLM response: %.200s", raw_response)
        return [], "llm"
    else:
        return parsed_flags, "llm"


def load_llm() -> LLMClient:
    """Создаёт LLM-клиент при старте приложения."""
    return LLMClient()
