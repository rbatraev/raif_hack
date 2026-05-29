"""LLM-клиент и детектор red flags."""

from __future__ import annotations

import json
import logging
import os
import typing

import httpx

from app.prompts import build_prompt, load_categories

OPENROUTER_MODEL = "google/gemini-3.5-flash"

_logger = logging.getLogger(__name__)


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


def process_risk_detection(
    llm_client: LLMClient,
    messages: str,
) -> list[dict[str, typing.Any]]:
    """Детектирует red flags в тексте диалога через LLM.

    Возвращает список словарей вида {"category": str, "confidence": float, "evidence": str}.
    При ошибке LLM или парсинга возвращает пустой список.
    """
    prompt_text = build_prompt(load_categories(), messages)

    raw_response = llm_client.request_completion(prompt_text, json_mode=True)
    if raw_response is None:
        return []

    try:
        return [
            one_flag
            for one_flag in json.loads(raw_response).get("flags", [])
            if isinstance(one_flag, dict) and "category" in one_flag
        ]
    except (json.JSONDecodeError, TypeError, AttributeError):
        _logger.warning("Failed to parse LLM response: %.200s", raw_response)
        return []


def load_llm() -> LLMClient:
    """Создаёт LLM-клиент при старте приложения."""
    return LLMClient()
