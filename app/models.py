"""LLM-клиент и заглушка детектора red flags."""

from __future__ import annotations

import os
import random
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


_DEMO_ANSWERS_QUEUE: list[str] = [
    "policy_manipulation",
    "identity_deception",
    "transaction_coercion",
    "information_extraction",
    "adversarial_attack",
    "clean",
]


def process_risk_detection(
    llm_client: LLMClient,  # noqa: ARG001
    messages: str,  # noqa: ARG001
) -> dict[str, typing.Any] | None:
    """Демо-заглушка: случайная категория из списка."""
    if not _DEMO_ANSWERS_QUEUE:
        return None
    result_category = random.choice(_DEMO_ANSWERS_QUEUE)  # noqa: S311

    if result_category == "clean":
        return None
    return {"category": result_category}


def load_llm() -> LLMClient:
    """Создаёт LLM-клиент при старте приложения."""
    return LLMClient()
