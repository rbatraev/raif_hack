# ruff: noqa: RUF002
"""LLM-клиент и детектор red flags."""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import typing

import httpx

from app.prompts import build_system_prompt, build_user_prompt, load_categories

OPENROUTER_MODEL = "google/gemini-2.5-flash"
_REQUEST_TIMEOUT = 3.0
_HIGH_CONFIDENCE_THRESHOLD = 0.85
_PARALLEL_MODELS = [
    "google/gemini-2.5-flash",
    "openai/gpt-4o-mini",
    "anthropic/claude-haiku-4-5-20251001",
    "google/gemini-3.5-flash",
]

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
) -> list[dict[str, typing.Any]]:
    """Детектирует red flags через один LLM-вызов (используется в тестах).

    Возвращает список словарей вида {"category": str, "confidence": float, "evidence": str}.
    При ошибке LLM или парсинга возвращает пустой список.
    """
    raw_response = llm_client.request_completion(
        build_system_prompt(load_categories()),
        build_user_prompt(messages),
        json_mode=True,
    )
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


async def _fetch_model_flags(
    openrouter_key: str,
    model_name: str,
    system_prompt: str,
    user_content: str,
) -> list[dict[str, typing.Any]] | None:
    """Вызывает одну модель и возвращает распарсенный список флагов или None при ошибке."""
    request_payload: dict[str, typing.Any] = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
        "response_format": {"type": "json_object"},
    }
    try:
        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as http_client:
            api_response = await http_client.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {openrouter_key}",
                    "Content-Type": "application/json",
                },
                json=request_payload,
            )
            parsed_data: dict[str, typing.Any] = json.loads(
                str(api_response.json()["choices"][0]["message"]["content"])
            )
            return [
                one_flag
                for one_flag in parsed_data.get("flags", [])
                if isinstance(one_flag, dict) and "category" in one_flag
            ]
    except Exception:  # noqa: BLE001
        _logger.debug("Model %s failed", model_name)
        return None


def _extract_confidence(flag_dict: dict[str, typing.Any] | None) -> float:
    """Извлекает значение confidence из флага, возвращает -1.0 если флаг None."""
    if flag_dict is None:
        return -1.0
    return float(flag_dict.get("confidence", 0))


def _check_confidence(flag_list: list[dict[str, typing.Any]]) -> bool:
    """Возвращает True если ответ уверенный: нет флагов или все флаги с confidence >= порога."""
    if not flag_list:
        return True
    return all(float(one_flag.get("confidence", 0)) >= _HIGH_CONFIDENCE_THRESHOLD for one_flag in flag_list)


def _merge_by_majority(
    result_list: list[list[dict[str, typing.Any]]],
) -> list[dict[str, typing.Any]]:
    """Объединяет ответы нескольких моделей: оставляет флаги, поддержанные большинством."""
    if not result_list:
        return []
    if len(result_list) == 1:
        return result_list[0]

    majority_count = math.ceil(len(result_list) / 2)
    category_votes: dict[str, int] = {}
    category_best_flag: dict[str, dict[str, typing.Any]] = {}

    for one_result in result_list:
        seen_category_ids: set[str] = set()
        for one_flag in one_result:
            category_id = str(one_flag.get("category", ""))
            if not category_id or category_id in seen_category_ids:
                continue
            seen_category_ids.add(category_id)
            category_votes[category_id] = category_votes.get(category_id, 0) + 1
            if float(one_flag.get("confidence", 0)) > _extract_confidence(category_best_flag.get(category_id)):
                category_best_flag[category_id] = one_flag

    return [
        category_best_flag[category_id]
        for category_id, vote_count in category_votes.items()
        if vote_count >= majority_count
    ]


async def run_parallel_detection(openrouter_key: str, messages: str) -> list[dict[str, typing.Any]]:
    """Детектирует red flags параллельным запросом к нескольким моделям.

    Логика:
    - Запускает все модели одновременно с таймаутом 3 сек.
    - Если модель вернула уверенный ответ (confidence >= 0.85 для всех флагов) —
      сразу возвращает его, отменяя остальные запросы.
    - Если ни одна модель не дала уверенного ответа до таймаута —
      возвращает флаги, поддержанные большинством ответивших моделей.
    """
    if not openrouter_key:
        return []

    system_prompt = build_system_prompt(load_categories())
    user_content = build_user_prompt(messages)

    event_loop = asyncio.get_event_loop()
    deadline_time = event_loop.time() + _REQUEST_TIMEOUT

    pending_tasks: set[asyncio.Task[list[dict[str, typing.Any]] | None]] = {
        asyncio.create_task(_fetch_model_flags(openrouter_key, one_model, system_prompt, user_content))
        for one_model in _PARALLEL_MODELS
    }

    completed_results: list[list[dict[str, typing.Any]]] = []

    while pending_tasks:
        remaining_time = deadline_time - event_loop.time()
        if remaining_time <= 0:
            break

        done_tasks, pending_tasks = await asyncio.wait(
            pending_tasks, timeout=remaining_time, return_when=asyncio.FIRST_COMPLETED
        )

        for one_task in done_tasks:
            try:
                task_result = one_task.result()
            except Exception:  # noqa: BLE001, S112
                continue
            if task_result is None:
                continue
            completed_results.append(task_result)
            if _check_confidence(task_result):
                _logger.info("Early return: confident answer received, cancelling %d pending", len(pending_tasks))
                for one_pending_task in pending_tasks:
                    one_pending_task.cancel()
                return task_result

    for one_pending_task in pending_tasks:
        one_pending_task.cancel()

    _logger.info("Aggregating results from %d/%d models", len(completed_results), len(_PARALLEL_MODELS))
    return _merge_by_majority(completed_results)


def load_llm() -> LLMClient:
    """Создаёт LLM-клиент при старте приложения."""
    return LLMClient()
