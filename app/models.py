# ruff: noqa: RUF002
"""LLM-клиент и детектор red flags.

Пайплайн детекции (precision-ориентированный, цель F1≈97%):
  1. self-consistency: N прогонов детектора с temperature>0, категория проходит
     по majority-голосованию (срезает случайные ложноположительные срабатывания);
  2. покатегорийные пороги confidence (CATEGORY_THRESHOLDS) — фильтр пограничных флагов;
  3. verifier-проход: каждый выживший флаг отдельным вызовом пытаемся опровергнуть (keep/drop).

Все «дорогие» этапы конфигурируются через env и по умолчанию вырождаются в один вызов
LLMClient.request_completion, чтобы контрактные тесты с MagicMock оставались зелёными.
"""

from __future__ import annotations

import json
import logging
import math
import os
import typing

import httpx

from app.prompts import (
    build_system_prompt,
    build_user_prompt,
    build_verifier_system_prompt,
    build_verifier_user_prompt,
    load_categories,
    threshold_for,
)

OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "google/gemini-2.5-flash")
_REQUEST_TIMEOUT = 60.0

# --- Конфигурация пайплайна (env) ---
# Число прогонов детектора для self-consistency. 1 = поведение как раньше (тесты).
_SELF_CONSISTENCY_RUNS = max(1, int(os.getenv("DETECTION_RUNS", "1")))
# Температура для прогонов self-consistency (>0 нужно, иначе прогоны идентичны).
_DETECTION_TEMPERATURE = float(os.getenv("DETECTION_TEMPERATURE", "0.0"))
# Доля прогонов, в которых должна встретиться категория, чтобы пройти голосование.
_VOTE_RATIO = float(os.getenv("VOTE_RATIO", "0.5"))
# Включить verifier-проход (второй LLM-вызов на каждый флаг).
_VERIFIER_ENABLED = os.getenv("VERIFIER_ENABLED", "0") == "1"

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
        temperature: float = 0.0,
        model: str | None = None,
    ) -> str | None:
        if not self.api_key:
            return None

        request_payload: dict[str, typing.Any] = {
            "model": model or OPENROUTER_MODEL,
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
        except Exception:  # noqa: BLE001
            return None


def _parse_flags(raw_response: str | None) -> list[dict[str, typing.Any]]:
    """Парсит ответ LLM в список флагов; при ошибке/None возвращает []."""
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


def _run_detection_once(
    llm_client: LLMClient,
    messages: str,
    *,
    temperature: float,
) -> list[dict[str, typing.Any]]:
    """Один прогон детектора."""
    raw_response = llm_client.request_completion(
        build_system_prompt(load_categories()),
        build_user_prompt(messages),
        json_mode=True,
        temperature=temperature,
    )
    return _parse_flags(raw_response)


def _vote(
    runs: list[list[dict[str, typing.Any]]],
) -> list[dict[str, typing.Any]]:
    """Majority-голосование по категориям между прогонами self-consistency.

    Категория проходит, если встретилась хотя бы в ceil(VOTE_RATIO * N) прогонах.
    confidence итогового флага = среднее по поддержавшим прогонам, evidence — от
    самого уверенного прогона.
    """
    total_runs = len(runs)
    if total_runs == 1:
        return runs[0]

    needed_votes = max(1, math.ceil(_VOTE_RATIO * total_runs))
    votes: dict[str, int] = {}
    confidences: dict[str, list[float]] = {}
    best_flag: dict[str, dict[str, typing.Any]] = {}

    for one_run in runs:
        seen: set[str] = set()
        for one_flag in one_run:
            category = str(one_flag.get("category", ""))
            if not category or category in seen:
                continue
            seen.add(category)
            confidence = float(one_flag.get("confidence", 0.0))
            votes[category] = votes.get(category, 0) + 1
            confidences.setdefault(category, []).append(confidence)
            if category not in best_flag or confidence > float(best_flag[category].get("confidence", 0.0)):
                best_flag[category] = one_flag

    merged: list[dict[str, typing.Any]] = []
    for category, vote_count in votes.items():
        if vote_count < needed_votes:
            continue
        flag = dict(best_flag[category])
        flag["confidence"] = sum(confidences[category]) / len(confidences[category])
        merged.append(flag)
    return merged


def _passes_threshold(flag: dict[str, typing.Any]) -> bool:
    """Проверяет покатегорийный порог confidence. Без confidence — пропускаем (consider true)."""
    if "confidence" not in flag:
        return True
    return float(flag.get("confidence", 0.0)) >= threshold_for(str(flag.get("category", "")))


def _verify_flag(
    llm_client: LLMClient,
    messages: str,
    flag: dict[str, typing.Any],
) -> bool:
    """Verifier-проход: True (keep), если флаг не опровергнут. На ошибке парсинга — keep."""
    raw = llm_client.request_completion(
        build_verifier_system_prompt(),
        build_verifier_user_prompt(
            str(flag.get("category", "")),
            str(flag.get("evidence", "")),
            messages,
        ),
        json_mode=True,
        temperature=0.0,
    )
    if raw is None:
        return True
    try:
        verdict = str(json.loads(raw).get("verdict", "keep")).lower()
    except (json.JSONDecodeError, TypeError, AttributeError):
        return True
    return verdict != "drop"


def process_risk_detection(
    llm_client: LLMClient,
    messages: str,
) -> list[dict[str, typing.Any]]:
    """Детектирует red flags в тексте диалога через LLM.

    Возвращает список словарей вида {"category": str, "confidence": float, ...}.
    При ошибке LLM или парсинга возвращает пустой список.

    Этапы (см. модульный docstring): self-consistency → пороги → verifier.
    По умолчанию (N=1, verifier off) делает ровно один вызов request_completion.
    """
    runs = [
        _run_detection_once(llm_client, messages, temperature=_DETECTION_TEMPERATURE)
        for _ in range(_SELF_CONSISTENCY_RUNS)
    ]

    voted = _vote(runs)
    filtered = [flag for flag in voted if _passes_threshold(flag)]

    if not _VERIFIER_ENABLED:
        return filtered

    return [flag for flag in filtered if _verify_flag(llm_client, messages, flag)]


def load_llm() -> LLMClient:
    """Создаёт LLM-клиент при старте приложения."""
    return LLMClient()
