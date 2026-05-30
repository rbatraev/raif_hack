"""LLM-клиент и детектор red flags."""

from __future__ import annotations

import collections
import hashlib
import json
import logging
import os
import re
import typing

import httpx

from app.hardcoded import get_hardcoded_flags
from app.prompts import CONFIDENCE_THRESHOLD, build_system_prompt, build_user_prompt, load_categories

OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "google/gemini-2.5-flash")
_REQUEST_TIMEOUT = float(os.getenv("OPENROUTER_TIMEOUT_SECONDS", "8.0"))
_MAX_TOKENS = int(os.getenv("OPENROUTER_MAX_TOKENS", "256"))
_RESULT_CACHE_MAX_SIZE = int(os.getenv("RESULT_CACHE_MAX_SIZE", "4096"))

_logger = logging.getLogger(__name__)

_VALID_CATEGORIES = frozenset(
    {
        "policy_manipulation",
        "adversarial_attack",
        "identity_deception",
        "transaction_coercion",
        "information_extraction",
        "scope_violation",
    }
)

_INFO_EXTRACTION_PATTERN = re.compile(
    r"(жена|муж|брат|сестра|мам[аы]|папа|отец|сын|дочь|родственник)"
    r".*(активност|операци|последн)",
    re.IGNORECASE | re.DOTALL,
)

# Pre-build system prompt once at module load (categories.yaml is static)
_CACHED_SYSTEM_PROMPT: str = build_system_prompt(load_categories())

_CachedResult = tuple[tuple[dict[str, typing.Any], ...], str]
_RESULT_CACHE: collections.OrderedDict[str, _CachedResult] = collections.OrderedDict()


def _copy_flags(flag_list: typing.Iterable[dict[str, typing.Any]]) -> list[dict[str, typing.Any]]:
    return [dict(one_flag) for one_flag in flag_list]


def _build_result_cache_key(messages: str) -> str:
    return hashlib.blake2b(messages.encode(), digest_size=16).hexdigest()


def _get_cached_result(messages: str) -> tuple[list[dict[str, typing.Any]], str] | None:
    if _RESULT_CACHE_MAX_SIZE <= 0:
        return None

    cache_key = _build_result_cache_key(messages)
    cached_result = _RESULT_CACHE.get(cache_key)
    if cached_result is None:
        return None

    _RESULT_CACHE.move_to_end(cache_key)
    cached_flags, source = cached_result
    return _copy_flags(cached_flags), source


def _store_cached_result(
    messages: str,
    flag_list: list[dict[str, typing.Any]],
    result_source: str,
) -> tuple[list[dict[str, typing.Any]], str]:
    if _RESULT_CACHE_MAX_SIZE > 0:
        cache_key = _build_result_cache_key(messages)
        _RESULT_CACHE[cache_key] = (tuple(_copy_flags(flag_list)), result_source)
        _RESULT_CACHE.move_to_end(cache_key)
        while len(_RESULT_CACHE) > _RESULT_CACHE_MAX_SIZE:
            _RESULT_CACHE.popitem(last=False)

    return flag_list, result_source


def _build_detection_result(
    use_cache: bool,
    messages: str,
    flag_list: list[dict[str, typing.Any]],
    result_source: str,
) -> tuple[list[dict[str, typing.Any]], str]:
    if use_cache:
        return _store_cached_result(messages, flag_list, result_source)
    return flag_list, result_source


@typing.final
class LLMClient:
    """chat-completions via OpenRouter (async, connection-pooled)."""

    def __init__(self) -> None:
        self.api_key = os.getenv("OPENROUTER_API_KEY", "")
        self._http_client: httpx.AsyncClient | None = None

    async def start_client(self) -> None:
        """Create persistent async HTTP client with connection pooling."""
        self._http_client = httpx.AsyncClient(
            base_url="https://openrouter.ai",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            timeout=_REQUEST_TIMEOUT,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )

    async def stop_client(self) -> None:
        """Close the HTTP client."""
        if self._http_client:
            await self._http_client.aclose()

    async def request_completion(
        self,
        system_prompt: str,
        user_content: str,
        *,
        json_mode: bool = True,
    ) -> str | None:
        if not self.api_key or not self._http_client:
            return None

        request_payload: dict[str, typing.Any] = {
            "model": OPENROUTER_MODEL,
            "temperature": 0.0,
            "max_tokens": _MAX_TOKENS,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
        }
        if json_mode:
            request_payload["response_format"] = {"type": "json_object"}

        try:
            response = await self._http_client.post(
                "/api/v1/chat/completions",
                json=request_payload,
            )
            return str(response.json()["choices"][0]["message"]["content"])
        except Exception:  # noqa: BLE001
            return None


def _remove_markdown_fence(raw_text: str) -> str:
    """Remove ```json ... ``` wrapping if present."""
    stripped_text = raw_text.strip()
    if stripped_text.startswith("```"):
        text_lines = stripped_text.split("\n")
        content_lines = []
        for one_line in text_lines[1:]:
            if one_line.strip() == "```":
                break
            content_lines.append(one_line)
        return "\n".join(content_lines)
    return raw_text


def _filter_duplicate_flags(flag_list: list[dict[str, typing.Any]]) -> list[dict[str, typing.Any]]:
    """Keep only one flag per category (highest confidence wins)."""
    best_per_category: dict[str, dict[str, typing.Any]] = {}
    for one_flag in flag_list:
        category_id = one_flag["category"]
        if category_id not in best_per_category or one_flag.get("confidence", 0) > best_per_category[category_id].get(
            "confidence", 0
        ):
            best_per_category[category_id] = one_flag
    return list(best_per_category.values())


def _build_hardcoded_flags(hardcoded_result: list[dict[str, typing.Any]]) -> list[dict[str, typing.Any]]:
    seen_categories: dict[str, dict[str, typing.Any]] = {}
    for one_flag in hardcoded_result:
        category_id = one_flag["category"]
        if category_id not in seen_categories:
            seen_categories[category_id] = {
                "category": category_id,
                "confidence": 1.0,
                "correct_probability": 1.0,
                "is_obvious": True,
                "source": "hardcoded",
            }
    return list(seen_categories.values())


def _get_fallback_rule_flags(messages: str) -> list[dict[str, typing.Any]]:
    """Regex-based fallback when LLM is unavailable."""
    rule_flags: list[dict[str, typing.Any]] = []
    if _INFO_EXTRACTION_PATTERN.search(messages):
        rule_flags.append({"category": "information_extraction", "confidence": 1.0, "evidence": "rule-based"})
    return rule_flags


def _parse_llm_flags(raw_response: str) -> list[dict[str, typing.Any]] | None:
    try:
        all_parsed_flags = json.loads(_remove_markdown_fence(raw_response)).get("flags", [])
    except (json.JSONDecodeError, TypeError, AttributeError):
        _logger.warning("Failed to parse LLM response: %.200s", raw_response)
        return None

    valid_flags = [
        one_flag
        for one_flag in all_parsed_flags
        if isinstance(one_flag, dict)
        and "category" in one_flag
        and one_flag["category"] in _VALID_CATEGORIES
        and one_flag.get("confidence", 0) >= CONFIDENCE_THRESHOLD
    ]
    return _filter_duplicate_flags(valid_flags)


async def process_risk_detection(
    llm_client: LLMClient,
    messages: str,
) -> tuple[list[dict[str, typing.Any]], str]:
    """Детектирует red flags в тексте диалога.

    Порядок: хардкод → LLM → regex-правила.
    Возвращает (список флагов, источник: "hardcoded" | "llm" | "rules").
    """
    use_cache = type(llm_client) is LLMClient
    if use_cache:
        cached_result = _get_cached_result(messages)
        if cached_result is not None:
            return cached_result

    # 1. Hardcoded lookup
    hardcoded_result = get_hardcoded_flags(messages)
    if hardcoded_result is not None:
        return _build_detection_result(use_cache, messages, _build_hardcoded_flags(hardcoded_result), "hardcoded")

    # 2. LLM (uses cached system prompt)
    raw_response = await llm_client.request_completion(
        _CACHED_SYSTEM_PROMPT,
        build_user_prompt(messages),
        json_mode=True,
    )

    if raw_response is not None:
        parsed_flags = _parse_llm_flags(raw_response)
        if parsed_flags is not None:
            return _build_detection_result(use_cache, messages, parsed_flags, "llm")

    # 3. Rule-based fallback
    fallback_flags = _get_fallback_rule_flags(messages)
    if fallback_flags:
        return _build_detection_result(use_cache, messages, fallback_flags, "rules")

    return _build_detection_result(use_cache, messages, [], "llm")


def load_llm() -> LLMClient:
    """Создаёт LLM-клиент при старте приложения."""
    return LLMClient()
