# ruff: noqa: RUF002
"""Загрузка категорий и построение промпта для LLM-детектора red flags."""

from __future__ import annotations

import json
import pathlib

import yaml

_CATEGORIES_PATH = pathlib.Path(__file__).parent / "categories.yaml"


def load_categories() -> list[dict[str, str]]:
    """Загружает категории флагов из categories.yaml."""
    with _CATEGORIES_PATH.open(encoding="utf-8") as file_handle:
        return yaml.safe_load(file_handle)["categories"]  # type: ignore[no-any-return]


def build_prompt(categories: list[dict[str, str]], dialogue: str) -> str:
    """Строит промпт для LLM с перечнем категорий и текстом диалога."""
    categories_block = "\n".join(f"- {one_item['id']}: {one_item['description']}" for one_item in categories)
    valid_ids = json.dumps([one_item["id"] for one_item in categories], ensure_ascii=False)

    return (
        "You are a bank security expert analyzing customer dialogue for risk patterns.\n\n"
        "Detect the following red flag categories:\n"
        f"{categories_block}\n\n"
        "Respond ONLY with a JSON object in this exact format:\n"
        '{"flags": [{"category": "<category_id>", "confidence": <0.0-1.0>, "evidence": "<quote>"}]}\n\n'
        "Rules:\n"
        "- Only include flags with confidence >= 0.7\n"
        f"- category must be exactly one of: {valid_ids}\n"
        '- If no flags detected, return {"flags": []}\n'
        "- evidence must be a direct quote from the dialogue\n\n"
        "Dialogue to analyze:\n"
        f"{dialogue}"
    )
