# ruff: noqa: RUF001, RUF002
"""Файл для тестирования с eval сервисом, желательно не трогать."""

import logging
import random
import time
import typing

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from app.models import process_risk_detection

raw_text_logger = logging.getLogger("raw_text")
raw_text_logger.setLevel(logging.INFO)
raw_text_logger.addHandler(logging.FileHandler("/tmp/log.txt"))  # noqa: S108

check_router = APIRouter(tags=["Dialogue Check"])


@typing.final
class DialogueMessage(BaseModel):
    role: str = Field(description="Роль отправителя сообщения (user, support, assistant)")
    content: str = Field(description="Содержимое сообщения")


def format_dialogue(messages: list[DialogueMessage]) -> str:
    """Форматирует историю сообщений диалога в один текстовый блок."""
    return "\n".join(f"{one_message.role}: {one_message.content}" for one_message in messages)


@typing.final
class DialogueCheckRequest(BaseModel):
    session_id: str = Field(description="Идентификатор пользовательской сессии")
    messages: list[DialogueMessage] = Field(description="Список сообщений в диалоге")


@typing.final
class RedFlagItem(BaseModel):
    category: str = Field(description="Категория обнаруженного риска")
    confidence: float = Field(default=1.0, description="Уверенность детектора в категории")
    correct_probability: float = Field(default=1.0, description="Оценка вероятности правильности ответа")
    is_obvious: bool = Field(default=True, description="Явно правильный флаг по текущему порогу уверенности")


@typing.final
class DialogueCheckResponse(BaseModel):
    session_id: str = Field(description="Идентификатор сессии")
    predicted_red_flags: list[RedFlagItem] = Field(
        description="Список предсказанных нарушений (сравнивается eval-сервисом с expected_red_flags)",
    )
    processing_time_ms: int = Field(description="Время обработки сессии в миллисекундах")


@check_router.post("/check")
def check_dialogue(
    http_request: Request,
    request_body: DialogueCheckRequest,
) -> DialogueCheckResponse:
    start_time = time.perf_counter()

    time.sleep(random.uniform(1.0, 2.0))  # noqa: S311

    raw_text = format_dialogue(request_body.messages)
    flags, source = process_risk_detection(http_request.app.state.llm_client, raw_text)
    predicted_red_flags = [
        RedFlagItem(
            category=one_flag["category"],
            confidence=float(one_flag.get("confidence", 1.0)),
            correct_probability=float(one_flag.get("correct_probability", one_flag.get("confidence", 1.0))),
            is_obvious=bool(one_flag.get("is_obvious", True)),
        )
        for one_flag in flags
    ]

    processing_time_ms = int((time.perf_counter() - start_time) * 1000)

    raw_text_logger.info(
        "session=%s flags=%s source=%s time_ms=%d\n%s\n%s",
        request_body.session_id,
        [
            {
                "category": one_flag.category,
                "correct_probability": one_flag.correct_probability,
                "is_obvious": one_flag.is_obvious,
            }
            for one_flag in predicted_red_flags
        ],
        source,
        processing_time_ms,
        raw_text,
        "=" * 40,
    )

    return DialogueCheckResponse(
        session_id=request_body.session_id,
        predicted_red_flags=predicted_red_flags,
        processing_time_ms=processing_time_ms,
    )
