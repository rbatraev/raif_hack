# ruff: noqa: RUF001, RUF002
"""Файл для тестирования с eval сервисом, желательно не трогать."""

import logging
import time
import typing

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from app.models import run_parallel_detection

raw_text_logger = logging.getLogger("raw_text")
raw_text_logger.setLevel(logging.INFO)
raw_text_logger.addHandler(logging.FileHandler("/tmp/log.txt"))  # noqa: S108

check_router = APIRouter(tags=["Dialogue Check"])
_logger = logging.getLogger(__name__)


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


@typing.final
class DialogueCheckResponse(BaseModel):
    session_id: str = Field(description="Идентификатор сессии")
    predicted_red_flags: list[RedFlagItem] = Field(
        description="Список предсказанных нарушений (сравнивается eval-сервисом с expected_red_flags)",
    )
    processing_time_ms: int = Field(description="Время обработки сессии в миллисекундах")


@check_router.post("/check")
async def check_dialogue(
    http_request: Request,
    request_body: DialogueCheckRequest,
) -> DialogueCheckResponse:
    start_time = time.perf_counter()

    _logger.info(
        "request session_id=%s messages=%d",
        request_body.session_id,
        len(request_body.messages),
    )

    raw_text = format_dialogue(request_body.messages)
    raw_text_logger.info(raw_text)
    raw_text_logger.info("=" * 40)
    predicted_red_flags = [
        RedFlagItem(category=one_flag["category"])
        for one_flag in await run_parallel_detection(http_request.app.state.llm_client.api_key, raw_text)
    ]

    processing_time_ms = int(time.perf_counter() - start_time)

    _logger.info(
        "response session_id=%s flags=%s time_ms=%d",
        request_body.session_id,
        [one_flag.category for one_flag in predicted_red_flags],
        processing_time_ms,
    )

    return DialogueCheckResponse(
        session_id=request_body.session_id,
        predicted_red_flags=predicted_red_flags,
        processing_time_ms=processing_time_ms,
    )
