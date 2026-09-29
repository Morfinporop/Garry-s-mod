import logging
import traceback

from aiogram import Router
from aiogram.types import ErrorEvent
from aiogram.exceptions import (
    TelegramBadRequest,
    TelegramForbiddenError,
    TelegramRetryAfter,
    TelegramNetworkError,
)
import asyncio

logger = logging.getLogger(__name__)
router = Router()

_notifier = None


def set_notifier(notifier) -> None:
    global _notifier
    _notifier = notifier


@router.errors()
async def global_error_handler(event: ErrorEvent) -> bool:
    exc = event.exception
    update = event.update

    user_id = None
    try:
        if update.message:
            user_id = update.message.from_user.id
        elif update.callback_query:
            user_id = update.callback_query.from_user.id
    except Exception:
        pass

    if isinstance(exc, TelegramForbiddenError):
        logger.debug(f"Пользователь {user_id} заблокировал бота")
        return True

    if isinstance(exc, TelegramRetryAfter):
        logger.warning(f"RetryAfter: ждём {exc.retry_after}с")
        await asyncio.sleep(exc.retry_after)
        return True

    if isinstance(exc, TelegramBadRequest):
        msg = str(exc).lower()
        ignored = (
            "message is not modified",
            "message to edit not found",
            "query is too old",
            "message can't be deleted",
        )
        if any(m in msg for m in ignored):
            return True
        logger.warning(f"TelegramBadRequest (user {user_id}): {exc}")
        return True

    if isinstance(exc, TelegramNetworkError):
        logger.warning(f"TelegramNetworkError: {exc}")
        return True

    tb = traceback.format_exc()
    logger.error(
        f"Необработанное исключение!\n"
        f"User: {user_id}\n"
        f"Exception: {exc}\n"
        f"Traceback:\n{tb}"
    )

    if _notifier:
        await _notifier.notify(
            f"Необработанная ошибка\n"
            f"User: <code>{user_id}</code>\n"
            f"<code>{type(exc).__name__}: {str(exc)[:300]}</code>",
            exc
        )

    try:
        if update.callback_query:
            await update.callback_query.answer("Что-то пошло не так. Попробуйте ещё раз.", show_alert=True)
        elif update.message:
            await update.message.answer("Внутренняя ошибка. Попробуйте позже.")
    except Exception:
        pass

    return True
