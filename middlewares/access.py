import logging
from typing import Callable, Dict, Any, Awaitable

from aiogram import BaseMiddleware
from aiogram.types import TelegramObject, CallbackQuery, Message

from database.db import is_banned

logger = logging.getLogger(__name__)


class BanMiddleware(BaseMiddleware):
    """
    Блокирует ВСЕ сообщения и кнопки забаненных пользователей.
    Статус бана читается из БД напрямую (без кэша) — иначе после бана
    или разбана ещё действовало устаревшее значение.
    """

    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any],
    ) -> Any:
        user = data.get("event_from_user")
        if user is None:
            return await handler(event, data)

        try:
            banned = await is_banned(user.id)
        except Exception:
            # Повторная попытка напрямую по БД; если и она не удалась —
            # логируем и пропускаем (недоступность БД не должна ломать бота
            # для всех остальных). Проверка в /start страхует основной путь.
            logger.exception(f"BanMiddleware: ошибка проверки бана {user.id}")
            try:
                banned = await is_banned(user.id)
            except Exception:
                banned = False

        if banned:
            try:
                if isinstance(event, CallbackQuery):
                    await event.answer("Вы заблокированы в боте", show_alert=True)
                elif isinstance(event, Message):
                    await event.answer("Вы заблокированы в боте")
            except Exception:
                pass
            return

        return await handler(event, data)
