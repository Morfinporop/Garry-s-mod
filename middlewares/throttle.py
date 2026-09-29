import asyncio
import logging
import time
from typing import Callable, Dict, Any, Awaitable
from collections import defaultdict

from aiogram import BaseMiddleware
from aiogram.types import TelegramObject, Message, CallbackQuery

logger = logging.getLogger(__name__)

SWEEP_INTERVAL = 300  # раз в 5 минут выкидываем «спящих» пользователей


class ThrottleMiddleware(BaseMiddleware):
    def __init__(
        self,
        message_limit: int = 10,
        message_window: float = 5,
        callback_limit: int = 15,
        callback_window: float = 5,
    ):
        self.message_limit = message_limit
        self.message_window = message_window
        self.callback_limit = callback_limit
        self.callback_window = callback_window
        self._message_history: Dict[int, list] = defaultdict(list)
        self._callback_history: Dict[int, list] = defaultdict(list)
        self._warned: Dict[int, bool] = defaultdict(bool)
        self._last_sweep = time.monotonic()

    def _sweep(self, now: float) -> None:
        """Удаляем записи пользователей, которые давно ничего не нажимали,
        чтобы словари не росли память бесконечно."""
        if now - self._last_sweep < SWEEP_INTERVAL:
            return
        self._last_sweep = now
        max_window = max(self.message_window, self.callback_window)
        for history in (self._message_history, self._callback_history):
            for uid in [u for u, ts in history.items()
                        if not ts or now - max(ts) >= max_window]:
                history.pop(uid, None)
                self._warned.pop(uid, None)

    def _is_throttled(
        self,
        user_id: int,
        history: Dict[int, list],
        limit: int,
        window: float,
    ) -> bool:
        now = time.monotonic()
        self._sweep(now)
        recent = [t for t in history.get(user_id, []) if now - t < window]
        if len(recent) >= limit:
            history[user_id] = recent
            return True
        recent.append(now)
        history[user_id] = recent
        return False

    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any],
    ) -> Any:
        user = data.get("event_from_user")
        if user is None:
            return await handler(event, data)

        user_id = user.id

        if isinstance(event, Message):
            throttled = self._is_throttled(
                user_id, self._message_history,
                self.message_limit, self.message_window
            )
        elif isinstance(event, CallbackQuery):
            throttled = self._is_throttled(
                user_id, self._callback_history,
                self.callback_limit, self.callback_window
            )
        else:
            return await handler(event, data)

        if throttled:
            if not self._warned[user_id]:
                self._warned[user_id] = True
                logger.info(f"Throttle: user {user_id} превысил лимит")
                try:
                    if isinstance(event, Message):
                        await event.answer("Не так быстро. Подождите несколько секунд.")
                    elif isinstance(event, CallbackQuery):
                        await event.answer("Не так быстро, подождите пару секунд.", show_alert=True)
                except Exception:
                    pass
            return

        self._warned[user_id] = False
        return await handler(event, data)
