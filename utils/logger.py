import logging
import logging.handlers
import os
import time
from typing import Optional


def setup_logging(log_dir: str = "logs") -> None:
    os.makedirs(log_dir, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(logging.INFO)

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))

    file_handler = logging.handlers.TimedRotatingFileHandler(
        filename=os.path.join(log_dir, "bot.log"),
        when="midnight",
        backupCount=7,
        encoding="utf-8"
    )
    file_handler.setLevel(logging.WARNING)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))

    root.handlers.clear()
    root.addHandler(console)
    root.addHandler(file_handler)

    logging.getLogger("aiogram.event").setLevel(logging.WARNING)
    logging.getLogger("aiogram.dispatcher").setLevel(logging.WARNING)
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("py3xui").setLevel(logging.WARNING)
    logging.getLogger("py3xui.async_api").setLevel(logging.ERROR)
    logging.getLogger("py3xui.async_api.async_api_base").setLevel(logging.ERROR)


class TelegramErrorNotifier:
    def __init__(self, bot, admin_ids: list):
        self.bot = bot
        self.admin_ids = admin_ids
        self._last_errors: dict = {}
        self._dedup_window = 300

    async def notify(self, text: str, exc: Optional[Exception] = None) -> None:
        if exc is None:
            return

        now = time.time()
        key = text[:100]

        if (
            key in self._last_errors
            and now - self._last_errors[key] < self._dedup_window
        ):
            return

        self._last_errors[key] = now

        full_text = f"<b>FlowVPN Bot</b>\n\n{text}"
        full_text += (
            f"\n\n<code>"
            f"{type(exc).__name__}: {str(exc)[:500]}"
            f"</code>"
        )

        for admin_id in self.admin_ids:
            try:
                await self.bot.send_message(admin_id, full_text, parse_mode="HTML")
            except Exception:
                pass
