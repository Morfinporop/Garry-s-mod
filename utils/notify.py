import logging

from webapp import extra_store

logger = logging.getLogger(__name__)


async def notify_user(user_id: int, text: str, bot=None) -> bool:
    """
    Единая точка отправки уведомлений:
    1) всегда пишет в колокольчик Mini App (extra.db -> раздел «Уведомления»);
    2) дополнительно отправляет сообщение в Telegram, если передан bot.
    """
    ok = False

    try:
        await extra_store.push_notification(user_id, text)
        ok = True
    except Exception:
        logger.exception("notify_user: не удалось записать уведомление в БД для %s", user_id)

    if bot is not None:
        try:
            await bot.send_message(user_id, text)
        except Exception:
            logger.debug("notify_user: не удалось отправить Telegram-сообщение %s", user_id)

    return ok
