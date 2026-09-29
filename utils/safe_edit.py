import logging

from aiogram.types import Message, CallbackQuery
from aiogram.exceptions import TelegramBadRequest

logger = logging.getLogger(__name__)

CAPTION_LIMIT = 1024

_IGNORED = (
    "message is not modified",
    "message content isn't modified",
)


def _has_media(message) -> bool:
    if message is None:
        return False
    for attr in ("photo", "animation", "document", "video", "audio", "voice", "video_note", "sticker"):
        if getattr(message, attr, None):
            return True
    return False


async def _send_new(bot, chat_id: int, text: str, reply_markup):
    return await bot.send_message(chat_id, text, reply_markup=reply_markup)


async def show_screen(message: Message, text: str, reply_markup=None):
    """
    Показывает экран, редактируя текущее сообщение НА МЕСТЕ.
    Новые сообщения не создаются (кроме вынужденных случаев: слишком старое
    сообщение или текст длиннее лимита подписи у медиа-сообщений).
    """
    if message is None or not hasattr(message, "chat"):
        return None

    bot = message.bot
    chat_id = message.chat.id
    media = _has_media(message)

    # InaccessibleMessage и прочее без edit_text — просто шлём новое
    if not hasattr(message, "edit_text") and not hasattr(message, "edit_media"):
        return await _send_new(bot, chat_id, text, reply_markup)

    try:
        if media:
            fits = len(text) <= CAPTION_LIMIT
            if not fits:
                # длинный текст на фото — вынужденно заменяем на текстовое
                try:
                    await message.delete()
                except Exception:
                    pass
                return await _send_new(bot, chat_id, text, reply_markup)
            await message.edit_caption(caption=text, reply_markup=reply_markup)
            return message

        await message.edit_text(text, reply_markup=reply_markup)
        return message

    except TelegramBadRequest as e:
        err = str(e).lower()
        if any(m in err for m in _IGNORED):
            return message

        # слишком старое / удалённое сообщение — показываем новое
        try:
            await message.delete()
        except Exception:
            pass
        try:
            return await _send_new(bot, chat_id, text, reply_markup)
        except Exception:
            logger.exception("show_screen: не удалось показать экран chat=%s", chat_id)
            return None
    except Exception:
        logger.exception("show_screen: неожиданная ошибка chat=%s", chat_id)
        return None


async def drop_message(*messages) -> None:
    """Тихо удаляет сообщения (ввод пользователя, служебные подсказки)."""
    for m in messages:
        if m is None:
            continue
        try:
            await m.delete()
        except Exception:
            pass
