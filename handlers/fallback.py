from aiogram import Router
from aiogram.types import CallbackQuery

router = Router()


@router.callback_query()
async def fallback_callback(callback: CallbackQuery):
    """Ловит клики по кнопкам из старых сообщений, оставшихся в чатах."""
    await callback.answer(
        "Используйте кнопку «Открыть» слева внизу, чтобы работать с FlowVPN.",
        show_alert=True,
    )
