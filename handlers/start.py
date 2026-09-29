import logging

from aiogram import Router
from aiogram.filters import CommandStart, CommandObject
from aiogram.types import Message

from database.db import add_user, is_admin, set_admin, register_referral, is_banned
from utils.notify import notify_user
from config import ADMIN_IDS, REFERRAL_BONUS

router = Router()
logger = logging.getLogger(__name__)


def _welcome_text(name: str) -> str:
    return (
        f"Добро пожаловать, <b>{name}</b>!\n\n"
        "Мы рады видеть вас тут, попробуйте наш впн.\n"
        "Нажмите слева внизу «Открыть».\n"
        "Удачных покупок!"
    )


def _parse_referrer_id(payload: str | None) -> int | None:
    if not payload:
        return None

    payload = payload.strip()
    if payload.startswith("ref"):
        payload = payload[3:]

    if payload.isdigit():
        try:
            return int(payload)
        except ValueError:
            return None
    return None


@router.message(CommandStart())
async def start_cmd(message: Message, command: CommandObject):
    if await is_banned(message.from_user.id):
        try:
            await message.answer("Вы заблокированы в боте.")
        except Exception:
            pass
        return

    is_new = await add_user(message.from_user.id, message.from_user.username or "")

    if message.from_user.id in ADMIN_IDS and not await is_admin(message.from_user.id):
        await set_admin(message.from_user.id, 1)

    if is_new:
        referrer_id = _parse_referrer_id(command.args)

        if referrer_id and referrer_id != message.from_user.id:
            try:
                registered = await register_referral(referrer_id, message.from_user.id)
            except Exception:
                logger.exception("start_cmd referral error")
                registered = False

            if registered:
                try:
                    await notify_user(
                        referrer_id,
                        f"По вашей реферальной ссылке зарегистрировался новый пользователь! "
                        f"Начислено +{REFERRAL_BONUS} ₽ на баланс.",
                        bot=message.bot,
                    )
                except Exception:
                    logger.exception("start_cmd notify referrer error")

    name = message.from_user.first_name or message.from_user.username or "друг"

    await message.answer("🍀")
    await message.answer(_welcome_text(name))