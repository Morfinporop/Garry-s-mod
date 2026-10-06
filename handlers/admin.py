import logging

from aiogram import Router, F
from aiogram.types import Message, CallbackQuery
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup

from keyboards.menu import (
    admin_menu, admin_promos_menu, broadcast_setup_menu, broadcast_active_list_menu,
    back_btn, users_list_menu, user_card_menu, user_revoke_menu,
    user_revoke_confirm_menu, user_history_menu,
    features_menu, FEATURE_LABELS, FEATURE_HINTS, promo_post_kb,
)
from database.db import (
    is_admin, get_users_count, get_all_keys_count,
    create_key, add_balance, get_balance, user_exists,
    create_promo, get_all_promos, delete_promo, get_promo,
    get_all_users, add_transaction,
    ban_user, unban_user,
    create_broadcast, get_active_broadcasts, stop_broadcast,
    get_user_active_keys_with_id, get_key_by_id, deactivate_key,
    add_promo_post, get_promo_posts,
    is_feature_enabled, set_feature, get_all_features,
    get_user, get_user_by_username,
    get_revenue_stats, get_tariff_stats, get_funnel_stats,
    set_user_auto_renew_all,
    get_user_transactions, get_user_transactions_count,
    get_user_purchase_summary, search_users,
)
from utils.safe_edit import show_screen, drop_message
from utils.notify import notify_user as push_notify

router = Router()
logger = logging.getLogger(__name__)

MAX_DAYS = 3650
MAX_BALANCE_CHANGE = 1000000
USERS_PER_PAGE = 16
HISTORY_PER_PAGE = 5


class AdmSearch(StatesGroup):
    waiting_query = State()


class AdmBal(StatesGroup):
    waiting_amount = State()


class AdmKey(StatesGroup):
    waiting_days = State()


class AdmBan(StatesGroup):
    waiting_reason = State()


class AdmMsg(StatesGroup):
    waiting_text = State()


class AdmPromo(StatesGroup):
    waiting_code = State()
    waiting_bonus_type = State()
    waiting_bonus_value = State()
    waiting_max_uses = State()
    waiting_post_chat = State()


class AdmDelPromo(StatesGroup):
    waiting_code = State()


class AdmGift(StatesGroup):
    waiting_gift_type = State()
    waiting_gift_value = State()


class AdmNotifyAll(StatesGroup):
    waiting_text = State()


class BroadcastPhoto(StatesGroup):
    waiting_photo = State()
    waiting_text = State()
    waiting_url_choice = State()
    waiting_url_text = State()
    waiting_url_link = State()
    waiting_duration_unit = State()
    waiting_duration = State()
    waiting_interval_unit = State()
    waiting_interval = State()


class BroadcastText(StatesGroup):
    waiting_text = State()
    waiting_url_choice = State()
    waiting_url_text = State()
    waiting_url_link = State()
    waiting_duration_unit = State()
    waiting_duration = State()
    waiting_interval_unit = State()
    waiting_interval = State()


async def check_admin(callback: CallbackQuery) -> bool:
    if not await is_admin(callback.from_user.id):
        await callback.answer("Нет доступа", show_alert=True)
        return False
    return True


async def check_admin_msg(message: Message, state: FSMContext) -> bool:
    if not await is_admin(message.from_user.id):
        await state.clear()
        await message.answer("Нет доступа")
        return False
    return True


def parse_int(text: str):
    if not text:
        return None
    try:
        return int(text.strip())
    except ValueError:
        return None


def parse_cb_id(data: str, prefix: str):
    try:
        return int(data.replace(prefix, "", 1))
    except ValueError:
        return None


async def notify_user(bot, user_id: int, text: str) -> bool:
    full_text = f"<b>Уведомление от Администрации</b>\n\n{text}"
    return await push_notify(user_id, full_text, bot=bot)


def _tx_line(tx) -> str:
    amount = tx["amount"]
    sign = "+" if amount > 0 else ""
    desc = tx["description"] or "Операция"
    return f"{sign}{amount} ₽ · {desc} · {tx['created_at']}"


async def user_card_text(user_id: int) -> str:
    user = await get_user(user_id)
    if not user:
        return "Пользователь не найден."

    keys = await get_user_active_keys_with_id(user_id)
    summary = await get_user_purchase_summary(user_id)
    txs = await get_user_transactions(user_id, limit=5, offset=0)

    nick = f"@{user['username']}" if user["username"] else "без ника"
    statuses = [
        "Триал: " + ("да" if user["trial_used"] else "нет"),
        "Админ: " + ("да" if user["is_admin"] else "нет"),
        "Бан: " + ("ДА" if user["is_banned"] else "нет")
    ]

    text = (
        f"<b>Пользователь</b>\n\n"
        f"ID: <code>{user['user_id']}</code>\n"
        f"Ник: {nick}\n"
        f"Баланс: <b>{user['balance']} ₽</b>\n"
        f"Регистрация: {user['registered_at'] or '—'}\n"
        f"{' · '.join(statuses)}\n"
    )

    if user["ban_reason"]:
        text += f"Причина бана: {user['ban_reason']}\n"

    text += f"\n<b>Ключи ({len(keys)}):</b>\n"
    if keys:
        for k in keys[:5]:
            multi = ""
            if k["max_users"]:
                multi = f" · {k['max_users']} чел"
            elif k["is_duo"]:
                multi = " · DUO"
            text += f"· {k['tariff']}{multi} · до {k['expires_at']}\n"
        if len(keys) > 5:
            text += f"… и ещё {len(keys) - 5}\n"
    else:
        text += "—\n"

    text += f"\n<b>Покупки: {summary['count']} · {summary['spent']} ₽</b>\n"
    if txs:
        for tx in txs:
            text += _tx_line(tx) + "\n"
    else:
        text += "пока пусто\n"

    return text


async def _show_card(message, user_id: int, state: FSMContext | None = None):
    keys = await get_user_active_keys_with_id(user_id)
    user = await get_user(user_id)

    auto_on = any(bool(k["auto_renew"]) for k in keys)
    is_banned = bool(user["is_banned"]) if user else False
    await show_screen(
        message,
        await user_card_text(user_id),
        user_card_menu(user_id, is_banned, auto_on),
    )


@router.callback_query(F.data == "adm:panel")
async def admin_panel(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    await state.clear()
    await show_screen(callback.message, "<b>Админ-панель</b>\n\nВыберите действие", admin_menu())
    await callback.answer()


@router.callback_query(F.data == "adm:stats")
async def admin_stats(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    await state.clear()
    users = await get_users_count()
    keys = await get_all_keys_count()
    bc = await get_active_broadcasts()
    revenue = await get_revenue_stats()
    tariffs = await get_tariff_stats()
    funnel = await get_funnel_stats()

    text = (
        f"<b>Статистика</b>\n\n"
        f"Пользователей: <b>{users}</b>\n"
        f"Активных ключей: <b>{keys}</b>\n"
        f"Рассылок: <b>{len(bc)}</b>\n\n"
        f"<b>Доходы:</b>\n"
        f"Сегодня: <b>{revenue['today']} ₽</b>\n"
        f"Неделя: <b>{revenue['week']} ₽</b>\n"
        f"Месяц: <b>{revenue['month']} ₽</b>\n"
        f"Всего: <b>{revenue['total']} ₽</b>\n\n"
        f"<b>Популярные тарифы:</b>\n"
    )
    for t in tariffs:
        text += f"  {t['tariff']}: <b>{t['cnt']}</b> шт\n"

    text += (
        f"\n<b>Воронка:</b>\n"
        f"Всего зашло: <b>{funnel['total']}</b>\n"
        f"Использовали триал: <b>{funnel['trial']}</b>\n"
        f"Купили подписку: <b>{funnel['paid']}</b>\n"
        f"Конверсия: <b>{funnel['conversion']}%</b>"
    )

    await show_screen(callback.message, text, back_btn("adm:panel"))
    await callback.answer()


def _format_users_header(total: int, page: int, total_pages: int) -> str:
    return (
        f"<b>Пользователи ({total})</b>\n"
        f"{page + 1}/{total_pages}\n\n"
        f"Нажмите на ник — откроется полная карточка"
    )


async def _show_users_page(message, page: int):
    users = await get_all_users()
    total = len(users)
    if not users:
        await show_screen(message, "Нет пользователей.", back_btn("adm:panel"))
        return

    total_pages = max(1, (total + USERS_PER_PAGE - 1) // USERS_PER_PAGE)
    page = max(0, min(page, total_pages - 1))
    slice_users = users[page * USERS_PER_PAGE:(page + 1) * USERS_PER_PAGE]

    await show_screen(
        message,
        _format_users_header(total, page, total_pages),
        users_list_menu(slice_users, page, total_pages),
    )


@router.callback_query(F.data == "adm:users")
async def admin_users(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    await state.clear()
    await _show_users_page(callback.message, 0)
    await callback.answer()


@router.callback_query(F.data.startswith("adm:users:"))
async def admin_users_page(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    await state.clear()
    try:
        page = int(callback.data.split(":")[2])
    except (IndexError, ValueError):
        await callback.answer("Некорректная страница", show_alert=True)
        return
    await _show_users_page(callback.message, page)
    await callback.answer()


@router.callback_query(F.data == "adm:search")
async def admin_search_start(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    await state.clear()
    await show_screen(
        callback.message,
        "<b>Поиск пользователя</b>\n\nВведите ID или @username:",
        back_btn("adm:users"),
    )
    await state.set_state(AdmSearch.waiting_query)
    await state.update_data(scr=callback.message)
    await callback.answer()


@router.message(AdmSearch.waiting_query)
async def admin_search_process(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    if not message.text:
        await message.answer("Введите запрос.")
        return

    query = message.text.strip()
    data = await state.get_data()
    scr = data.get("scr")
    await state.clear()
    await drop_message(message)

    user = None
    if query.lstrip("-").isdigit():
        user = await get_user(int(query))
    if not user:
        user = await get_user_by_username(query.lstrip("@"))
    if not user:
        results = await search_users(query, limit=1)
        if results:
            user = results[0]

    if not user:
        text = "Пользователь не найден."
        kb = back_btn("adm:users")
        if scr:
            await show_screen(scr, text, kb)
        else:
            await message.answer(text, reply_markup=kb)
        return

    uid = user["user_id"]
    if scr:
        await _show_card(scr, uid)
    else:
        await message.answer(await user_card_text(uid), reply_markup=user_card_menu(uid, bool(user["is_banned"]), False))


@router.callback_query(F.data.startswith("auc_"))
async def user_card(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    await state.clear()
    uid = parse_cb_id(callback.data, "auc_")
    if uid is None or not await user_exists(uid):
        await callback.answer("Пользователь не найден", show_alert=True)
        return
    await _show_card(callback.message, uid)
    await callback.answer()


@router.callback_query(F.data.startswith("aubal_"))
async def user_balance_start(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    uid = parse_cb_id(callback.data, "aubal_")
    if uid is None or not await user_exists(uid):
        await callback.answer("Пользователь не найден", show_alert=True)
        return
    await state.clear()
    bal = await get_balance(uid)
    await show_screen(
        callback.message,
        f"<b>Баланс</b> <code>{uid}</code>: {bal} ₽\n\n"
        f"Введите сумму: <code>+50</code> или <code>-30</code>:",
        back_btn(f"auc_{uid}"),
    )
    await state.set_state(AdmBal.waiting_amount)
    await state.update_data(scr=callback.message, target=uid)
    await callback.answer()


@router.message(AdmBal.waiting_amount)
async def user_balance_apply(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    amount = parse_int(message.text)
    if amount is None or amount == 0 or abs(amount) > MAX_BALANCE_CHANGE:
        await message.answer(f"Число ≠ 0, до {MAX_BALANCE_CHANGE}.")
        return

    data = await state.get_data()
    uid = data["target"]
    scr = data.get("scr")
    await state.clear()
    await drop_message(message)

    await add_balance(uid, amount)
    new_bal = await get_balance(uid)
    await add_transaction(uid, amount, "admin", "Изменение админом")

    if amount > 0:
        await notify_user(message.bot, uid, f"Баланс пополнен!\n\nНачислено: <b>+{amount} ₽</b>\nБаланс: <b>{new_bal} ₽</b>")
    else:
        await notify_user(message.bot, uid, f"Списание с баланса.\n\nСписано: <b>{amount} ₽</b>\nБаланс: <b>{new_bal} ₽</b>")

    if scr:
        await _show_card(scr, uid)
    else:
        await message.answer(f"{amount:+d} ₽ баланс {new_bal} ₽", reply_markup=back_btn(f"auc_{uid}"))


@router.callback_query(F.data.startswith("aukey_"))
async def user_give_key_start(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    uid = parse_cb_id(callback.data, "aukey_")
    if uid is None or not await user_exists(uid):
        await callback.answer("Пользователь не найден", show_alert=True)
        return
    await state.clear()
    await show_screen(
        callback.message,
        f"<b>Выдать ключ</b> <code>{uid}</code>\n\n"
        f"Сколько дней? (например 30, 90, 365)",
        back_btn(f"auc_{uid}"),
    )
    await state.set_state(AdmKey.waiting_days)
    await state.update_data(scr=callback.message, target=uid)
    await callback.answer()


@router.message(AdmKey.waiting_days)
async def user_give_key_apply(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    days = parse_int(message.text)
    if days is None or days <= 0 or days > MAX_DAYS:
        await message.answer(f"Число дней от 1 до {MAX_DAYS}.")
        return

    data = await state.get_data()
    uid = data["target"]
    scr = data.get("scr")
    await state.clear()
    await drop_message(message)

    try:
        key = await create_key(uid, f"Подарок ({days}д)", days=days)
    except Exception:
        logger.exception("create key admin error")
        text = "Ошибка создания ключа.\nПопробуйте позже."
        if scr:
            await show_screen(scr, text, back_btn(f"auc_{uid}"))
        else:
            await message.answer(text, reply_markup=back_btn(f"auc_{uid}"))
        return

    await notify_user(
        message.bot, uid,
        f"Вам выдан VPN-ключ!\n\nКлюч:\n<pre>{key}</pre>\nСрок действия: <b>{days} дней</b>\n\nИнструкции — в разделе «FAQ»."
    )

    text = (
        f"<b>Ключ выдан!</b>\n\n"
        f"ID: <code>{uid}</code>\n"
        f"Ключ:\n<pre>{key}</pre>\n"
        f"{days} дней"
    )
    if scr:
        await show_screen(scr, text, back_btn(f"auc_{uid}"))
    else:
        await message.answer(text, reply_markup=back_btn(f"auc_{uid}"))


@router.callback_query(F.data.startswith("aurev_") & ~F.data.startswith("aurevk_") & ~F.data.startswith("aurevc_"))
async def user_revoke_list(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    uid = parse_cb_id(callback.data, "aurev_")
    if uid is None or not await user_exists(uid):
        await callback.answer("Пользователь не найден", show_alert=True)
        return
    await state.clear()
    keys = await get_user_active_keys_with_id(uid)
    if not keys:
        await show_screen(
            callback.message,
            f"<b>Отзыв ключа</b>\n\nУ <code>{uid}</code> нет активных ключей.",
            back_btn(f"auc_{uid}"),
        )
        await callback.answer()
        return
    await show_screen(
        callback.message,
        f"<b>Отзыв ключа</b> <code>{uid}</code>\n\nВыберите ключ:",
        user_revoke_menu(keys, uid),
    )
    await callback.answer()


@router.callback_query(F.data.startswith("aurevk_"))
async def user_revoke_confirm(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    await state.clear()
    key_id = parse_cb_id(callback.data, "aurevk_")
    key = await get_key_by_id(key_id) if key_id else None
    if not key:
        await callback.answer("Ключ не найден", show_alert=True)
        return
    if not key["is_active"]:
        await callback.answer("Ключ уже неактивен", show_alert=True)
        return

    multi = ""
    if key["max_users"]:
        multi = f"{key['max_users']}чел"

    await show_screen(
        callback.message,
        f"<b>Подтвердите отзыв</b>\n\n"
        f"<code>{key['user_id']}</code>\n"
        f"{key['tariff']}{multi}\n"
        f"до {key['expires_at']}\n"
        f"Создан: {key['created_at']}\n\n"
        f"Деньги <b>НЕ возвращаются</b>.",
        user_revoke_confirm_menu(key_id, key["user_id"]),
    )
    await callback.answer()


@router.callback_query(F.data.startswith("aurevc_"))
async def user_revoke_apply(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    await state.clear()
    key_id = parse_cb_id(callback.data, "aurevc_")
    key = await get_key_by_id(key_id) if key_id else None
    if not key:
        await callback.answer("Ключ не найден", show_alert=True)
        return
    if not key["is_active"]:
        await callback.answer("Ключ уже неактивен", show_alert=True)
        return

    uid = key["user_id"]
    tariff = key["tariff"]

    try:
        await deactivate_key(key_id)
    except Exception:
        logger.exception(f"Error revoke key {key_id}")
        await show_screen(callback.message, "Ошибка отзыва ключа.", back_btn(f"auc_{uid}"))
        await callback.answer()
        return

    await notify_user(
        callback.bot, uid,
        f"Ваш VPN-ключ отозван.\n\nТариф: <b>{tariff}</b>\n\nОбратитесь в поддержку если ошибка."
    )
    await _show_card(callback.message, uid)
    await callback.answer("Ключ отозван")


@router.callback_query(F.data.startswith("auren_"))
async def user_auto_renew_toggle(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    uid = parse_cb_id(callback.data, "auren_")
    if uid is None or not await user_exists(uid):
        await callback.answer("Пользователь не найден", show_alert=True)
        return
    await state.clear()

    keys = await get_user_active_keys_with_id(uid)
    if not keys:
        await callback.answer("У пользователя нет ключей", show_alert=True)
        return

    current = any(bool(k["auto_renew"]) for k in keys)
    count = await set_user_auto_renew_all(uid, not current)
    status_text = "включено" if not current else "выключено"
    await notify_user(callback.bot, uid, f"Автопродление <b>{status_text}</b> администратором.\n\nКлючей: {count}")
    await _show_card(callback.message, uid)
    await callback.answer(f"Автопродление {status_text}")


@router.callback_query(F.data.startswith("aumsg_"))
async def user_notify_start(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    uid = parse_cb_id(callback.data, "aumsg_")
    if uid is None or not await user_exists(uid):
        await callback.answer("Пользователь не найден", show_alert=True)
        return
    await state.clear()
    await show_screen(
        callback.message,
        f"<b>Уведомление</b> для <code>{uid}</code>\n\nВведите текст:",
        back_btn(f"auc_{uid}"),
    )
    await state.set_state(AdmMsg.waiting_text)
    await state.update_data(scr=callback.message, target=uid)
    await callback.answer()


@router.message(AdmMsg.waiting_text)
async def user_notify_apply(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    if not message.text:
        await message.answer("Введите текст.")
        return

    data = await state.get_data()
    uid = data["target"]
    scr = data.get("scr")
    await state.clear()
    await drop_message(message)

    ok = await notify_user(message.bot, uid, message.text.strip())
    result = f"Уведомление отправлено <code>{uid}</code>" if ok else f"Не удалось отправить <code>{uid}</code>"

    if scr:
        await show_screen(scr, result, back_btn(f"auc_{uid}"))
    else:
        await message.answer(result, reply_markup=back_btn(f"auc_{uid}"))


@router.callback_query(F.data.startswith("auban_"))
async def user_ban_start(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    uid = parse_cb_id(callback.data, "auban_")
    if uid is None or not await user_exists(uid):
        await callback.answer("Пользователь не найден", show_alert=True)
        return
    if uid == callback.from_user.id:
        await callback.answer("Нельзя забанить себя", show_alert=True)
        return
    if await is_admin(uid):
        await callback.answer("Нельзя забанить админа", show_alert=True)
        return
    await state.clear()
    await show_screen(
        callback.message,
        f"<b>Бан</b> <code>{uid}</code>\n\nПричина бана:",
        back_btn(f"auc_{uid}"),
    )
    await state.set_state(AdmBan.waiting_reason)
    await state.update_data(scr=callback.message, target=uid)
    await callback.answer()


@router.message(AdmBan.waiting_reason)
async def user_ban_apply(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    if not message.text:
        await message.answer("Введите причину текстом.")
        return

    data = await state.get_data()
    uid = data["target"]
    scr = data.get("scr")
    reason = message.text.strip()[:255]
    await state.clear()
    await drop_message(message)

    await ban_user(uid, reason)
    await notify_user(message.bot, uid, f"Аккаунт заблокирован.\n\nПричина: <b>{reason}</b>\n\nОбратитесь в поддержку.")

    if scr:
        await _show_card(scr, uid)
    else:
        await message.answer(f"{uid} забанен.", reply_markup=back_btn(f"auc_{uid}"))


@router.callback_query(F.data.startswith("auunban_"))
async def user_unban(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    uid = parse_cb_id(callback.data, "auunban_")
    if uid is None or not await user_exists(uid):
        await callback.answer("Пользователь не найден", show_alert=True)
        return
    await state.clear()
    await unban_user(uid)
    await notify_user(callback.bot, uid, "Аккаунт разблокирован.\n\nМожете пользоваться ботом.")
    await _show_card(callback.message, uid)
    await callback.answer("Разбанен")


@router.callback_query(F.data.startswith("auhist_"))
async def user_history(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    await state.clear()
    parts = callback.data.split("_")
    try:
        uid = int(parts[1])
        page = int(parts[2])
    except (IndexError, ValueError):
        await callback.answer("Некорректное действие", show_alert=True)
        return

    total = await get_user_transactions_count(uid)
    total_pages = max(1, (total + HISTORY_PER_PAGE - 1) // HISTORY_PER_PAGE)
    page = max(0, min(page, total_pages - 1))
    txs = await get_user_transactions(uid, limit=HISTORY_PER_PAGE, offset=page * HISTORY_PER_PAGE)

    if not txs:
        text = f"<b>История</b> <code>{uid}</code>\n\nОпераций нет."
    else:
        text = f"<b>История</b> <code>{uid}</code> ({page + 1}/{total_pages})\n\n"
        for tx in txs:
            text += _tx_line(tx) + "\n"

    await show_screen(callback.message, text, user_history_menu(uid, page, total_pages))
    await callback.answer()


@router.callback_query(F.data == "noop")
async def noop(callback: CallbackQuery):
    await callback.answer()


@router.callback_query(F.data == "adm:gift")
async def gift_all_start(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    await state.clear()
    await show_screen(
        callback.message,
        "<b>Подарок всем</b>\n\nТип:\n<code>1</code> — ₽\n<code>2</code> — часы VPN\n<code>3</code> — дни VPN",
        back_btn("adm:panel"),
    )
    await state.set_state(AdmGift.waiting_gift_type)
    await callback.answer()


@router.message(AdmGift.waiting_gift_type)
async def gift_all_type(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    choice = parse_int(message.text)
    if choice not in (1, 2, 3):
        await message.answer("1, 2 или 3.")
        return
    await state.update_data(gift_type=choice)
    labels = {1: "Сумма:", 2: "Часы:", 3: "Дни:"}
    await message.answer(labels[choice])
    await state.set_state(AdmGift.waiting_gift_value)


@router.message(AdmGift.waiting_gift_value)
async def gift_all_value(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    value = parse_int(message.text)
    if value is None or value <= 0:
        await message.answer("Число > 0.")
        return
    data = await state.get_data()
    gift_type = data["gift_type"]
    await state.clear()
    await message.answer("Отправляю...")
    users = await get_all_users(include_banned=False)
    success = failed = 0
    for u in users:
        uid = u["user_id"]
        try:
            if gift_type == 1:
                await add_balance(uid, value)
                await add_transaction(uid, value, "admin_gift", f"Подарок всем: {value} ₽")
                await notify_user(message.bot, uid, f"Подарок!\n\nНачислено: <b>+{value} ₽</b>")
            elif gift_type == 2:
                key = await create_key(uid, f"Подарок ({value}ч)", hours=value, source="gift")
                await add_transaction(uid, 0, "admin_gift", f"Подарок всем: {value}ч VPN")
                await notify_user(message.bot, uid, f"VPN-ключ!\n\n<b>{value} часов</b>\n\n\n<pre>{key}</pre>")
            else:
                key = await create_key(uid, f"Подарок ({value}д)", days=value, source="gift")
                await add_transaction(uid, 0, "admin_gift", f"Подарок всем: {value}д VPN")
                await notify_user(message.bot, uid, f"VPN-ключ!\n\n<b>{value} дней</b>\n\n\n<pre>{key}</pre>")
            success += 1
        except Exception:
            failed += 1
    labels = {1: f"{value} ₽", 2: f"{value}ч VPN", 3: f"{value}д VPN"}
    await message.answer(
        f"Подарки отправлены.\n\nТип: {labels[gift_type]}\nУспешно: {success}\nОшибок: {failed}",
        reply_markup=back_btn("adm:panel"),
    )


@router.callback_query(F.data == "adm:notify")
async def notify_all_start(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    await state.clear()
    await show_screen(
        callback.message,
        "<b>Оповещение всем</b>\n\nТекст для всех:",
        back_btn("adm:panel"),
    )
    await state.set_state(AdmNotifyAll.waiting_text)
    await callback.answer()


@router.message(AdmNotifyAll.waiting_text)
async def notify_all_text(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    if not message.text:
        await message.answer("Введите текст.")
        return
    text = message.text.strip()
    await state.clear()
    await message.answer("Отправляю...")
    users = await get_all_users(include_banned=False)
    success = failed = 0
    for u in users:
        ok = await notify_user(message.bot, u["user_id"], text)
        if ok:
            success += 1
        else:
            failed += 1
    await message.answer(
        f"Отправлено.\n\nВсего активных: {len(users)}\nУспешно доставлено: {success}\nОшибок: {failed}",
        reply_markup=back_btn("adm:panel"),
    )


@router.callback_query(F.data == "adm:promos")
async def admin_promos(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    await state.clear()
    await show_screen(callback.message, "<b>Промокоды</b>", admin_promos_menu())
    await callback.answer()


@router.callback_query(F.data == "adm:promo:new")
async def create_promo_start(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    await state.clear()
    await show_screen(callback.message, "Введите код промокода (латиницей):", back_btn("adm:promos"))
    await state.set_state(AdmPromo.waiting_code)
    await state.update_data(scr=callback.message)
    await callback.answer()


@router.message(AdmPromo.waiting_code)
async def promo_code(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    if not message.text:
        await message.answer("Введите код текстом.")
        return
    code = message.text.strip().upper()
    if " " in code or len(code) < 2 or len(code) > 32:
        await message.answer("Без пробелов, 2–32 символа.")
        return
    if await get_promo(code):
        await message.answer("Такой промокод уже существует.")
        return
    await state.update_data(promo_code=code)
    await message.answer(
        f"Код: <b>{code}</b>\n\nТип бонуса?\n"
        f"<code>1</code> — баланс (₽)\n<code>2</code> — дни VPN\n<code>3</code> — скидка на тариф (%)\n\nВведите 1, 2 или 3:"
    )
    await state.set_state(AdmPromo.waiting_bonus_type)


@router.message(AdmPromo.waiting_bonus_type)
async def promo_bonus_type(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    choice = parse_int(message.text)
    if choice not in (1, 2, 3):
        await message.answer("Введите 1, 2 или 3.")
        return
    await state.update_data(bonus_type=choice)
    if choice == 1:
        await message.answer("Сумма в рублях:")
    elif choice == 2:
        await message.answer("Количество дней VPN:")
    else:
        await message.answer("Процент скидки (1-99):")
    await state.set_state(AdmPromo.waiting_bonus_value)


@router.message(AdmPromo.waiting_bonus_value)
async def promo_bonus_value(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    value = parse_int(message.text)
    if value is None or value < 1:
        await message.answer("Число ≥ 1.")
        return

    data = await state.get_data()
    if data["bonus_type"] == 3 and value > 99:
        await message.answer("Скидка не может быть больше 99%.")
        return

    if data["bonus_type"] == 1:
        await state.update_data(discount=value, bonus_days=0, discount_percent=0)
    elif data["bonus_type"] == 2:
        await state.update_data(discount=0, bonus_days=value, discount_percent=0)
    else:
        await state.update_data(discount=0, bonus_days=0, discount_percent=value)

    await message.answer("Макс. использований: -1 = безлимит, иначе ≥ 1")
    await state.set_state(AdmPromo.waiting_max_uses)


@router.message(AdmPromo.waiting_max_uses)
async def promo_max_uses(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    max_uses = parse_int(message.text)
    if max_uses is None or (max_uses != -1 and max_uses < 1):
        await message.answer("Введите -1 или число ≥ 1.")
        return
    await state.update_data(max_uses=max_uses)
    await message.answer("<b>Опубликовать в канал?</b>\n\nID чата или <code>0</code> — не публиковать.")
    await state.set_state(AdmPromo.waiting_post_chat)


@router.message(AdmPromo.waiting_post_chat)
async def promo_post_chat(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    chat_id = parse_int(message.text)
    if chat_id is None:
        await message.answer("ID чата числом или 0.")
        return

    data = await state.get_data()
    await create_promo(
        code=data["promo_code"],
        discount=data.get("discount", 0),
        bonus_days=data.get("bonus_days", 0),
        discount_percent=data.get("discount_percent", 0),
        max_uses=data["max_uses"],
        created_by=message.from_user.id
    )

    limit_str = "безлимит" if data["max_uses"] == -1 else str(data["max_uses"])
    if data.get("discount", 0) > 0:
        bonus_str = f"{data['discount']} ₽ на баланс"
    elif data.get("bonus_days", 0) > 0:
        bonus_str = f"{data['bonus_days']} дней VPN"
    else:
        bonus_str = f"скидка {data.get('discount_percent', 0)}% на тариф"

    result_text = f"<b>Промокод создан!</b>\n\nКод: <code>{data['promo_code']}</code>\nБонус: {bonus_str}\nЛимит: {limit_str}"

    if chat_id != 0:
        try:
            bot_info = await message.bot.get_me()
            post_text = (
                f"<b>Новый промокод!</b>\n\nКод: <code>{data['promo_code']}</code>\n"
                f"Бонус: <b>{bonus_str}</b>\nОсталось: <b>{limit_str}</b>\n\n"
                f"Нажмите на код чтобы скопировать\n\nАктивация: Промокод в главном меню"
            )
            sent = await message.bot.send_message(chat_id, post_text, reply_markup=promo_post_kb(bot_info.username))
            try:
                await message.bot.pin_chat_message(chat_id, sent.message_id, disable_notification=False)
            except Exception:
                pass
            await add_promo_post(data["promo_code"], chat_id, sent.message_id)
            result_text += f"\n\nОпубликовано в <code>{chat_id}</code>"
        except Exception as e:
            logger.exception("Error posting promo")
            result_text += f"\n\nОшибка: <code>{e}</code>"

    await state.clear()
    await message.answer(result_text, reply_markup=back_btn("adm:promos"))


@router.callback_query(F.data == "adm:promo:list")
async def list_promos(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    await state.clear()
    promos = await get_all_promos()
    if not promos:
        text = "Нет промокодов."
    else:
        text = "<b>Промокоды:</b>\n\n"
        for p in promos:
            limit = "∞" if p["max_uses"] == -1 else f"{p['used_count']}/{p['max_uses']}"
            if p["discount"] > 0:
                bonus = f"{p['discount']} ₽"
            elif p["bonus_days"] > 0:
                bonus = f"{p['bonus_days']} дн"
            else:
                bonus = f"-{p['discount_percent']}%"
            text += f"<code>{p['code']}</code> — {bonus} [{limit}]\n"
    await show_screen(callback.message, text, back_btn("adm:promos"))
    await callback.answer()


@router.callback_query(F.data == "adm:promo:del")
async def delete_promo_start(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    await state.clear()
    await show_screen(callback.message, "Введите код для удаления:", back_btn("adm:promos"))
    await state.set_state(AdmDelPromo.waiting_code)
    await state.update_data(scr=callback.message)
    await callback.answer()


@router.message(AdmDelPromo.waiting_code)
async def delete_promo_process(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    if not message.text:
        await message.answer("Введите код текстом.")
        return
    code = message.text.strip().upper()
    data = await state.get_data()
    scr = data.get("scr")

    posts = await get_promo_posts(code)
    for p in posts:
        try:
            await message.bot.unpin_chat_message(p["chat_id"], p["message_id"])
        except Exception:
            pass
        try:
            await message.bot.delete_message(p["chat_id"], p["message_id"])
        except Exception:
            pass

    deleted = await delete_promo(code)
    await state.clear()
    await drop_message(message)

    result = f"{code} удалён. Постов удалено: {len(posts)}" if deleted else f"{code} не найден."
    if scr:
        await show_screen(scr, result, back_btn("adm:promos"))
    else:
        await message.answer(result, reply_markup=back_btn("adm:promos"))


@router.callback_query(F.data == "adm:bc")
async def broadcast_menu(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    await state.clear()
    active = await get_active_broadcasts()
    await show_screen(callback.message, f"<b>Рассылка</b>\n\nАктивных: {len(active)}", broadcast_setup_menu())
    await callback.answer()


@router.callback_query(F.data == "adm:bc:list")
async def broadcast_active_list(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    await state.clear()
    active = await get_active_broadcasts()
    if not active:
        await show_screen(callback.message, "Нет активных рассылок.", back_btn("adm:bc"))
        await callback.answer()
        return
    await show_screen(
        callback.message,
        "<b>Активные рассылки</b>\n\nНажмите на рассылку, чтобы остановить её:",
        broadcast_active_list_menu(active)
    )
    await callback.answer()


@router.callback_query(F.data.startswith("bc_stop_one_"))
async def broadcast_stop_one(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    await state.clear()
    bc_id = parse_cb_id(callback.data, "bc_stop_one_")
    if bc_id is not None:
        await stop_broadcast(bc_id)
        await callback.answer(f"Рассылка #{bc_id} остановлена", show_alert=True)
    active = await get_active_broadcasts()
    if not active:
        await show_screen(callback.message, "Все рассылки остановлены.", back_btn("adm:bc"))
    else:
        await show_screen(
            callback.message,
            "<b>Активные рассылки</b>\n\nНажмите на рассылку, чтобы остановить её:",
            broadcast_active_list_menu(active)
        )


@router.callback_query(F.data == "bc_with_photo")
async def bc_photo_start(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    await state.clear()
    await show_screen(callback.message, "Отправьте картинку или GIF:", back_btn("adm:bc"))
    await state.set_state(BroadcastPhoto.waiting_photo)
    await callback.answer()


@router.message(BroadcastPhoto.waiting_photo, F.photo)
async def bc_photo_receive(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    await state.update_data(photo_id=message.photo[-1].file_id, media_type="photo")
    await message.answer("Текст рассылки:")
    await state.set_state(BroadcastPhoto.waiting_text)


@router.message(BroadcastPhoto.waiting_photo, F.animation)
async def bc_gif_receive(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    await state.update_data(photo_id=message.animation.file_id, media_type="animation")
    await message.answer("Текст рассылки:")
    await state.set_state(BroadcastPhoto.waiting_text)


@router.message(BroadcastPhoto.waiting_photo)
async def bc_photo_wrong(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    await message.answer("Отправьте картинку или GIF.")


@router.message(BroadcastPhoto.waiting_text)
async def bc_photo_text(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    if not message.text:
        await message.answer("Введите текст.")
        return
    await state.update_data(bc_text=message.text)
    await message.answer("Кнопка-ссылка?\n<code>1</code> — да\n<code>0</code> — нет")
    await state.set_state(BroadcastPhoto.waiting_url_choice)


@router.message(BroadcastPhoto.waiting_url_choice)
async def bc_photo_url_choice(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    choice = parse_int(message.text)
    if choice not in (0, 1):
        await message.answer("1 или 0.")
        return
    if choice == 0:
        await state.update_data(btn_text="", btn_url="")
        await message.answer("Единица длительности:\n<code>0</code> — отправить 1 раз сейчас\n<code>1</code> — мин\n<code>2</code> — час\n<code>3</code> — дни")
        await state.set_state(BroadcastPhoto.waiting_duration_unit)
    else:
        await message.answer("Текст кнопки:")
        await state.set_state(BroadcastPhoto.waiting_url_text)


@router.message(BroadcastPhoto.waiting_url_text)
async def bc_photo_url_text(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    if not message.text or len(message.text) > 64:
        await message.answer("1-64 символа.")
        return
    await state.update_data(btn_text=message.text.strip())
    await message.answer("Ссылка:")
    await state.set_state(BroadcastPhoto.waiting_url_link)


@router.message(BroadcastPhoto.waiting_url_link)
async def bc_photo_url_link(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    url = (message.text or "").strip()
    if not url.startswith(("http://", "https://", "tg://")):
        await message.answer("http://, https:// или tg://")
        return
    await state.update_data(btn_url=url)
    await message.answer("Единица длительности:\n<code>0</code> — отправить 1 раз сейчас\n<code>1</code> — мин\n<code>2</code> — час\n<code>3</code> — дни")
    await state.set_state(BroadcastPhoto.waiting_duration_unit)


@router.message(BroadcastPhoto.waiting_duration_unit)
async def bc_photo_dur_unit(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    choice = parse_int(message.text)
    if choice not in (0, 1, 2, 3):
        await message.answer("0, 1, 2 или 3.")
        return

    data = await state.get_data()
    media_type = data.get("media_type", "photo")
    encoded = f"{media_type}|{data['photo_id']}|{data.get('btn_text', '')}|{data.get('btn_url', '')}"

    if choice == 0:
        bc_id = await create_broadcast(encoded, data["bc_text"], 0, 1, message.from_user.id)
        await state.clear()
        await message.answer(
            f"Разовая рассылка #{bc_id} создана и будет отправлена прямо сейчас.",
            reply_markup=back_btn("adm:panel")
        )
        return

    labels = {1: "минут", 2: "часов", 3: "дней"}
    await state.update_data(duration_unit=choice)
    await message.answer(f"Количество {labels[choice]}:")
    await state.set_state(BroadcastPhoto.waiting_duration)


@router.message(BroadcastPhoto.waiting_duration)
async def bc_photo_dur(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    value = parse_int(message.text)
    if value is None or value < 1:
        await message.answer("> 0.")
        return
    data = await state.get_data()
    unit = data["duration_unit"]
    if unit == 1:
        hours = value / 60
    elif unit == 2:
        hours = value
    else:
        hours = value * 24
    await state.update_data(duration_hours=hours, duration_value=value)
    await message.answer("Единица интервала:\n<code>1</code> — мин\n<code>2</code> — час\n<code>3</code> — дни")
    await state.set_state(BroadcastPhoto.waiting_interval_unit)


@router.message(BroadcastPhoto.waiting_interval_unit)
async def bc_photo_int_unit(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    choice = parse_int(message.text)
    if choice not in (1, 2, 3):
        await message.answer("1, 2 или 3.")
        return
    labels = {1: "минут", 2: "часов", 3: "дней"}
    await state.update_data(interval_unit=choice)
    await message.answer(f"Количество {labels[choice]}:")
    await state.set_state(BroadcastPhoto.waiting_interval)


@router.message(BroadcastPhoto.waiting_interval)
async def bc_photo_int(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    value = parse_int(message.text)
    if value is None or value < 1:
        await message.answer("> 0.")
        return
    data = await state.get_data()
    unit = data["interval_unit"]
    if unit == 1:
        ih = max(value / 60, 0.017)
    elif unit == 2:
        ih = value
    else:
        ih = value * 24
    dd = max(int(data["duration_hours"] / 24), 1)
    ihh = max(int(ih), 1)
    media_type = data.get("media_type", "photo")
    encoded = f"{media_type}|{data['photo_id']}|{data.get('btn_text', '')}|{data.get('btn_url', '')}"
    bc_id = await create_broadcast(encoded, data["bc_text"], dd, ihh, message.from_user.id)
    await state.clear()
    ul = {1: "мин", 2: "ч", 3: "дн"}
    await message.answer(
        f"Рассылка #{bc_id}\n{data['duration_value']} {ul[data['duration_unit']]}\nкаждые {value} {ul[data['interval_unit']]}",
        reply_markup=back_btn("adm:panel")
    )


@router.callback_query(F.data == "bc_text_only")
async def bc_text_start(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    await state.clear()
    await show_screen(callback.message, "Текст рассылки:", back_btn("adm:bc"))
    await state.set_state(BroadcastText.waiting_text)
    await callback.answer()


@router.message(BroadcastText.waiting_text)
async def bc_text_text(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    if not message.text:
        await message.answer("Введите текст.")
        return
    await state.update_data(bc_text=message.text)
    await message.answer("Кнопка-ссылка?\n<code>1</code> — да\n<code>0</code> — нет")
    await state.set_state(BroadcastText.waiting_url_choice)


@router.message(BroadcastText.waiting_url_choice)
async def bc_text_url_choice(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    choice = parse_int(message.text)
    if choice not in (0, 1):
        await message.answer("1 или 0.")
        return
    if choice == 0:
        await state.update_data(btn_text="", btn_url="")
        await message.answer("Единица длительности:\n<code>0</code> — отправить 1 раз сейчас\n<code>1</code> — мин\n<code>2</code> — час\n<code>3</code> — дни")
        await state.set_state(BroadcastText.waiting_duration_unit)
    else:
        await message.answer("Текст кнопки:")
        await state.set_state(BroadcastText.waiting_url_text)


@router.message(BroadcastText.waiting_url_text)
async def bc_text_url_text(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    if not message.text or len(message.text) > 64:
        await message.answer("1-64 символа.")
        return
    await state.update_data(btn_text=message.text.strip())
    await message.answer("Ссылка:")
    await state.set_state(BroadcastText.waiting_url_link)


@router.message(BroadcastText.waiting_url_link)
async def bc_text_url_link(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    url = (message.text or "").strip()
    if not url.startswith(("http://", "https://", "tg://")):
        await message.answer("http:// или https://")
        return
    await state.update_data(btn_url=url)
    await message.answer("Единица длительности:\n<code>0</code> — отправить 1 раз сейчас\n<code>1</code> — мин\n<code>2</code> — час\n<code>3</code> — дни")
    await state.set_state(BroadcastText.waiting_duration_unit)


@router.message(BroadcastText.waiting_duration_unit)
async def bc_text_dur_unit(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    choice = parse_int(message.text)
    if choice not in (0, 1, 2, 3):
        await message.answer("0, 1, 2 или 3.")
        return

    data = await state.get_data()
    encoded = f"text||{data.get('btn_text', '')}|{data.get('btn_url', '')}"

    if choice == 0:
        bc_id = await create_broadcast(encoded, data["bc_text"], 0, 1, message.from_user.id)
        await state.clear()
        await message.answer(
            f"Разовая рассылка #{bc_id} создана и будет отправлена прямо сейчас.",
            reply_markup=back_btn("adm:panel")
        )
        return

    labels = {1: "минут", 2: "часов", 3: "дней"}
    await state.update_data(duration_unit=choice)
    await message.answer(f"Количество {labels[choice]}:")
    await state.set_state(BroadcastText.waiting_duration)


@router.message(BroadcastText.waiting_duration)
async def bc_text_dur(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    value = parse_int(message.text)
    if value is None or value < 1:
        await message.answer("> 0.")
        return
    data = await state.get_data()
    unit = data["duration_unit"]
    if unit == 1:
        hours = value / 60
    elif unit == 2:
        hours = value
    else:
        hours = value * 24
    await state.update_data(duration_hours=hours, duration_value=value)
    await message.answer("Единица интервала:\n<code>1</code> — мин\n<code>2</code> — час\n<code>3</code> — дни")
    await state.set_state(BroadcastText.waiting_interval_unit)


@router.message(BroadcastText.waiting_interval_unit)
async def bc_text_int_unit(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    choice = parse_int(message.text)
    if choice not in (1, 2, 3):
        await message.answer("1, 2 или 3.")
        return
    labels = {1: "минут", 2: "часов", 3: "дней"}
    await state.update_data(interval_unit=choice)
    await message.answer(f"Количество {labels[choice]}:")
    await state.set_state(BroadcastText.waiting_interval)


@router.message(BroadcastText.waiting_interval)
async def bc_text_int(message: Message, state: FSMContext):
    if not await check_admin_msg(message, state):
        return
    value = parse_int(message.text)
    if value is None or value < 1:
        await message.answer("> 0.")
        return
    data = await state.get_data()
    unit = data["interval_unit"]
    if unit == 1:
        ih = max(value / 60, 0.017)
    elif unit == 2:
        ih = value
    else:
        ih = value * 24
    dd = max(int(data["duration_hours"] / 24), 1)
    ihh = max(int(ih), 1)
    encoded = f"text||{data.get('btn_text', '')}|{data.get('btn_url', '')}"
    bc_id = await create_broadcast(encoded, data["bc_text"], dd, ihh, message.from_user.id)
    await state.clear()
    ul = {1: "мин", 2: "ч", 3: "дн"}
    await message.answer(
        f"Рассылка #{bc_id}\n{data['duration_value']} {ul[data['duration_unit']]}\nкаждые {value} {ul[data['interval_unit']]}",
        reply_markup=back_btn("adm:panel")
    )


@router.callback_query(F.data == "bc_stop_all")
async def bc_stop(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    await state.clear()
    broadcasts = await get_active_broadcasts()
    for b in broadcasts:
        await stop_broadcast(b["id"])
    await show_screen(callback.message, f"Остановлено: {len(broadcasts)}", back_btn("adm:panel"))
    await callback.answer()


def _features_text(features: dict) -> str:
    on_count = sum(1 for k in FEATURE_LABELS if features.get(k, True))
    off_count = len(FEATURE_LABELS) - on_count
    hints = "\n".join(f"· {FEATURE_LABELS[k]} — {FEATURE_HINTS[k]}" for k in FEATURE_LABELS)
    return (
        f"<b>Функции</b>\n\n"
        f"Включено: <b>{on_count}</b>\nВыключено: <b>{off_count}</b>\n\n"
        f"Выключаете целый раздел — он закрывается для ВСЕХ (включая админов).\n"
        f"{hints}"
    )


@router.callback_query(F.data == "adm:feat")
async def admin_features(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    await state.clear()
    features = await get_all_features()
    await show_screen(callback.message, _features_text(features), features_menu(features))
    await callback.answer()


@router.callback_query(F.data.startswith("admf_"))
async def toggle_feature(callback: CallbackQuery, state: FSMContext):
    if not await check_admin(callback):
        return
    await state.clear()
    feature = callback.data.replace("admf_", "", 1)
    if feature not in FEATURE_LABELS:
        await callback.answer("Неизвестная функция", show_alert=True)
        return
    current = await is_feature_enabled(feature)
    new_state = not current
    await set_feature(feature, new_state)
    label = FEATURE_LABELS[feature]
    action = "включена" if new_state else "выключена"
    await callback.answer(f"{label} {action}", show_alert=False)

    features = await get_all_features()
    await show_screen(callback.message, _features_text(features), features_menu(features))