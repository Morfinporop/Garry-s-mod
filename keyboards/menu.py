from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton


def back_btn(to="back_main"):
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="< Назад", callback_data=to)]
    ])


def admin_menu():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="Статистика", callback_data="adm:stats")],
        [InlineKeyboardButton(text="Пользователи", callback_data="adm:users")],
        [InlineKeyboardButton(text="Промокоды", callback_data="adm:promos")],
        [InlineKeyboardButton(text="Подарок всем", callback_data="adm:gift")],
        [InlineKeyboardButton(text="Оповещение всем", callback_data="adm:notify")],
        [InlineKeyboardButton(text="Рассылка", callback_data="adm:bc")],
        [InlineKeyboardButton(text="Функции (вкл/выкл)", callback_data="adm:feat")],
        [InlineKeyboardButton(text="< Назад", callback_data="back_main")],
    ])


def users_list_menu(users: list, page: int, total_pages: int):
    buttons = [[InlineKeyboardButton(text="Найти по ID / нику", callback_data="adm:search")]]
    buttons.append([InlineKeyboardButton(text="Сортировка: сначала новые", callback_data="noop")])

    row = []
    for u in users:
        banned = " [бан]" if u["is_banned"] else ""
        nick = f"@{u['username']}" if u["username"] else f"id {u['user_id']}"
        label = f"{nick}{banned}"[:64]
        row.append(InlineKeyboardButton(text=label, callback_data=f"auc_{u['user_id']}"))
        if len(row) == 2:
            buttons.append(row)
            row = []
    if row:
        buttons.append(row)

    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="<", callback_data=f"adm:users:{page - 1}"))
    nav.append(InlineKeyboardButton(text=f"{page + 1}/{total_pages}", callback_data="noop"))
    if page < total_pages - 1:
        nav.append(InlineKeyboardButton(text=">", callback_data=f"adm:users:{page + 1}"))
    buttons.append(nav)
    buttons.append([InlineKeyboardButton(text="< Назад", callback_data="adm:panel")])
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def user_card_menu(user_id: int, is_banned: bool, auto_renew: bool):
    ren_label = f"Автопродление: {'вкл' if auto_renew else 'выкл'}"
    ban_btn = (
        [InlineKeyboardButton(text="Разбанить", callback_data=f"auunban_{user_id}")]
        if is_banned else
        [InlineKeyboardButton(text="Забанить", callback_data=f"auban_{user_id}")]
    )
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="+Баланс", callback_data=f"aubal_{user_id}"),
            InlineKeyboardButton(text="-Баланс", callback_data=f"aubal_{user_id}"),
        ],
        [
            InlineKeyboardButton(text="Выдать ключ", callback_data=f"aukey_{user_id}"),
            InlineKeyboardButton(text="Отозвать ключ", callback_data=f"aurev_{user_id}"),
        ],
        [InlineKeyboardButton(text=ren_label, callback_data=f"auren_{user_id}")],
        [
            InlineKeyboardButton(text="Уведомить", callback_data=f"aumsg_{user_id}"),
            InlineKeyboardButton(text="История", callback_data=f"auhist_{user_id}_0"),
        ],
        ban_btn,
        [
            InlineKeyboardButton(text="Найти", callback_data="adm:search"),
            InlineKeyboardButton(text="< К списку", callback_data="adm:users"),
        ],
    ])


def user_revoke_menu(keys: list, user_id: int):
    buttons = []
    for k in keys:
        multi = ""
        if k["max_users"]:
            multi = f" · {k['max_users']} чел"
        elif k["is_duo"]:
            multi = " · DUO"
        label = f"{k['tariff']}{multi} · до {k['expires_at']}"[:64]
        buttons.append([InlineKeyboardButton(text=label, callback_data=f"aurevk_{k['id']}")])
    buttons.append([InlineKeyboardButton(text="< Назад", callback_data=f"auc_{user_id}")])
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def user_revoke_confirm_menu(key_id: int, user_id: int):
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="Да, отозвать", callback_data=f"aurevc_{key_id}"),
            InlineKeyboardButton(text="Отмена", callback_data=f"auc_{user_id}"),
        ]
    ])


def user_history_menu(user_id: int, page: int, total_pages: int):
    buttons = []
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="<", callback_data=f"auhist_{user_id}_{page - 1}"))
    nav.append(InlineKeyboardButton(text=f"{page + 1}/{total_pages}", callback_data="noop"))
    if page < total_pages - 1:
        nav.append(InlineKeyboardButton(text=">", callback_data=f"auhist_{user_id}_{page + 1}"))
    if nav:
        buttons.append(nav)
    buttons.append([InlineKeyboardButton(text="< Назад", callback_data=f"auc_{user_id}")])
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def admin_promos_menu():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="Создать промокод", callback_data="adm:promo:new")],
        [InlineKeyboardButton(text="Список промокодов", callback_data="adm:promo:list")],
        [InlineKeyboardButton(text="Удалить промокод", callback_data="adm:promo:del")],
        [InlineKeyboardButton(text="< Назад", callback_data="adm:panel")],
    ])


def broadcast_setup_menu():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="С картинкой/GIF", callback_data="bc_with_photo")],
        [InlineKeyboardButton(text="Только текст", callback_data="bc_text_only")],
        [InlineKeyboardButton(text="Активные рассылки", callback_data="adm:bc:list")],
        [InlineKeyboardButton(text="Остановить все", callback_data="bc_stop_all")],
        [InlineKeyboardButton(text="< Назад", callback_data="adm:panel")],
    ])


def broadcast_active_list_menu(broadcasts: list):
    buttons = []
    for b in broadcasts:
        short_text = (b["text"] or "")[:26]
        buttons.append([InlineKeyboardButton(
            text=f"#{b['id']} · {short_text}",
            callback_data=f"bc_stop_one_{b['id']}"
        )])
    buttons.append([InlineKeyboardButton(text="< Назад", callback_data="adm:bc")])
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def promo_post_kb(bot_username: str):
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(
            text="Активировать в боте",
            url=f"https://t.me/{bot_username}?start=promo"
        )]
    ])


def broadcast_url_kb(button_text: str, url: str):
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=button_text, url=url)]
    ])


FEATURE_LABELS = {
    "shop":    "Магазин",
    "topup":   "Баланс",
    "profile": "Профиль",
    "promo":   "Промокод",
}

FEATURE_HINTS = {
    "shop":    "покупки, мульти, триал",
    "topup":   "пополнение баланса",
    "profile": "профиль, ключи, история, пополнение",
    "promo":   "ввод промокодов",
}


def features_menu(features: dict):
    buttons = []
    for key, label in FEATURE_LABELS.items():
        state = features.get(key, True)
        state_text = "вкл" if state else "выкл"
        buttons.append([InlineKeyboardButton(
            text=f"{label} — {state_text}",
            callback_data=f"admf_{key}"
        )])
    buttons.append([InlineKeyboardButton(text="< Назад", callback_data="adm:panel")])
    return InlineKeyboardMarkup(inline_keyboard=buttons)