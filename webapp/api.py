import asyncio
import logging
import os
import re
import time
import uuid
from pathlib import Path
from datetime import datetime

from fastapi import FastAPI, Header, HTTPException, Depends, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, FileResponse
from pydantic import BaseModel

from webapp.auth import validate_init_data, extract_user_id
from webapp import extra_store
from database.db import (
    get_user, get_balance, get_user_active_keys,
    get_user_transactions, get_user_transactions_count,
    is_admin, create_payment_record, get_payment_by_id,
    add_balance, add_transaction, mark_payment_completed,
    deduct_balance, create_key, get_user_keys_count,
    has_used_trial, mark_trial_used, unmark_trial, use_promo,
    apply_promo_bonus_days, is_section_enabled,
    MAX_KEYS_PER_USER,
    get_users_count, get_all_keys_count, get_revenue_stats,
    get_tariff_stats, get_funnel_stats, get_all_users, search_users,
    user_exists, get_user_active_keys_with_id,
    get_key_by_id, deactivate_key, set_user_auto_renew_all,
    get_user_purchase_summary, ban_user, unban_user,
    create_promo, get_all_promos, delete_promo, get_promo,
    add_promo_post, get_promo_posts,
    create_broadcast, get_active_broadcasts, stop_broadcast,
    is_feature_enabled, set_feature, get_all_features,
    extend_key, get_referral_stats,
)
from utils.payments import create_payment, check_payment
from keyboards.menu import promo_post_kb, FEATURE_LABELS, FEATURE_HINTS
from config import (
    MIN_TOPUP, MAX_TOPUP, TARIFFS, MULTI_TARIFFS, MULTI_ORDER,
    TRIAL_CHANNEL_ID, TRIAL_CHANNEL_URL, TRIAL_DAYS, TRIAL_TARIFF,
    REFERRAL_BONUS,
    DB_PATH as MAIN_DB_PATH,
)

logger = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN") or None
BOT = None
BOT_USERNAME: str | None = None

_avatar_cache: dict[int, dict] = {}
AVATAR_CACHE_TTL = 600

_user_action_locks: dict[int, asyncio.Lock] = {}


def _get_user_lock(user_id: int) -> asyncio.Lock:
    lock = _user_action_locks.get(user_id)
    if lock is None:
        lock = asyncio.Lock()
        _user_action_locks[user_id] = lock
    return lock


def _reject_parallel(user_id: int) -> asyncio.Lock:
    lock = _get_user_lock(user_id)
    if lock.locked():
        raise HTTPException(409, "Предыдущая операция ещё выполняется, подождите")
    return lock


def set_bot_token(token: str) -> None:
    global BOT_TOKEN
    BOT_TOKEN = token


def set_bot(bot) -> None:
    global BOT
    BOT = bot


def set_bot_username(username: str) -> None:
    global BOT_USERNAME
    BOT_USERNAME = username


app = FastAPI(title="FlowVPN Mini App API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = Path(__file__).resolve().parent / "static"

PERSISTENT_DIR = Path(MAIN_DB_PATH).resolve().parent
BANNER_UPLOAD_DIR = PERSISTENT_DIR / "uploads" / "banners"
BROADCAST_UPLOAD_DIR = PERSISTENT_DIR / "uploads" / "broadcasts"

for d in (BANNER_UPLOAD_DIR, BROADCAST_UPLOAD_DIR):
    try:
        d.mkdir(parents=True, exist_ok=True)
    except Exception:
        logger.exception("Failed to create upload dir: %s", d)

ALLOWED_MEDIA_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
MAX_FILE_SIZE = 8 * 1024 * 1024

_pending_promo: dict[int, dict] = {}


@app.on_event("startup")
async def _on_startup():
    await extra_store.init()


@app.on_event("shutdown")
async def _on_shutdown():
    await extra_store.close()


@app.get("/api/health")
async def api_health():
    return {"ok": True, "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}


async def get_current_user_id(x_telegram_init_data: str = Header(default="")) -> int:
    if not BOT_TOKEN:
        raise HTTPException(500, "Bot token not configured")

    if not x_telegram_init_data:
        raise HTTPException(401, "Приложение открыто не через Telegram — initData отсутствует. Перезайдите через бота.")

    validated, error = validate_init_data(x_telegram_init_data, BOT_TOKEN)

    if not validated:
        reason_messages = {
            "parse_error": "Не удалось прочитать данные Telegram. Перезайдите в приложение.",
            "no_hash": "В данных Telegram отсутствует подпись. Перезайдите в приложение.",
            "bad_signature": "Подпись Telegram не совпадает. Закройте и снова откройте приложение через бота.",
            "expired": "Сессия Telegram устарела. Закройте и снова откройте приложение.",
            "bad_json": "Повреждены данные профиля Telegram. Перезайдите в приложение.",
            "empty": "Приложение открыто не через Telegram.",
        }
        msg = reason_messages.get(error, "Не удалось подтвердить вход через Telegram. Перезайдите в приложение.")
        logger.warning(f"get_current_user_id auth rejected, reason={error}")
        raise HTTPException(401, msg)

    user_id = extract_user_id(validated)
    if not user_id:
        raise HTTPException(401, "В данных Telegram не найден пользователь")

    user = await get_user(user_id)
    if user and user["is_banned"]:
        reason = user["ban_reason"] or "не указана"
        raise HTTPException(403, f"Аккаунт заблокирован администратором. Причина: {reason}")

    return user_id


async def get_admin_user_id(user_id: int = Depends(get_current_user_id)) -> int:
    if not await is_admin(user_id):
        raise HTTPException(403, "Доступ запрещён")
    return user_id


_HTML_TAG_RE = re.compile(r"<[^>]+>")


async def push_notification(user_id: int, text: str, also_telegram: bool = True) -> None:
    plain = _HTML_TAG_RE.sub("", text).strip()

    try:
        await extra_store.push_notification(user_id, plain)
    except Exception:
        logger.exception(f"push_notification DB error for {user_id}")

    if also_telegram and BOT is not None:
        try:
            await BOT.send_message(user_id, text)
        except Exception:
            logger.debug(f"push_notification telegram send error for {user_id}")


def _estimate_key_price(tariff_name: str) -> int:
    for t in TARIFFS.values():
        if t.get("name") == tariff_name:
            return t.get("price", 0)
    for t in MULTI_TARIFFS.values():
        if t.get("name") == tariff_name or t.get("title") == tariff_name:
            return t.get("price", 0)
    return 0


@app.get("/api/profile")
async def api_profile(user_id: int = Depends(get_current_user_id)):
    user = await get_user(user_id)
    if not user:
        raise HTTPException(404, "User not found")

    balance = await get_balance(user_id)
    admin = await is_admin(user_id)
    trial_used = await has_used_trial(user_id)
    profile_enabled = await is_feature_enabled("profile")

    return {
        "id": user_id,
        "username": user["username"] or "",
        "balance": balance,
        "is_admin": admin,
        "trial_used": trial_used,
        "trial_days": TRIAL_DAYS,
        "topup_enabled": await is_section_enabled("topup"),
        "profile_enabled": profile_enabled,
    }


@app.get("/api/keys")
async def api_keys(user_id: int = Depends(get_current_user_id)):
    if not await is_feature_enabled("profile"):
        raise HTTPException(403, "Раздел временно отключён")
    keys = await get_user_active_keys(user_id)
    return [
        {
            "id": k["id"],
            "key_value": k["key_value"],
            "tariff": k["tariff"],
            "expires_at": k["expires_at"],
            "is_duo": bool(k["is_duo"]),
            "max_users": k["max_users"],
            "auto_renew": bool(k["auto_renew"]),
            "key_type": k["key_source"] or "purchased",
        }
        for k in keys
    ]


@app.delete("/api/keys/{key_id}")
async def api_delete_key(key_id: int, user_id: int = Depends(get_current_user_id)):
    if not await is_feature_enabled("profile"):
        raise HTTPException(403, "Раздел временно отключён")
    key = await get_key_by_id(key_id)
    if not key or key["user_id"] != user_id:
        raise HTTPException(404, "Ключ не найден")
    if not key["is_active"]:
        raise HTTPException(400, "Ключ уже неактивен")

    source = key["key_source"] or "purchased"
    if source != "purchased":
        raise HTTPException(403, "Этот ключ нельзя удалить самостоятельно")

    price_paid = key["price_paid"] or 0
    if price_paid <= 0:
        price_paid = _estimate_key_price(key["tariff"])

    refund = 0
    if price_paid > 0:
        try:
            created = datetime.strptime(key["created_at"], "%Y-%m-%d %H:%M")
            expires = datetime.strptime(key["expires_at"], "%Y-%m-%d %H:%M")
            total_seconds = (expires - created).total_seconds()
            remaining_seconds = (expires - datetime.now()).total_seconds()
            if total_seconds > 0 and remaining_seconds > 0:
                fraction = min(1.0, remaining_seconds / total_seconds)
                refund = int(price_paid * fraction)
        except Exception:
            refund = 0

    await deactivate_key(key_id)

    if refund > 0:
        await add_balance(user_id, refund)
        await add_transaction(user_id, refund, "refund", f"Возврат за удалённый ключ «{key['tariff']}»")

    balance = await get_balance(user_id)
    return {"refund": refund, "balance": balance}


# ──────────────────────────────────────────────────────────────
# 📱 Подключённые устройства ключа (кто пользуется вашим VPN)
# ──────────────────────────────────────────────────────────────

def _check_own_active_key(key, user_id: int):
    if not key or key["user_id"] != user_id:
        raise HTTPException(404, "Ключ не найден")
    if not key["is_active"]:
        raise HTTPException(400, "Ключ неактивен")


async def _resolve_key_panel_email(key) -> str:
    from xui_api import _resolve_client_email

    ref = (key["proxy_address"] or "").strip()
    if not ref:
        raise HTTPException(404, "Ключ не привязан к VPN-серверу")
    try:
        email = await asyncio.wait_for(_resolve_client_email(ref), timeout=20)
    except Exception:
        email = None
    if not email:
        raise HTTPException(503, "VPN-сервер временно не отвечает, попробуйте позже")
    return email


def _normalize_panel_device(d: dict) -> dict:
    return {
        "id": d.get("id"),
        "kind": "device",
        "model": str(d.get("deviceModel") or "")[:80],
        "os": str(d.get("deviceOs") or "")[:40],
        "os_version": str(d.get("osVersion") or "")[:40],
        "user_agent": str(d.get("userAgent") or "")[:160],
        "first_seen": d.get("firstSeen") or 0,
        "last_seen": d.get("lastSeen") or 0,
    }


@app.get("/api/keys/{key_id}/devices")
async def api_key_devices(key_id: int, user_id: int = Depends(get_current_user_id)):
    """Список устройств, которые подключались к конкретному ключу пользователя."""
    if not await is_feature_enabled("profile"):
        raise HTTPException(403, "Раздел временно отключён")
    key = await get_key_by_id(key_id)
    _check_own_active_key(key, user_id)
    email = await _resolve_key_panel_email(key)

    from xui_api import get_client_devices, get_client_ips

    hwid_devices, ips = await asyncio.gather(
        get_client_devices(email), get_client_ips(email)
    )

    devices = [_normalize_panel_device(d) for d in hwid_devices]
    devices.sort(key=lambda d: d.get("last_seen") or 0, reverse=True)
    if devices:
        return {"mode": "hwid", "devices": devices}

    ip_devices = [{"id": None, "kind": "ip", "ip": ip} for ip in sorted(ips)]
    return {"mode": "ip" if ip_devices else "none", "devices": ip_devices}


@app.delete("/api/keys/{key_id}/devices/{device_id}")
async def api_key_delete_device(key_id: int, device_id: int, user_id: int = Depends(get_current_user_id)):
    """Отключить конкретное устройство от ключа — оно теряет доступ к VPN."""
    if not await is_feature_enabled("profile"):
        raise HTTPException(403, "Раздел временно отключён")
    key = await get_key_by_id(key_id)
    _check_own_active_key(key, user_id)
    email = await _resolve_key_panel_email(key)

    from xui_api import delete_client_device, clear_client_ips, get_client_devices, revoke_client_configs

    ok = await delete_client_device(email, device_id)
    if not ok:
        # Повторное нажатие после частично выполненного удаления:
        # если устройства уже нет в журнале — считаем удаление состоявшимся
        # и доигрываем остальные шаги.
        current = await get_client_devices(email)
        if any(isinstance(d, dict) and d.get("id") == device_id for d in current):
            raise HTTPException(502, "Не удалось отключить устройство. Попробуйте ещё раз")

    # ВАЖНО: вместе с HWID-записью убираем и IP-записи клиента,
    # иначе устройство останется висеть «безымянным» IP-подключением
    # и фактически не отключится от VPN.
    if not await clear_client_ips(email):
        logger.warning(f"[devices] HWID {device_id} удалён, но IP-записи {email} очистить не удалось")

    # ЖЁСТКИЙ ВЫБРОС: новый UUID моментально рвёт подключения по старым
    # конфигам (устройство вылетает из сети, даже если сидит в VPN прямо
    # сейчас), а лимит HWID = числу оставшихся устройств не даёт удалённому
    # устройству ещё раз скачать конфиг по подписке — назад дороги нет.
    remaining = await get_client_devices(email)
    slots = max(1, len(remaining))
    if not await revoke_client_configs(email, hwid_slots=slots):
        logger.error(f"[devices] HWID {device_id} удалён, но сброс доступа не удался: {email}")
        raise HTTPException(
            502,
            "Устройство отключено, но не получилось оборвать его соединение. "
            "Нажмите «Отключить» ещё раз",
        )
    return {"ok": True}


@app.delete("/api/keys/{key_id}/ip-devices/{ip}")
async def api_key_delete_ip_device(key_id: int, ip: str, user_id: int = Depends(get_current_user_id)):
    """Сбросить IP-подключения ключа (для устройств без HWID-идентификатора)."""
    if not await is_feature_enabled("profile"):
        raise HTTPException(403, "Раздел временно отключён")
    key = await get_key_by_id(key_id)
    _check_own_active_key(key, user_id)
    email = await _resolve_key_panel_email(key)

    from xui_api import clear_client_ips, revoke_client_configs

    ok = await clear_client_ips(email)
    if not ok:
        raise HTTPException(502, "Не удалось отключить устройство. Попробуйте ещё раз")

    # Рвём активное соединение: новый UUID — и все ранее выданные конфиги
    # этого ключа мертвы. Лимит HWID здесь не трогаем: у устройств без
    # HWID-идентификатора включение HWID-проверки заблокировало бы и
    # владельца ключа.
    if not await revoke_client_configs(email):
        logger.error(f"[devices] IP-лог {email} очищен, но сброс доступа не удался")
        raise HTTPException(
            502,
            "Подключения сброшены, но не получилось оборвать активное соединение. "
            "Нажмите «Отключить» ещё раз",
        )
    return {"ok": True}


@app.get("/api/history")
async def api_history(page: int = 0, user_id: int = Depends(get_current_user_id)):
    if not await is_feature_enabled("profile"):
        raise HTTPException(403, "Раздел временно отключён")
    per_page = 10
    total = await get_user_transactions_count(user_id)
    txs = await get_user_transactions(user_id, limit=per_page, offset=page * per_page)

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "items": [
            {"amount": t["amount"], "type": t["type"], "description": t["description"], "created_at": t["created_at"]}
            for t in txs
        ],
    }


@app.get("/api/referral")
async def api_referral(user_id: int = Depends(get_current_user_id)):
    stats = await get_referral_stats(user_id)
    link = f"https://t.me/{BOT_USERNAME}?start=ref{user_id}" if BOT_USERNAME else ""

    return {
        "invited_count": stats["invited_count"],
        "earned": stats["earned"],
        "bonus_per_referral": REFERRAL_BONUS,
        "link": link,
    }


@app.get("/api/avatar/{uid}")
async def api_avatar(uid: int):
    if BOT is None:
        raise HTTPException(404, "no bot")

    now = time.monotonic()
    cached = _avatar_cache.get(uid)

    if cached and (now - cached["ts"]) < AVATAR_CACHE_TTL:
        if cached["data"] is None:
            raise HTTPException(404, "no photo")
        return Response(content=cached["data"], media_type="image/jpeg")

    try:
        photos = await BOT.get_user_profile_photos(uid, limit=1)
    except Exception:
        _avatar_cache[uid] = {"ts": now, "unique_id": None, "data": None}
        raise HTTPException(404, "no photo")

    if not photos or photos.total_count == 0:
        _avatar_cache[uid] = {"ts": now, "unique_id": None, "data": None}
        raise HTTPException(404, "no photo")

    photo = photos.photos[0][-1]

    if cached and cached.get("unique_id") == photo.file_unique_id and cached.get("data"):
        cached["ts"] = now
        return Response(content=cached["data"], media_type="image/jpeg")

    try:
        file = await BOT.get_file(photo.file_id)
        buf = await BOT.download_file(file.file_path)
        data = buf.read()
    except Exception:
        raise HTTPException(404, "download failed")

    _avatar_cache[uid] = {"ts": now, "unique_id": photo.file_unique_id, "data": data}
    return Response(content=data, media_type="image/jpeg")


@app.get("/api/topup/limits")
async def api_topup_limits(_: int = Depends(get_current_user_id)):
    return {"min": MIN_TOPUP, "max": MAX_TOPUP}


class TopupRequest(BaseModel):
    amount: int


@app.post("/api/topup")
async def api_topup(body: TopupRequest, user_id: int = Depends(get_current_user_id)):
    if not await is_section_enabled("topup"):
        raise HTTPException(403, "Функция временно отключена")

    if body.amount < MIN_TOPUP or body.amount > MAX_TOPUP:
        raise HTTPException(400, f"Сумма должна быть от {MIN_TOPUP} до {MAX_TOPUP} ₽")

    result = await asyncio.to_thread(create_payment, user_id, body.amount)
    if not result:
        raise HTTPException(502, "Не удалось создать платёж")

    payment_id, url = result
    await create_payment_record(payment_id, user_id, body.amount)

    return {"payment_id": payment_id, "url": url}


@app.get("/api/payment/{payment_id}/status")
async def api_payment_status(payment_id: str, user_id: int = Depends(get_current_user_id)):
    payment = await get_payment_by_id(payment_id)
    if not payment or payment["user_id"] != user_id:
        raise HTTPException(404, "Payment not found")

    if payment["status"] == "succeeded":
        balance = await get_balance(user_id)
        return {"status": "succeeded", "balance": balance}

    if payment["status"] == "pending":
        status = await asyncio.to_thread(check_payment, payment_id)
        if status == "succeeded" and await mark_payment_completed(payment_id):
            await add_balance(user_id, payment["amount"])
            await add_transaction(user_id, payment["amount"], "topup", f"Пополнение через Mini App ({payment_id})")
            balance = await get_balance(user_id)
            return {"status": "succeeded", "balance": balance}

    return {"status": payment["status"]}


@app.get("/api/tariffs")
async def api_tariffs(user_id: int = Depends(get_current_user_id)):
    trial_used = await has_used_trial(user_id)
    pending = _pending_promo.get(user_id)
    discount_pct = pending["discount_percent"] if pending else 0

    tariffs = []
    for key, t in TARIFFS.items():
        price = t["price"]
        if discount_pct:
            price = int(price * (100 - discount_pct) / 100)
        tariffs.append({"key": key, "name": t["name"], "price": price, "original_price": t["price"] if discount_pct else None, "days": t["days"]})

    multi = []
    for key in MULTI_ORDER:
        t = MULTI_TARIFFS[key]
        price = t["price"]
        if discount_pct:
            price = int(price * (100 - discount_pct) / 100)
        multi.append({"key": key, "title": t["title"], "name": t["name"], "price": price, "original_price": t["price"] if discount_pct else None, "days": t["days"], "max_users": t["max_users"], "savings": t.get("savings")})

    return {
        "tariffs": tariffs, "multi": multi, "show_trial": not trial_used,
        "trial_days": TRIAL_DAYS, "discount_percent": discount_pct,
        "shop_enabled": await is_section_enabled("shop"),
    }


async def _check_trial_subscription(user_id: int) -> bool:
    if BOT is None:
        return False
    try:
        member = await BOT.get_chat_member(TRIAL_CHANNEL_ID, user_id)
        return member.status in ("member", "administrator", "creator")
    except Exception:
        return False


@app.get("/api/trial/subscription")
async def api_trial_subscription(user_id: int = Depends(get_current_user_id)):
    subscribed = await _check_trial_subscription(user_id)
    return {"subscribed": subscribed, "channel_url": TRIAL_CHANNEL_URL}


@app.post("/api/trial/claim")
async def api_trial_claim(user_id: int = Depends(get_current_user_id)):
    lock = _reject_parallel(user_id)
    async with lock:
        if not await is_section_enabled("shop"):
            raise HTTPException(403, "Функция временно отключена")

        if await has_used_trial(user_id):
            raise HTTPException(400, "Пробный период уже использован")

        subscribed = await _check_trial_subscription(user_id)
        if not subscribed:
            raise HTTPException(403, "Подпишитесь на канал, чтобы получить пробный период")

        if not await mark_trial_used(user_id):
            raise HTTPException(400, "Пробный период уже использован")

        try:
            existing_keys = await get_user_active_keys(user_id)
        except Exception:
            logger.exception("api_trial_claim: get keys error for %s", user_id)
            existing_keys = []

        purchased_keys = [k for k in existing_keys if (k["key_source"] or "purchased") == "purchased"]

        target_key = None
        if purchased_keys:
            target_key = min(purchased_keys, key=lambda k: k["expires_at"])
        elif existing_keys:
            target_key = min(existing_keys, key=lambda k: k["expires_at"])

        if target_key:
            try:
                new_expiry = await extend_key(target_key["id"], TRIAL_DAYS)
            except Exception:
                logger.exception("api_trial_claim: extend key error for %s", user_id)
                await unmark_trial(user_id)
                raise HTTPException(502, "Не удалось продлить ключ, обратитесь в поддержку")

            return {
                "key": target_key["key_value"],
                "tariff": target_key["tariff"],
                "days": TRIAL_DAYS,
                "expires_at": new_expiry,
                "extended": True,
            }

        try:
            key = await create_key(user_id, TRIAL_TARIFF, days=TRIAL_DAYS, source="trial")
        except Exception:
            logger.exception("api_trial_claim: create key error for %s", user_id)
            await unmark_trial(user_id)
            raise HTTPException(502, "Не удалось создать ключ, обратитесь в поддержку")

        return {"key": key, "days": TRIAL_DAYS, "extended": False}


class BuyRequest(BaseModel):
    tariff_key: str


@app.post("/api/buy")
async def api_buy(body: BuyRequest, user_id: int = Depends(get_current_user_id)):
    lock = _reject_parallel(user_id)
    async with lock:
        if not await is_section_enabled("shop"):
            raise HTTPException(403, "Функция временно отключена")

        tariff = TARIFFS.get(body.tariff_key)
        if not tariff:
            raise HTTPException(404, "Тариф не найден")

        keys_count = await get_user_keys_count(user_id)
        admin = await is_admin(user_id)
        if not admin and keys_count >= MAX_KEYS_PER_USER:
            raise HTTPException(400, f"Лимит ключей ({MAX_KEYS_PER_USER}) исчерпан")

        price = tariff["price"]
        pending = _pending_promo.pop(user_id, None)
        if pending and pending.get("discount_percent", 0) > 0:
            price = int(price * (100 - pending["discount_percent"]) / 100)

        success = await deduct_balance(user_id, price)
        if not success:
            if pending:
                _pending_promo[user_id] = pending
            raise HTTPException(400, "Недостаточно средств")

        try:
            key = await create_key(user_id, tariff["name"], days=tariff["days"], source="purchased", price_paid=price)
        except Exception:
            await add_balance(user_id, price)
            if pending:
                _pending_promo[user_id] = pending
            logger.exception("api_buy: create key error")
            raise HTTPException(502, "Ошибка создания ключа, средства возвращены")

        await add_transaction(user_id, -price, "purchase", f"Покупка {tariff['name']}")

        return {"key": key, "tariff": tariff["name"], "days": tariff["days"], "price": price}


class BuyMultiRequest(BaseModel):
    multi_key: str


@app.post("/api/buy-multi")
async def api_buy_multi(body: BuyMultiRequest, user_id: int = Depends(get_current_user_id)):
    lock = _reject_parallel(user_id)
    async with lock:
        if not await is_section_enabled("shop"):
            raise HTTPException(403, "Функция временно отключена")

        tariff = MULTI_TARIFFS.get(body.multi_key)
        if not tariff:
            raise HTTPException(404, "Тариф не найден")

        keys_count = await get_user_keys_count(user_id)
        admin = await is_admin(user_id)
        if not admin and keys_count >= MAX_KEYS_PER_USER:
            raise HTTPException(400, f"Лимит ключей ({MAX_KEYS_PER_USER}) исчерпан")

        price = tariff["price"]
        pending = _pending_promo.pop(user_id, None)
        if pending and pending.get("discount_percent", 0) > 0:
            price = int(price * (100 - pending["discount_percent"]) / 100)

        success = await deduct_balance(user_id, price)
        if not success:
            if pending:
                _pending_promo[user_id] = pending
            raise HTTPException(400, "Недостаточно средств")

        try:
            key = await create_key(user_id, tariff["name"], days=tariff["days"], max_users=tariff["max_users"], source="purchased", price_paid=price)
        except Exception:
            await add_balance(user_id, price)
            if pending:
                _pending_promo[user_id] = pending
            logger.exception("api_buy_multi: create key error")
            raise HTTPException(502, "Ошибка создания ключа, средства возвращены")

        await add_transaction(user_id, -price, "purchase_multi", f"Покупка Мульти {tariff['title']}")

        return {"key": key, "tariff": tariff["title"], "days": tariff["days"], "price": price, "max_users": tariff["max_users"]}


class PromoRequest(BaseModel):
    code: str


@app.post("/api/promo/use")
async def api_promo_use(body: PromoRequest, user_id: int = Depends(get_current_user_id)):
    if not await is_section_enabled("promo"):
        raise HTTPException(403, "Функция временно отключена")

    code = body.code.strip().upper()
    if not code:
        raise HTTPException(400, "Промокод не может быть пустым")

    result = await use_promo(user_id, code)
    if not result:
        raise HTTPException(404, "Промокод не найден, истёк или уже использован")

    discount = result["discount"]
    bonus_days = result["bonus_days"]
    discount_pct = result["discount_percent"]

    response = {"discount": discount, "bonus_days": 0, "discount_percent": discount_pct}

    if discount > 0:
        await add_balance(user_id, discount)
        await add_transaction(user_id, discount, "promo", f"Промокод {code}")

    if bonus_days > 0:
        result_bonus = await apply_promo_bonus_days(user_id, bonus_days)
        if result_bonus:
            action, info = result_bonus
            response["bonus_days"] = bonus_days
            response["bonus_action"] = action
            response["bonus_info"] = info

    if discount_pct > 0:
        _pending_promo[user_id] = dict(result)

    balance = await get_balance(user_id)
    response["balance"] = balance
    return response


@app.get("/api/promo/status")
async def api_promo_status(user_id: int = Depends(get_current_user_id)):
    pending = _pending_promo.get(user_id)
    return {"discount_percent": pending["discount_percent"] if pending else 0}


@app.get("/api/reviews/summary")
async def api_reviews_summary():
    return await extra_store.review_summary()


@app.get("/api/reviews/my")
async def api_reviews_my(user_id: int = Depends(get_current_user_id)):
    has = await extra_store.has_reviewed(user_id)
    return {"has_reviewed": has}


@app.get("/api/reviews")
async def api_reviews_list(user_id: int = Depends(get_current_user_id)):
    admin = await is_admin(user_id)
    items = await extra_store.list_reviews()
    result = []
    for r in items:
        is_anon = bool(r["is_anonymous"])
        display = "Аноним" if is_anon else (f"@{r['username']}" if r["username"] else f"ID {r['user_id']}")
        item = {
            "id": r["id"], "rating": r["rating"], "comment": r["comment"] or "",
            "created_at": r["created_at"], "display_name": display, "is_anonymous": is_anon,
            "is_hearted": bool(r["is_hearted"]),
        }
        if not is_anon or admin:
            item["user_id"] = r["user_id"]
        result.append(item)
    return result


class ReviewCreate(BaseModel):
    rating: int
    comment: str = ""
    anonymous: bool = False


@app.post("/api/reviews")
async def api_reviews_create(body: ReviewCreate, user_id: int = Depends(get_current_user_id)):
    if body.rating < 1 or body.rating > 5:
        raise HTTPException(400, "Оценка от 1 до 5")

    if await extra_store.has_reviewed(user_id):
        raise HTTPException(409, "Вы уже оставляли отзыв — можно оставить только один")

    user = await get_user(user_id)
    username = user["username"] if user else ""
    await extra_store.add_review(user_id, username, body.rating, body.comment.strip()[:500], body.anonymous)
    return {"ok": True}


@app.delete("/api/admin/reviews/{review_id}")
async def admin_delete_review(review_id: int, _: int = Depends(get_admin_user_id)):
    ok = await extra_store.delete_review(review_id)
    if not ok:
        raise HTTPException(404, "Отзыв не найден")
    return {"ok": True}


@app.post("/api/admin/reviews/{review_id}/heart")
async def admin_toggle_review_heart(review_id: int, _: int = Depends(get_admin_user_id)):
    items = await extra_store.list_reviews()
    review = next((r for r in items if r["id"] == review_id), None)
    if not review:
        raise HTTPException(404, "Отзыв не найден")

    new_state = not bool(review["is_hearted"])
    ok = await extra_store.set_review_heart(review_id, new_state)
    if not ok:
        raise HTTPException(404, "Отзыв не найден")
    return {"id": review_id, "is_hearted": new_state}


@app.get("/api/notifications")
async def api_notifications(user_id: int = Depends(get_current_user_id)):
    items = await extra_store.get_notifications(user_id)
    return [{"id": n["id"], "text": n["text"], "is_read": bool(n["is_read"]), "created_at": n["created_at"]} for n in items]


@app.post("/api/notifications/read-all")
async def api_notifications_read_all(user_id: int = Depends(get_current_user_id)):
    await extra_store.mark_all_read(user_id)
    return {"ok": True}


@app.get("/api/banners/{placement}")
async def api_banners_for_placement(placement: str):
    items = await extra_store.get_banners_for_placement(placement)
    return [
        {"id": b["id"], "image_url": b["image_url"], "link_url": b["link_url"], "expires_at": b["expires_at"]}
        for b in items
    ]


@app.get("/api/admin/banners")
async def admin_list_banners(_: int = Depends(get_admin_user_id)):
    return await extra_store.list_all_banners()


@app.post("/api/admin/banners/{placement}/upload")
async def admin_upload_banner(
    placement: str,
    file: UploadFile = File(...),
    _: int = Depends(get_admin_user_id),
):
    if placement not in ("home", "shop", "profile", "promo"):
        raise HTTPException(400, "Некорректное размещение")

    ext = Path(file.filename or "").suffix.lower()
    if ext not in ALLOWED_MEDIA_EXT:
        raise HTTPException(400, "Разрешены только изображения (jpg, png, webp) и GIF")

    content = await file.read()
    if not content:
        raise HTTPException(400, "Пустой файл")
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(400, "Файл слишком большой (максимум 8 МБ)")

    filename = f"{placement}_{uuid.uuid4().hex}{ext}"
    filepath = BANNER_UPLOAD_DIR / filename

    try:
        with open(filepath, "wb") as f:
            f.write(content)
    except Exception:
        logger.exception("admin_upload_banner: save file error")
        raise HTTPException(502, "Не удалось сохранить файл")

    return {"image_url": f"/uploads/banners/{filename}"}


class BannerCreate(BaseModel):
    image_url: str
    link_url: str = ""
    expires_at: str | None = None


@app.post("/api/admin/banners/{placement}")
async def admin_add_banner(placement: str, body: BannerCreate, _: int = Depends(get_admin_user_id)):
    if placement not in ("home", "shop", "profile", "promo"):
        raise HTTPException(400, "Некорректное размещение")
    if not body.image_url.strip():
        raise HTTPException(400, "Укажите картинку")

    expires_at = body.expires_at.strip() if body.expires_at else None
    if expires_at:
        try:
            datetime.strptime(expires_at, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(400, "Дата должна быть в формате ГГГГ-ММ-ДД")

    new_id = await extra_store.add_banner(placement, body.image_url.strip(), body.link_url.strip(), True, expires_at)
    return {"id": new_id, "ok": True}


@app.delete("/api/admin/banners/{banner_id}")
async def admin_delete_banner_by_id(banner_id: int, _: int = Depends(get_admin_user_id)):
    ok = await extra_store.delete_banner_by_id(banner_id)
    if not ok:
        raise HTTPException(404, "Баннер не найден")
    return {"ok": True}


@app.post("/api/admin/banners/{banner_id}/toggle")
async def admin_toggle_banner_by_id(banner_id: int, _: int = Depends(get_admin_user_id)):
    res = await extra_store.toggle_banner_by_id(banner_id)
    if not res:
        raise HTTPException(404, "Баннер не найден")
    return res


@app.get("/api/admin/stats")
async def admin_stats(_: int = Depends(get_admin_user_id)):
    users = await get_users_count()
    keys = await get_all_keys_count()
    bc = await get_active_broadcasts()
    revenue = await get_revenue_stats()
    tariffs = await get_tariff_stats()
    funnel = await get_funnel_stats()

    return {
        "users": users, "keys": keys, "broadcasts": len(bc), "revenue": revenue,
        "tariffs": [{"tariff": t["tariff"], "count": t["cnt"]} for t in tariffs],
        "funnel": funnel,
    }


@app.get("/api/admin/users")
async def admin_users(page: int = 0, search: str = "", _: int = Depends(get_admin_user_id)):
    per_page = 20
    q = search.strip()

    if q:
        found = await search_users(q, limit=per_page)
        return {
            "total": len(found), "page": 0, "per_page": per_page,
            "items": [_user_list_item(u) for u in found[:per_page]],
            "search": q,
        }

    users = await get_all_users(include_banned=True)
    total = len(users)
    start = page * per_page
    chunk = users[start:start + per_page]

    return {
        "total": total, "page": page, "per_page": per_page,
        "items": [_user_list_item(u) for u in chunk],
        "search": "",
    }


def _user_list_item(u) -> dict:
    return {
        "user_id": u["user_id"],
        "username": u["username"],
        "balance": u["balance"],
        "is_banned": bool(u["is_banned"]),
        "is_admin": bool(u["is_admin"]),
        "registered_at": u["registered_at"] or "",
    }


@app.get("/api/admin/users/{uid}")
async def admin_user_card(uid: int, _: int = Depends(get_admin_user_id)):
    user = await get_user(uid)
    if not user:
        raise HTTPException(404, "Пользователь не найден")

    keys = await get_user_active_keys_with_id(uid)
    summary = await get_user_purchase_summary(uid)
    txs = await get_user_transactions(uid, limit=5, offset=0)

    auto_renew = any(bool(k["auto_renew"]) for k in keys)

    return {
        "user": {
            "user_id": user["user_id"], "username": user["username"], "balance": user["balance"],
            "registered_at": user["registered_at"], "trial_used": bool(user["trial_used"]),
            "is_admin": bool(user["is_admin"]), "is_banned": bool(user["is_banned"]), "ban_reason": user["ban_reason"],
        },
        "keys": [
            {
                "id": k["id"], "tariff": k["tariff"], "expires_at": k["expires_at"],
                "max_users": k["max_users"], "is_duo": bool(k["is_duo"]),
                "key_value": k["key_value"], "key_source": k["key_source"] or "purchased",
            }
            for k in keys
        ],
        "purchase_summary": {"count": summary["count"], "spent": summary["spent"]},
        "transactions": [{"amount": t["amount"], "description": t["description"], "created_at": t["created_at"]} for t in txs],
        "auto_renew": auto_renew,
    }


class BalanceChangeRequest(BaseModel):
    amount: int


@app.post("/api/admin/users/{uid}/balance")
async def admin_change_balance(uid: int, body: BalanceChangeRequest, admin_id: int = Depends(get_admin_user_id)):
    if not await user_exists(uid):
        raise HTTPException(404, "Пользователь не найден")
    if body.amount == 0 or abs(body.amount) > 1_000_000:
        raise HTTPException(400, "Некорректная сумма")

    await add_balance(uid, body.amount)
    new_bal = await get_balance(uid)
    await add_transaction(uid, body.amount, "admin", "Изменение админом")

    if body.amount > 0:
        await push_notification(uid, f"Баланс пополнен администратором!\n\nНачислено: +{body.amount} ₽\nБаланс: {new_bal} ₽")
    else:
        await push_notification(uid, f"Списание с баланса администратором.\n\nСписано: {body.amount} ₽\nБаланс: {new_bal} ₽")

    return {"balance": new_bal}


class GiveKeyRequest(BaseModel):
    days: int
    key_type: int = 1


@app.post("/api/admin/users/{uid}/key")
async def admin_give_key(uid: int, body: GiveKeyRequest, _: int = Depends(get_admin_user_id)):
    if not await user_exists(uid):
        raise HTTPException(404, "Пользователь не найден")
    if body.days <= 0 or body.days > 3650:
        raise HTTPException(400, "Число дней от 1 до 3650")

    type_names = {1: "Обычный", 2: "DUO", 3: "TRIO", 4: "MIX"}
    max_users_map = {1: 0, 2: 2, 3: 3, 4: 4}

    ktype = body.key_type if body.key_type in type_names else 1
    max_users = max_users_map[ktype]
    type_label = type_names[ktype]

    tariff_name = f"Подарок {type_label} ({body.days}д)" if ktype > 1 else f"Подарок ({body.days}д)"

    try:
        key = await create_key(uid, tariff_name, days=body.days, max_users=max_users, source="gift")
    except Exception:
        logger.exception("admin_give_key error")
        raise HTTPException(502, "Ошибка создания ключа")

    await push_notification(uid, f"Вам выдан VPN-ключ ({type_label}) администратором на {body.days} дней. Ключ доступен в разделе «Профиль».")

    return {"key": key}


@app.delete("/api/admin/keys/{key_id}")
async def admin_delete_key_by_id(key_id: int, _: int = Depends(get_admin_user_id)):
    key = await get_key_by_id(key_id)
    if not key:
        raise HTTPException(404, "Ключ не найден")
    if not key["is_active"]:
        raise HTTPException(400, "Ключ уже неактивен")

    await deactivate_key(key_id)
    await push_notification(key["user_id"], f"Ваш VPN-ключ «{key['tariff']}» был отозван администратором.")

    return {"ok": True}


@app.post("/api/admin/keys/{key_id}/revoke")
async def admin_revoke_key(key_id: int, _: int = Depends(get_admin_user_id)):
    return await admin_delete_key_by_id(key_id)


@app.post("/api/admin/users/{uid}/auto-renew/toggle")
async def admin_toggle_autorenew(uid: int, _: int = Depends(get_admin_user_id)):
    keys = await get_user_active_keys_with_id(uid)
    if not keys:
        raise HTTPException(400, "У пользователя нет ключей")

    current = any(bool(k["auto_renew"]) for k in keys)

    count = await set_user_auto_renew_all(uid, not current)
    new_state = not current
    status_text = "включено" if new_state else "выключено"
    await push_notification(uid, f"Автопродление {status_text} администратором.")

    return {"auto_renew": new_state, "affected": count}


class NotifyRequest(BaseModel):
    text: str


@app.post("/api/admin/users/{uid}/notify")
async def admin_notify_user(uid: int, body: NotifyRequest, _: int = Depends(get_admin_user_id)):
    if not await user_exists(uid):
        raise HTTPException(404, "Пользователь не найден")
    if not body.text.strip():
        raise HTTPException(400, "Пустой текст")
    await push_notification(uid, body.text.strip())
    return {"ok": True}


class BanRequest(BaseModel):
    reason: str


@app.post("/api/admin/users/{uid}/ban")
async def admin_ban_user(uid: int, body: BanRequest, admin_id: int = Depends(get_admin_user_id)):
    if uid == admin_id:
        raise HTTPException(400, "Нельзя забанить себя")
    if not await user_exists(uid):
        raise HTTPException(404, "Пользователь не найден")
    if await is_admin(uid):
        raise HTTPException(400, "Нельзя забанить админа")

    reason = body.reason.strip()[:255] or "Не указана"
    await ban_user(uid, reason)
    await push_notification(uid, f"Аккаунт заблокирован администратором.\n\nПричина: {reason}")

    return {"ok": True}


@app.post("/api/admin/users/{uid}/unban")
async def admin_unban_user(uid: int, _: int = Depends(get_admin_user_id)):
    if not await user_exists(uid):
        raise HTTPException(404, "Пользователь не найден")
    await unban_user(uid)
    await push_notification(uid, "Аккаунт разблокирован администратором.")
    return {"ok": True}


@app.get("/api/admin/users/{uid}/history")
async def admin_user_history(uid: int, page: int = 0, _: int = Depends(get_admin_user_id)):
    per_page = 10
    total = await get_user_transactions_count(uid)
    txs = await get_user_transactions(uid, limit=per_page, offset=page * per_page)
    return {
        "total": total, "page": page, "per_page": per_page,
        "items": [{"amount": t["amount"], "description": t["description"], "created_at": t["created_at"]} for t in txs],
    }


class AdminPromoCreate(BaseModel):
    code: str
    bonus_type: int
    value: int
    max_uses: int
    post_chat_id: int | None = None


@app.get("/api/admin/promo")
async def admin_list_promo(_: int = Depends(get_admin_user_id)):
    promos = await get_all_promos()
    return [{"code": p["code"], "discount": p["discount"], "bonus_days": p["bonus_days"], "discount_percent": p["discount_percent"], "max_uses": p["max_uses"], "used_count": p["used_count"]} for p in promos]


@app.post("/api/admin/promo")
async def admin_create_promo(body: AdminPromoCreate, admin_id: int = Depends(get_admin_user_id)):
    code = body.code.strip().upper()
    if " " in code or len(code) < 2 or len(code) > 32:
        raise HTTPException(400, "Код: без пробелов, 2–32 символа")
    if await get_promo(code):
        raise HTTPException(400, "Такой промокод уже существует")
    if body.bonus_type not in (1, 2, 3):
        raise HTTPException(400, "bonus_type должен быть 1, 2 или 3")
    if body.value < 1 or (body.bonus_type == 3 and body.value > 99):
        raise HTTPException(400, "Некорректное значение бонуса")
    if body.max_uses != -1 and body.max_uses < 1:
        raise HTTPException(400, "max_uses: -1 или число ≥ 1")

    discount = body.value if body.bonus_type == 1 else 0
    bonus_days = body.value if body.bonus_type == 2 else 0
    discount_percent = body.value if body.bonus_type == 3 else 0

    await create_promo(code=code, discount=discount, bonus_days=bonus_days, discount_percent=discount_percent, max_uses=body.max_uses, created_by=admin_id)

    limit_str = "безлимит" if body.max_uses == -1 else str(body.max_uses)
    bonus_str = f"{discount} ₽ на баланс" if discount else (f"{bonus_days} дней VPN" if bonus_days else f"скидка {discount_percent}%")

    posted = False
    if body.post_chat_id and BOT:
        try:
            bot_info = await BOT.get_me()
            post_text = f"<b>Новый промокод!</b>\n\nКод: <code>{code}</code>\nБонус: <b>{bonus_str}</b>\nОсталось: <b>{limit_str}</b>"
            sent = await BOT.send_message(body.post_chat_id, post_text, reply_markup=promo_post_kb(bot_info.username))
            try:
                await BOT.pin_chat_message(body.post_chat_id, sent.message_id)
            except Exception:
                pass
            await add_promo_post(code, body.post_chat_id, sent.message_id)
            posted = True
        except Exception:
            logger.exception("admin_create_promo: post error")

    return {"code": code, "bonus": bonus_str, "limit": limit_str, "posted": posted}


@app.delete("/api/admin/promo/{code}")
async def admin_delete_promo(code: str, _: int = Depends(get_admin_user_id)):
    code = code.strip().upper()
    posts = await get_promo_posts(code)
    for p in posts:
        if BOT:
            try:
                await BOT.unpin_chat_message(p["chat_id"], p["message_id"])
            except Exception:
                pass
            try:
                await BOT.delete_message(p["chat_id"], p["message_id"])
            except Exception:
                pass

    deleted = await delete_promo(code)
    if not deleted:
        raise HTTPException(404, "Промокод не найден")
    return {"ok": True, "posts_removed": len(posts)}


class BroadcastCreate(BaseModel):
    text: str
    photo_url: str | None = None
    btn_text: str | None = None
    btn_url: str | None = None
    duration_days: int
    interval_hours: int


@app.get("/api/admin/broadcast/active")
async def admin_broadcast_active(_: int = Depends(get_admin_user_id)):
    items = await get_active_broadcasts()
    return [{"id": b["id"], "text": b["text"][:80], "started_at": b["started_at"], "duration_days": b["duration_days"], "interval_hours": b["interval_hours"]} for b in items]


@app.post("/api/admin/broadcast/upload")
async def admin_upload_broadcast_file(
    file: UploadFile = File(...),
    _: int = Depends(get_admin_user_id),
):
    ext = Path(file.filename or "").suffix.lower()
    if ext not in ALLOWED_MEDIA_EXT:
        raise HTTPException(400, "Разрешены только изображения (jpg, png, webp) и GIF")

    content = await file.read()
    if not content:
        raise HTTPException(400, "Пустой файл")
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(400, "Файл слишком большой (максимум 8 МБ)")

    filename = f"bc_{uuid.uuid4().hex}{ext}"
    filepath = BROADCAST_UPLOAD_DIR / filename

    try:
        with open(filepath, "wb") as f:
            f.write(content)
    except Exception:
        logger.exception("admin_upload_broadcast_file: save error")
        raise HTTPException(502, "Не удалось сохранить файл")

    return {"file_url": f"/uploads/broadcasts/{filename}"}


@app.post("/api/admin/broadcast")
async def admin_create_broadcast(body: BroadcastCreate, admin_id: int = Depends(get_admin_user_id)):
    if not body.text.strip():
        raise HTTPException(400, "Введите текст рассылки")
    if body.duration_days < 0 or body.interval_hours < 1:
        raise HTTPException(400, "Некорректные параметры длительности/интервала")

    media_type = "photo" if body.photo_url else "text"
    encoded = f"{media_type}|{body.photo_url or ''}|{body.btn_text or ''}|{body.btn_url or ''}"

    bc_id = await create_broadcast(encoded, body.text.strip(), body.duration_days, body.interval_hours, admin_id)
    return {"id": bc_id}


@app.post("/api/admin/broadcast/{bc_id}/stop")
async def admin_stop_broadcast(bc_id: int, _: int = Depends(get_admin_user_id)):
    items = await get_active_broadcasts()
    target = next((b for b in items if b["id"] == bc_id), None)
    if not target:
        raise HTTPException(404, "Рассылка не найдена или уже остановлена")
    await stop_broadcast(bc_id)
    return {"ok": True}


@app.post("/api/admin/broadcast/stop-all")
async def admin_stop_broadcasts(_: int = Depends(get_admin_user_id)):
    items = await get_active_broadcasts()
    for b in items:
        await stop_broadcast(b["id"])
    return {"stopped": len(items)}


class GiftAllRequest(BaseModel):
    gift_type: int
    value: int


@app.post("/api/admin/gift-all")
async def admin_gift_all(body: GiftAllRequest, _: int = Depends(get_admin_user_id)):
    if body.gift_type not in (1, 2, 3) or body.value <= 0:
        raise HTTPException(400, "Некорректные данные")

    users = await get_all_users(include_banned=False)
    success = failed = 0

    for u in users:
        uid = u["user_id"]
        try:
            if body.gift_type == 1:
                await add_balance(uid, body.value)
                await add_transaction(uid, body.value, "admin_gift", f"Подарок всем: {body.value} ₽")
                await push_notification(uid, f"Подарок от администрации: +{body.value} ₽ на баланс!")
            elif body.gift_type == 2:
                await create_key(uid, f"Подарок ({body.value}ч)", hours=body.value, source="gift")
                await add_transaction(uid, 0, "admin_gift", f"Подарок всем: {body.value}ч VPN")
                await push_notification(uid, f"Подарок от администрации: VPN-ключ на {body.value} часов! Смотрите в «Профиле».")
            else:
                await create_key(uid, f"Подарок ({body.value}д)", days=body.value, source="gift")
                await add_transaction(uid, 0, "admin_gift", f"Подарок всем: {body.value}д VPN")
                await push_notification(uid, f"Подарок от администрации: VPN-ключ на {body.value} дней! Смотрите в «Профиле».")
            success += 1
        except Exception:
            failed += 1

    return {"success": success, "failed": failed}


class NotifyAllRequest(BaseModel):
    text: str


@app.post("/api/admin/notify-all")
async def admin_notify_all(body: NotifyAllRequest, _: int = Depends(get_admin_user_id)):
    if not body.text.strip():
        raise HTTPException(400, "Введите текст")

    users = await get_all_users(include_banned=False)
    success = 0
    failed = 0
    for u in users:
        try:
            await push_notification(u["user_id"], body.text.strip())
            success += 1
        except Exception:
            failed += 1

    return {"success": success, "failed": failed, "total": len(users)}


@app.get("/api/admin/features")
async def admin_get_features(_: int = Depends(get_admin_user_id)):
    features = await get_all_features()
    return [{"key": k, "label": FEATURE_LABELS[k], "hint": FEATURE_HINTS[k], "enabled": features.get(k, True)} for k in FEATURE_LABELS]


@app.post("/api/admin/features/{feature}/toggle")
async def admin_toggle_feature(feature: str, _: int = Depends(get_admin_user_id)):
    if feature not in FEATURE_LABELS:
        raise HTTPException(404, "Неизвестная функция")
    current = await is_feature_enabled(feature)
    await set_feature(feature, not current)
    return {"key": feature, "enabled": not current}


try:
    app.mount("/uploads/banners", StaticFiles(directory=str(BANNER_UPLOAD_DIR)), name="banner_uploads")
    app.mount("/uploads/broadcasts", StaticFiles(directory=str(BROADCAST_UPLOAD_DIR)), name="broadcast_uploads")
except Exception:
    logger.exception("Failed to mount uploads dirs")


@app.get("/", include_in_schema=False)
async def serve_index():
    index_path = STATIC_DIR / "index.html"
    response = FileResponse(index_path, media_type="text/html")
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


_NOT_FOUND_HTML = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<title>FlowVPN — страница не найдена</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html, body { height: 100%; }
  body {
    background: #000;
    color: #fff;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    display: flex; align-items: center; justify-content: center;
    text-align: center; padding: 24px;
  }
  .card { max-width: 360px; width: 100%; }
  .logo { width: 84px; height: 84px; margin: 0 auto 20px; display: block; }
  h1 { font-size: 22px; font-weight: 800; margin-bottom: 10px; }
  p { font-size: 14px; color: #9a9aa2; line-height: 1.6; margin-bottom: 24px; }
  a.btn {
    display: inline-block; padding: 13px 28px; border-radius: 14px;
    background: #fff; color: #000; text-decoration: none; font-weight: 700; font-size: 14px;
  }
</style>
</head>
<body>
  <div class="card">
    <img class="logo" src="/image/loosa.png" alt="FlowVPN"
         onerror="this.style.display='none'">
    <h1>Страница не найдена</h1>
    <p>Ошибка 404. Возможно, ссылка устарела или в адресе опечатка.</p>
    <a class="btn" href="/">Открыть FlowVPN</a>
  </div>
</body>
</html>"""


@app.exception_handler(404)
async def not_found_handler(request, exc):
    from fastapi.responses import HTMLResponse, JSONResponse
    path = request.url.path
    if path.startswith("/api/") or path.startswith("/uploads/"):
        return JSONResponse({"detail": "Не найдено"}, status_code=404)
    return HTMLResponse(_NOT_FOUND_HTML, status_code=404)


app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")