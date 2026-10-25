import os
import asyncio
import logging
import signal
from datetime import datetime, timedelta
from dotenv import load_dotenv

import uvicorn

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramRetryAfter, TelegramForbiddenError, TelegramBadRequest
from aiogram.types import MenuButtonWebApp, WebAppInfo

from database.db import (
    init_db, close_db,
    get_active_broadcasts, get_all_users,
    update_broadcast_next, stop_broadcast,
    get_expired_active_keys, deactivate_key,
    get_keys_expiring_soon, mark_key_notified,
    add_balance,
    get_exhausted_promos, get_promo_posts, delete_promo_posts,
    get_pending_payments, mark_payment_completed, mark_payment_canceled,
    add_transaction, get_balance, cleanup_old_pending_payments,
    get_keys_for_auto_renew, extend_key, deduct_balance,
    cleanup_old_inactive_keys, cleanup_expired_cache, optimize_db,
    get_stale_pending_payments, mark_payment_expired,
)
from middlewares.access import BanMiddleware
from middlewares.throttle import ThrottleMiddleware
from utils.logger import setup_logging, TelegramErrorNotifier
from utils.notify import notify_user
from utils.payments import check_payment
from keyboards.menu import broadcast_url_kb
from handlers import start, admin, errors, fallback
from handlers.errors import set_notifier
from config import (
    ADMIN_IDS, TARIFFS, MULTI_TARIFFS, INACTIVE_KEY_TTL_DAYS,
    WEBAPP_PORT, MINIAPP_URL, PAYMENT_LINK_TTL_MINUTES,
)

from xui_api import check_suspicious_activity, warmup_and_log_panel
from webapp import extra_store
from webapp.api import app as webapp_app, set_bot_token, set_bot, set_bot_username

load_dotenv()
logger = logging.getLogger(__name__)

FLOOD_DELAY               = 0.05
BROADCAST_LOOP_INTERVAL   = 60
EXPIRY_CHECK_INTERVAL     = 3600
EXPIRY_NOTIFY_HOURS       = 24
PROMO_CLEANER_INTERVAL    = 300
SUSPICIOUS_CHECK_INTERVAL = 900
WATCHDOG_INTERVAL         = 600
PAYMENT_CHECK_INTERVAL    = 120
PAYMENT_CLEANUP_INTERVAL  = 60
AUTO_RENEW_INTERVAL       = 3600
KEY_CLEANUP_INTERVAL      = 24 * 3600
CACHE_CLEANUP_INTERVAL    = 600
MAINTENANCE_INTERVAL      = 600
DB_OPTIMIZE_INTERVAL      = 6 * 3600
RETRY_DELAY_BASE          = 5
RETRY_MAX_DELAY           = 300


async def _send_one(bot: Bot, user_id: int, photo_id: str, text: str) -> bool:
    media_type = "photo" if photo_id else "text"
    file_id = photo_id
    btn_text = ""
    btn_url = ""

    if photo_id and "|" in photo_id:
        parts = photo_id.split("|", 3)
        if len(parts) == 4:
            media_type, file_id, btn_text, btn_url = parts

    reply_markup = None
    if btn_text and btn_url:
        try:
            reply_markup = broadcast_url_kb(btn_text, btn_url)
        except Exception:
            reply_markup = None

    try:
        if media_type == "animation" and file_id:
            await bot.send_animation(user_id, file_id, caption=text, reply_markup=reply_markup)
        elif media_type == "photo" and file_id:
            await bot.send_photo(user_id, file_id, caption=text, reply_markup=reply_markup)
        else:
            await bot.send_message(user_id, text, reply_markup=reply_markup)
        return True

    except TelegramRetryAfter as e:
        logger.warning(f"RetryAfter {e.retry_after}s, user {user_id}")
        await asyncio.sleep(e.retry_after)
        try:
            if media_type == "animation" and file_id:
                await bot.send_animation(user_id, file_id, caption=text, reply_markup=reply_markup)
            elif media_type == "photo" and file_id:
                await bot.send_photo(user_id, file_id, caption=text, reply_markup=reply_markup)
            else:
                await bot.send_message(user_id, text, reply_markup=reply_markup)
            return True
        except Exception:
            return False

    except (TelegramForbiddenError, TelegramBadRequest):
        return False

    except Exception:
        logger.exception(f"_send_one: unexpected error user={user_id}")
        return False


async def broadcast_loop(bot: Bot) -> None:
    retry_delay = RETRY_DELAY_BASE

    while True:
        try:
            broadcasts = await get_active_broadcasts()
            now = datetime.now()

            for b in broadcasts:
                try:
                    bc_id          = b["id"]
                    photo_id       = b["photo_id"]
                    text           = b["text"]
                    duration_days  = b["duration_days"]
                    interval_hours = b["interval_hours"]
                    started_at     = b["started_at"]
                    next_send      = b["next_send"]

                    start_dt = datetime.strptime(started_at, "%Y-%m-%d %H:%M")

                    if duration_days == 0:
                        users = await get_all_users(include_banned=False)
                        sent = failed = 0
                        for u in users:
                            ok = await _send_one(bot, u["user_id"], photo_id, text)
                            if ok:
                                sent += 1
                            else:
                                failed += 1
                            await asyncio.sleep(FLOOD_DELAY)
                        await stop_broadcast(bc_id)
                        logger.info(f"one-off broadcast {bc_id}: sent {sent}, failed {failed}")
                        continue

                    next_dt = datetime.strptime(next_send, "%Y-%m-%d %H:%M")

                    if now > start_dt + timedelta(days=duration_days):
                        await stop_broadcast(bc_id)
                        logger.info(f"broadcast {bc_id}: expired, stopped")
                        continue

                    if now < next_dt:
                        continue

                    new_next = now + timedelta(hours=interval_hours)
                    await update_broadcast_next(bc_id, new_next.strftime("%Y-%m-%d %H:%M"))

                    users = await get_all_users(include_banned=False)
                    sent = failed = 0

                    for u in users:
                        ok = await _send_one(bot, u["user_id"], photo_id, text)
                        if ok:
                            sent += 1
                        else:
                            failed += 1
                        await asyncio.sleep(FLOOD_DELAY)

                    logger.info(f"broadcast {bc_id}: sent {sent}, failed {failed}")

                except ValueError as e:
                    logger.error(f"broadcast {b['id']}: bad data: {e}")
                    await stop_broadcast(b["id"])
                except Exception:
                    logger.exception(f"broadcast {b['id']}: unexpected error")

            retry_delay = RETRY_DELAY_BASE

        except Exception:
            logger.exception("broadcast_loop: critical error")
            retry_delay = min(retry_delay * 2, RETRY_MAX_DELAY)
            await asyncio.sleep(retry_delay)
            continue

        await asyncio.sleep(BROADCAST_LOOP_INTERVAL)


async def expiry_checker(bot: Bot) -> None:
    retry_delay = RETRY_DELAY_BASE
    await asyncio.sleep(30)

    while True:
        try:
            expired = await get_expired_active_keys()

            if expired:
                logger.info(f"expiry_checker: found {len(expired)} expired keys")

            for row in expired:
                key_id  = row["id"]
                user_id = row["user_id"]

                try:
                    await deactivate_key(key_id)
                except Exception:
                    logger.exception(f"expiry_checker: deactivate error {key_id}")
                    continue

                try:
                    await notify_user(
                        user_id,
                        "Ваш VPN-ключ истёк.\n\n"
                        "Для продолжения использования FlowVPN "
                        "приобретите новую подписку в разделе «Купить VPN».",
                        bot=bot,
                    )
                except Exception:
                    logger.exception(f"expiry_checker: notify error {user_id}")

                await asyncio.sleep(FLOOD_DELAY)

            expiring = await get_keys_expiring_soon(hours=EXPIRY_NOTIFY_HOURS)

            for row in expiring:
                key_id     = row["id"]
                user_id    = row["user_id"]
                tariff     = row["tariff"]
                expires_at = row["expires_at"]

                try:
                    await notify_user(
                        user_id,
                        f"Ваш VPN-ключ скоро истечёт.\n\n"
                        f"Тариф: {tariff}\n"
                        f"Истекает: {expires_at}\n\n"
                        f"Не забудьте продлить подписку, чтобы не потерять доступ.",
                        bot=bot,
                    )
                    await mark_key_notified(key_id)
                except Exception:
                    logger.exception(f"expiry_checker: notify soon error {user_id}")

                await asyncio.sleep(FLOOD_DELAY)

            retry_delay = RETRY_DELAY_BASE

        except Exception:
            logger.exception("expiry_checker: critical error")
            retry_delay = min(retry_delay * 2, RETRY_MAX_DELAY)
            await asyncio.sleep(retry_delay)
            continue

        await asyncio.sleep(EXPIRY_CHECK_INTERVAL)


async def key_cleanup_loop() -> None:
    await asyncio.sleep(180)

    while True:
        try:
            deleted = await cleanup_old_inactive_keys(days=INACTIVE_KEY_TTL_DAYS)
            if deleted:
                logger.info(f"key_cleanup_loop: deleted {deleted} inactive keys")
        except Exception:
            logger.exception("key_cleanup_loop: critical error")

        await asyncio.sleep(KEY_CLEANUP_INTERVAL)


async def cache_cleanup_loop() -> None:
    while True:
        await asyncio.sleep(CACHE_CLEANUP_INTERVAL)
        try:
            n = await cleanup_expired_cache()
            if n:
                logger.info(f"cache_cleanup_loop: cleaned {n} expired entries")
        except Exception:
            logger.exception("cache_cleanup_loop: critical error")


async def maintenance_loop() -> None:
    await asyncio.sleep(60)

    while True:
        try:
            await extra_store.run_maintenance()
        except Exception:
            logger.exception("maintenance_loop: error cleaning extra.db")

        await asyncio.sleep(MAINTENANCE_INTERVAL)


async def db_optimize_loop() -> None:
    await asyncio.sleep(300)

    while True:
        try:
            result = await optimize_db()
            if result.get("vacuumed"):
                logger.info("db_optimize_loop: VACUUM performed")
        except Exception:
            logger.exception("db_optimize_loop: error optimizing main DB")

        await asyncio.sleep(DB_OPTIMIZE_INTERVAL)


async def promo_post_cleaner(bot: Bot) -> None:
    await asyncio.sleep(60)

    while True:
        try:
            exhausted = await get_exhausted_promos()

            for p in exhausted:
                code = p["code"]
                posts = await get_promo_posts(code)

                if not posts:
                    continue

                for post in posts:
                    try:
                        await bot.unpin_chat_message(post["chat_id"], post["message_id"])
                    except Exception:
                        pass
                    try:
                        await bot.delete_message(post["chat_id"], post["message_id"])
                    except Exception:
                        pass
                    await asyncio.sleep(0.1)

                await delete_promo_posts(code)

        except Exception:
            logger.exception("promo_post_cleaner: critical error")

        await asyncio.sleep(PROMO_CLEANER_INTERVAL)


async def suspicious_activity_loop() -> None:
    await asyncio.sleep(120)

    while True:
        try:
            found = await check_suspicious_activity()
            if found:
                logger.info(f"suspicious_activity_loop: found {found} suspicious clients")
        except Exception:
            logger.exception("suspicious_activity_loop: critical error")

        await asyncio.sleep(SUSPICIOUS_CHECK_INTERVAL)


async def payment_checker(bot: Bot) -> None:
    await asyncio.sleep(90)

    while True:
        try:
            pending = await get_pending_payments(limit=100)

            for p in pending:
                payment_id = p["payment_id"]
                user_id    = p["user_id"]
                amount     = p["amount"]

                status = await asyncio.to_thread(check_payment, payment_id)

                if status == "succeeded":
                    if await mark_payment_completed(payment_id):
                        await add_balance(user_id, amount)
                        await add_transaction(
                            user_id, amount, "topup",
                            f"Автозачисление ЮKassa ({payment_id})"
                        )
                        try:
                            new_bal = await get_balance(user_id)
                            await notify_user(
                                user_id,
                                f"Платёж зачислен.\n\n"
                                f"Сумма: {amount} ₽\n"
                                f"Ваш баланс: {new_bal} ₽",
                                bot=bot,
                            )
                        except Exception:
                            logger.exception(f"payment_checker: notify error {user_id}")

                elif status == "canceled":
                    await mark_payment_canceled(payment_id)

                await asyncio.sleep(0.3)

        except Exception:
            logger.exception("payment_checker: critical error")

        await asyncio.sleep(PAYMENT_CHECK_INTERVAL)


async def payment_cleanup_loop() -> None:
    await asyncio.sleep(30)

    while True:
        try:
            stale = await get_stale_pending_payments(minutes=PAYMENT_LINK_TTL_MINUTES)
            for p in stale:
                await mark_payment_expired(p["payment_id"])

            cnt = await cleanup_old_pending_payments(hours=48)
            if cnt:
                logger.info(f"payment_cleanup: canceled {cnt} old pending payments")
        except Exception:
            logger.exception("payment_cleanup: error")

        await asyncio.sleep(PAYMENT_CLEANUP_INTERVAL)


async def auto_renew_loop(bot: Bot) -> None:
    await asyncio.sleep(60)

    while True:
        try:
            keys = await get_keys_for_auto_renew()

            for k in keys:
                user_id = k["user_id"]
                key_id  = k["id"]
                tariff  = k["tariff"]

                price = None
                days  = None

                for t in TARIFFS.values():
                    if t["name"] == tariff:
                        price = t["price"]
                        days  = t["days"]
                        break

                if price is None:
                    for mt in MULTI_TARIFFS.values():
                        if mt["name"] == tariff:
                            price = mt["price"]
                            days  = mt["days"]
                            break

                if not price or not days:
                    continue

                success = await deduct_balance(user_id, price)

                if success:
                    try:
                        new_exp = await extend_key(key_id, days)
                    except Exception:
                        logger.exception(f"auto_renew_loop: extend error {key_id}")
                        await add_balance(user_id, price)
                        continue
                    await add_transaction(user_id, -price, "auto_renew", f"Автопродление {tariff}")
                    try:
                        await notify_user(
                            user_id,
                            f"Подписка автоматически продлена!\n\n"
                            f"Тариф: {tariff}\n"
                            f"Списано: {price} ₽\n"
                            f"Действует до: {new_exp}",
                            bot=bot,
                        )
                    except Exception:
                        logger.exception(f"auto_renew_loop: notify error {user_id}")
                else:
                    try:
                        await notify_user(
                            user_id,
                            f"Не удалось продлить подписку.\n\n"
                            f"Тариф: {tariff}\n"
                            f"Нужно: {price} ₽\n"
                            f"Недостаточно средств на балансе.",
                            bot=bot,
                        )
                    except Exception:
                        logger.exception(f"auto_renew_loop: notify error {user_id}")

                await asyncio.sleep(0.3)

        except Exception:
            logger.exception("auto_renew_loop: critical error")

        await asyncio.sleep(AUTO_RENEW_INTERVAL)


async def watchdog(bot: Bot, notifier: TelegramErrorNotifier) -> None:
    consecutive_failures = 0
    await asyncio.sleep(300)

    while True:
        try:
            await asyncio.wait_for(bot.get_me(), timeout=10)
            consecutive_failures = 0

        except Exception as e:
            consecutive_failures += 1
            logger.error(f"watchdog: bot not responding ({consecutive_failures}): {e}")

            if consecutive_failures >= 2:
                await notifier.notify(
                    f"Watchdog: бот не отвечает {consecutive_failures} раза подряд!",
                    exc=e
                )

        await asyncio.sleep(WATCHDOG_INTERVAL)


async def main() -> None:
    setup_logging()

    token = os.getenv("BOT_TOKEN")
    if not token:
        raise RuntimeError("BOT_TOKEN not configured")

    set_bot_token(token)

    bot = Bot(token=token, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher()

    set_bot(bot)

    try:
        me = await bot.get_me()
        set_bot_username(me.username)
        logger.info(f"Bot username: @{me.username}")
    except Exception:
        logger.exception("Failed to get bot username")

    if MINIAPP_URL:
        try:
            await bot.set_chat_menu_button(
                menu_button=MenuButtonWebApp(
                    text="Открыть",
                    web_app=WebAppInfo(url=MINIAPP_URL)
                )
            )
            logger.info(f"Menu button set: {MINIAPP_URL}")
        except Exception:
            logger.exception("Failed to set menu button")
    else:
        logger.warning("MINIAPP_URL not set")

    notifier = TelegramErrorNotifier(bot, ADMIN_IDS)
    set_notifier(notifier)

    throttle_kwargs = {
        "message_limit":  10,
        "message_window": 5.0,
        "callback_limit":  15,
        "callback_window": 5.0,
    }
    dp.message.middleware(ThrottleMiddleware(**throttle_kwargs))
    dp.callback_query.middleware(ThrottleMiddleware(**throttle_kwargs))

    dp.message.middleware(BanMiddleware())
    dp.callback_query.middleware(BanMiddleware())

    try:
        await init_db()
        await extra_store.init()
    except Exception:
        logger.exception("DB init failed")
        raise

    # Проверка панели 3x-ui: логирует локации и шаблон ссылки подписки.
    # Ошибки не фатальны — бот продолжает работать.
    try:
        await warmup_and_log_panel()
    except Exception:
        logger.exception("XUI panel warmup failed")

    dp.include_router(errors.router)
    dp.include_router(start.router)
    dp.include_router(admin.router)
    dp.include_router(fallback.router)

    asyncio.create_task(broadcast_loop(bot))
    asyncio.create_task(expiry_checker(bot))
    asyncio.create_task(key_cleanup_loop())
    asyncio.create_task(cache_cleanup_loop())
    asyncio.create_task(maintenance_loop())
    asyncio.create_task(db_optimize_loop())
    asyncio.create_task(promo_post_cleaner(bot))
    asyncio.create_task(watchdog(bot, notifier))
    asyncio.create_task(suspicious_activity_loop())
    asyncio.create_task(payment_checker(bot))
    asyncio.create_task(payment_cleanup_loop())
    asyncio.create_task(auto_renew_loop(bot))

    uvicorn_config = uvicorn.Config(
        webapp_app,
        host="0.0.0.0",
        port=WEBAPP_PORT,
        log_level="info",
        loop="asyncio",
    )
    web_server = uvicorn.Server(uvicorn_config)

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _on_signal():
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _on_signal)
        except NotImplementedError:
            pass

    try:
        await bot.delete_webhook(drop_pending_updates=True)

        polling_task = asyncio.create_task(
            dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())
        )
        webserver_task = asyncio.create_task(web_server.serve())

        wait_stop = asyncio.create_task(stop_event.wait())
        done, pending = await asyncio.wait(
            [polling_task, webserver_task, wait_stop],
            return_when=asyncio.FIRST_COMPLETED
        )

        if wait_stop in done:
            logger.info("Shutdown signal received")
            await dp.stop_polling()
            web_server.should_exit = True

    except Exception as e:
        logger.exception("Critical error in polling/webserver")
        await notifier.notify("Бот упал! Ошибка polling или web-сервера.", exc=e)
        raise
    finally:
        await close_db()
        await extra_store.close()
        await bot.session.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass
    except Exception:
        logger.exception("Fatal error")
        raise
