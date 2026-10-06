import aiosqlite
import asyncio
import logging
import os
import time
from datetime import datetime, timedelta
from config import DB_PATH, REFERRAL_BONUS, ADMIN_IDS

logger = logging.getLogger(__name__)

_db_connection: aiosqlite.Connection | None = None
_db_lock = asyncio.Lock()

_cache: dict = {}
_cache_ttl: dict = {}
CACHE_TTL_SHORT = 15
CACHE_TTL_LONG  = 120


def _cache_get(key: str):
    if key not in _cache:
        return None
    if time.monotonic() > _cache_ttl[key]:
        _cache.pop(key, None)
        _cache_ttl.pop(key, None)
        return None
    return _cache[key]


def _cache_set(key: str, value, ttl: float = CACHE_TTL_SHORT):
    _cache[key] = value
    _cache_ttl[key] = time.monotonic() + ttl


def _cache_del(*keys: str):
    for key in keys:
        _cache.pop(key, None)
        _cache_ttl.pop(key, None)


async def cleanup_expired_cache() -> int:
    now = time.monotonic()
    expired = [k for k, exp in _cache_ttl.items() if now > exp]
    for k in expired:
        _cache.pop(k, None)
        _cache_ttl.pop(k, None)
    return len(expired)


async def get_db() -> aiosqlite.Connection:
    global _db_connection
    if _db_connection is not None:
        return _db_connection

    async with _db_lock:
        if _db_connection is not None:
            return _db_connection

        db_dir = os.path.dirname(DB_PATH)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

        conn = await aiosqlite.connect(DB_PATH)
        conn.row_factory = aiosqlite.Row

        await conn.execute("PRAGMA journal_mode=WAL")
        await conn.execute("PRAGMA foreign_keys=ON")
        await conn.execute("PRAGMA busy_timeout=5000")
        await conn.execute("PRAGMA synchronous=NORMAL")
        await conn.execute("PRAGMA cache_size=-32000")
        await conn.execute("PRAGMA temp_store=MEMORY")
        await conn.execute("PRAGMA mmap_size=268435456")

        _db_connection = conn
        return _db_connection


async def close_db() -> None:
    global _db_connection
    if _db_connection is not None:
        await _db_connection.close()
        _db_connection = None


_FEATURE_DEFAULTS = {
    "shop":    True,
    "topup":   True,
    "profile": True,
    "promo":   True,
}

_FEATURES_REMOVED = ("buy_1_month", "buy_12_months", "buy_duo", "referral")

MAX_KEYS_PER_USER = 3

_key_creation_locks: dict[int, asyncio.Lock] = {}


def _get_key_creation_lock(user_id: int) -> asyncio.Lock:
    lock = _key_creation_locks.get(user_id)
    if lock is None:
        lock = asyncio.Lock()
        _key_creation_locks[user_id] = lock
    return lock


async def init_db() -> None:
    db = await get_db()

    await db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id       INTEGER PRIMARY KEY,
            username      TEXT    DEFAULT '',
            balance       INTEGER DEFAULT 0,
            is_admin      INTEGER DEFAULT 0,
            is_banned     INTEGER DEFAULT 0,
            ban_reason    TEXT    DEFAULT '',
            referred_by   INTEGER DEFAULT 0,
            trial_used    INTEGER DEFAULT 0,
            registered_at TEXT    DEFAULT ''
        )
    """)
    await db.execute("CREATE INDEX IF NOT EXISTS idx_users_registered ON users(registered_at DESC, user_id DESC)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")

    await db.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER NOT NULL,
            key_value       TEXT    NOT NULL,
            tariff          TEXT    DEFAULT '',
            proxy_address   TEXT    DEFAULT '',
            created_at      TEXT    DEFAULT '',
            expires_at      TEXT    DEFAULT '',
            is_duo          INTEGER DEFAULT 0,
            max_users       INTEGER DEFAULT 0,
            is_active       INTEGER DEFAULT 1,
            notified_expiry INTEGER DEFAULT 0,
            auto_renew      INTEGER DEFAULT 1,
            key_source      TEXT    DEFAULT 'purchased',
            price_paid      INTEGER DEFAULT 0
        )
    """)
    await db.execute("CREATE INDEX IF NOT EXISTS idx_keys_user_active ON keys(user_id, is_active)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_keys_expires ON keys(expires_at, is_active)")

    await db.execute("""
        CREATE TABLE IF NOT EXISTS promos (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            code             TEXT    UNIQUE NOT NULL,
            discount         INTEGER DEFAULT 0,
            bonus_days       INTEGER DEFAULT 0,
            discount_percent INTEGER DEFAULT 0,
            max_uses         INTEGER DEFAULT -1,
            used_count       INTEGER DEFAULT 0,
            created_by       INTEGER DEFAULT 0,
            created_at       TEXT    DEFAULT '',
            expires_at       TEXT    DEFAULT ''
        )
    """)

    await db.execute("""
        CREATE TABLE IF NOT EXISTS promo_uses (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            promo_code TEXT    NOT NULL,
            used_at    TEXT    DEFAULT ''
        )
    """)
    await db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_promo_once ON promo_uses(user_id, promo_code)")

    await db.execute("""
        CREATE TABLE IF NOT EXISTS promo_posts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            promo_code TEXT    NOT NULL,
            chat_id    INTEGER NOT NULL,
            message_id INTEGER NOT NULL,
            created_at TEXT    DEFAULT ''
        )
    """)
    await db.execute("CREATE INDEX IF NOT EXISTS idx_promo_posts_code ON promo_posts(promo_code)")

    await db.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            amount      INTEGER NOT NULL,
            type        TEXT    DEFAULT '',
            description TEXT    DEFAULT '',
            created_at  TEXT    DEFAULT ''
        )
    """)
    await db.execute("CREATE INDEX IF NOT EXISTS idx_transactions_user ON transactions(user_id, id DESC)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_transactions_type ON transactions(type, created_at)")

    await db.execute("""
        CREATE TABLE IF NOT EXISTS broadcasts (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            photo_id       TEXT    DEFAULT '',
            text           TEXT    DEFAULT '',
            duration_days  INTEGER DEFAULT 1,
            interval_hours INTEGER DEFAULT 24,
            started_at     TEXT    DEFAULT '',
            next_send      TEXT    DEFAULT '',
            is_active      INTEGER DEFAULT 1,
            created_by     INTEGER DEFAULT 0
        )
    """)

    await db.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            payment_id   TEXT    UNIQUE NOT NULL,
            user_id      INTEGER NOT NULL,
            amount       INTEGER NOT NULL,
            status       TEXT    DEFAULT 'pending',
            created_at   TEXT    DEFAULT '',
            completed_at TEXT    DEFAULT '',
            chat_id      INTEGER DEFAULT 0,
            message_id   INTEGER DEFAULT 0
        )
    """)
    await db.execute("CREATE INDEX IF NOT EXISTS idx_payments_status_created ON payments(status, created_at)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_payments_user ON payments(user_id)")

    await db.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value INTEGER NOT NULL DEFAULT 1
        )
    """)
    for feature, default in _FEATURE_DEFAULTS.items():
        await db.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
            (feature, 1 if default else 0)
        )

    await db.commit()
    await _migrate(db)
    await sync_admins()


async def sync_admins() -> None:
    db = await get_db()
    if ADMIN_IDS:
        placeholders = ",".join("?" for _ in ADMIN_IDS)
        await db.execute(
            f"UPDATE users SET is_admin = 0 WHERE is_admin = 1 AND user_id NOT IN ({placeholders})",
            ADMIN_IDS
        )
        await db.execute(
            f"UPDATE users SET is_admin = 1 WHERE user_id IN ({placeholders})",
            ADMIN_IDS
        )
    else:
        await db.execute("UPDATE users SET is_admin = 0 WHERE is_admin = 1")
    await db.commit()

    for k in list(_cache.keys()):
        if k.startswith("is_admin:") or k.startswith("user:"):
            _cache.pop(k, None)
            _cache_ttl.pop(k, None)


async def _migrate(db) -> None:
    cursor = await db.execute("PRAGMA table_info(promos)")
    columns = [row[1] for row in await cursor.fetchall()]
    if "discount_percent" not in columns:
        await db.execute("ALTER TABLE promos ADD COLUMN discount_percent INTEGER DEFAULT 0")

    cursor = await db.execute("PRAGMA table_info(keys)")
    columns = [row[1] for row in await cursor.fetchall()]
    if "auto_renew" not in columns:
        await db.execute("ALTER TABLE keys ADD COLUMN auto_renew INTEGER DEFAULT 1")
    if "max_users" not in columns:
        await db.execute("ALTER TABLE keys ADD COLUMN max_users INTEGER DEFAULT 0")
    if "key_source" not in columns:
        await db.execute("ALTER TABLE keys ADD COLUMN key_source TEXT DEFAULT 'purchased'")
    if "price_paid" not in columns:
        await db.execute("ALTER TABLE keys ADD COLUMN price_paid INTEGER DEFAULT 0")

    cursor = await db.execute("PRAGMA table_info(payments)")
    columns = [row[1] for row in await cursor.fetchall()]
    if "chat_id" not in columns:
        await db.execute("ALTER TABLE payments ADD COLUMN chat_id INTEGER DEFAULT 0")
    if "message_id" not in columns:
        await db.execute("ALTER TABLE payments ADD COLUMN message_id INTEGER DEFAULT 0")

    await db.execute("DROP TABLE IF EXISTS referrals")
    await db.execute("DROP TABLE IF EXISTS duo_invites")
    await db.execute(
        "DELETE FROM settings WHERE key IN ({})".format(",".join("?" * len(_FEATURES_REMOVED))),
        _FEATURES_REMOVED,
    )

    await db.commit()


async def add_user(user_id: int, username: str) -> bool:
    db = await get_db()
    is_adm = 1 if user_id in ADMIN_IDS else 0
    cur = await db.execute(
        "INSERT OR IGNORE INTO users (user_id, username, is_admin, registered_at) VALUES (?, ?, ?, ?)",
        (user_id, username or "", is_adm, datetime.now().strftime("%Y-%m-%d %H:%M"))
    )
    await db.commit()

    if cur.rowcount == 0:
        changed = False
        if username:
            cur2 = await db.execute(
                "UPDATE users SET username = ? WHERE user_id = ? AND username != ?",
                (username, user_id, username)
            )
            if cur2.rowcount > 0:
                changed = True

        cur_adm = await db.execute(
            "UPDATE users SET is_admin = ? WHERE user_id = ? AND is_admin != ?",
            (is_adm, user_id, is_adm)
        )
        if cur_adm.rowcount > 0:
            changed = True

        cur3 = await db.execute(
            "UPDATE users SET registered_at = ? WHERE user_id = ? AND (registered_at IS NULL OR registered_at = '')",
            (datetime.now().strftime("%Y-%m-%d %H:%M"), user_id)
        )
        if cur3.rowcount > 0:
            changed = True

        if changed:
            await db.commit()
            _cache_del(f"user:{user_id}", f"is_admin:{user_id}")
        return False

    _cache_del(f"user:{user_id}", f"exists:{user_id}", f"is_admin:{user_id}")
    return True


async def get_user(user_id: int):
    key = f"user:{user_id}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    db = await get_db()
    async with db.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)) as c:
        row = await c.fetchone()
    if row:
        _cache_set(key, row, CACHE_TTL_SHORT)
    return row


async def get_user_by_username(username: str):
    username = username.lstrip("@").lower()
    db = await get_db()
    async with db.execute("SELECT * FROM users WHERE LOWER(username) = ?", (username,)) as c:
        return await c.fetchone()


async def user_exists(user_id: int) -> bool:
    key = f"exists:{user_id}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    result = (await get_user(user_id)) is not None
    _cache_set(key, result, CACHE_TTL_LONG)
    return result


async def get_balance(user_id: int) -> int:
    key = f"balance:{user_id}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    db = await get_db()
    async with db.execute("SELECT balance FROM users WHERE user_id = ?", (user_id,)) as c:
        row = await c.fetchone()
        result = row["balance"] if row else 0
    _cache_set(key, result, CACHE_TTL_SHORT)
    return result


async def add_balance(user_id: int, amount: int) -> None:
    db = await get_db()
    await db.execute("UPDATE users SET balance = balance + ? WHERE user_id = ?", (amount, user_id))
    await db.commit()
    _cache_del(f"balance:{user_id}", f"user:{user_id}")


async def deduct_balance(user_id: int, amount: int) -> bool:
    if amount <= 0:
        return False
    db = await get_db()
    cur = await db.execute(
        "UPDATE users SET balance = balance - ? WHERE user_id = ? AND balance >= ?",
        (amount, user_id, amount)
    )
    await db.commit()
    _cache_del(f"balance:{user_id}", f"user:{user_id}")
    return cur.rowcount > 0


async def set_admin(user_id: int, val: int = 1) -> None:
    db = await get_db()
    await db.execute("UPDATE users SET is_admin = ? WHERE user_id = ?", (val, user_id))
    await db.commit()
    _cache_del(f"is_admin:{user_id}", f"user:{user_id}")


async def is_admin(user_id: int) -> bool:
    if user_id in ADMIN_IDS:
        return True
    key = f"is_admin:{user_id}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    db = await get_db()
    async with db.execute("SELECT is_admin FROM users WHERE user_id = ?", (user_id,)) as c:
        row = await c.fetchone()
        result = bool(row and row["is_admin"])
    _cache_set(key, result, CACHE_TTL_LONG)
    return result


async def is_banned(user_id: int) -> bool:
    db = await get_db()
    async with db.execute("SELECT is_banned FROM users WHERE user_id = ?", (user_id,)) as c:
        row = await c.fetchone()
        return bool(row and row["is_banned"])


async def ban_user(user_id: int, reason: str = "") -> None:
    db = await get_db()
    await db.execute(
        "UPDATE users SET is_banned = 1, ban_reason = ? WHERE user_id = ?",
        (reason[:500], user_id)
    )
    await db.commit()
    _cache_del(f"is_banned:{user_id}", f"user:{user_id}")


async def unban_user(user_id: int) -> None:
    db = await get_db()
    await db.execute("UPDATE users SET is_banned = 0, ban_reason = '' WHERE user_id = ?", (user_id,))
    await db.commit()
    _cache_del(f"is_banned:{user_id}", f"user:{user_id}")


async def get_all_users(include_banned: bool = True) -> list:
    db = await get_db()
    order = "ORDER BY registered_at DESC, user_id DESC"
    if include_banned:
        async with db.execute(f"SELECT * FROM users {order}") as c:
            return await c.fetchall()
    async with db.execute(f"SELECT * FROM users WHERE is_banned = 0 {order}") as c:
        return await c.fetchall()


async def search_users(query: str, limit: int = 50) -> list:
    query = (query or "").strip()
    if not query:
        return []

    db = await get_db()
    order = "ORDER BY registered_at DESC, user_id DESC"

    if query.lstrip("-").isdigit():
        async with db.execute(f"SELECT * FROM users WHERE user_id = ? {order}", (int(query),)) as c:
            rows = await c.fetchall()
        if rows:
            return rows

    date_q = query
    if len(date_q) >= 8 and date_q.count(".") == 2:
        try:
            d, m, y = date_q.split(".")
            date_q = f"{y}-{m}-{d}"
        except ValueError:
            pass
    if len(date_q) in (7, 10) and date_q[4:5] == "-" and date_q[:4].isdigit():
        async with db.execute(
            f"SELECT * FROM users WHERE registered_at LIKE ? {order}", (f"{date_q}%",)
        ) as c:
            rows = await c.fetchall()
        if rows:
            return rows

    like = query.lstrip("@").lower()
    if like:
        async with db.execute(
            f"SELECT * FROM users WHERE LOWER(username) LIKE ? {order}",
            (f"%{like}%",),
        ) as c:
            return await c.fetchall()
    return []


async def get_users_count() -> int:
    db = await get_db()
    async with db.execute("SELECT COUNT(*) as cnt FROM users") as c:
        row = await c.fetchone()
        return row["cnt"] if row else 0


async def has_used_trial(user_id: int) -> bool:
    key = f"trial:{user_id}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    db = await get_db()
    async with db.execute("SELECT trial_used FROM users WHERE user_id = ?", (user_id,)) as c:
        row = await c.fetchone()
        result = bool(row and row["trial_used"])
    _cache_set(key, result, CACHE_TTL_LONG)
    return result


async def mark_trial_used(user_id: int) -> bool:
    db = await get_db()
    cur = await db.execute(
        "UPDATE users SET trial_used = 1 WHERE user_id = ? AND trial_used = 0",
        (user_id,)
    )
    await db.commit()
    _cache_del(f"trial:{user_id}", f"user:{user_id}")
    return cur.rowcount > 0


async def unmark_trial(user_id: int) -> None:
    db = await get_db()
    await db.execute("UPDATE users SET trial_used = 0 WHERE user_id = ?", (user_id,))
    await db.commit()
    _cache_del(f"trial:{user_id}", f"user:{user_id}")


async def register_referral(referrer_id: int, new_user_id: int) -> bool:
    if not referrer_id or referrer_id == new_user_id or referrer_id <= 0:
        return False

    if not await user_exists(referrer_id):
        return False

    db = await get_db()
    cur = await db.execute(
        "UPDATE users SET referred_by = ? WHERE user_id = ? AND referred_by = 0",
        (referrer_id, new_user_id)
    )
    await db.commit()

    if cur.rowcount == 0:
        return False

    _cache_del(f"user:{new_user_id}")

    await add_balance(referrer_id, REFERRAL_BONUS)
    await add_transaction(
        referrer_id, REFERRAL_BONUS, "referral",
        f"Реферальный бонус за приглашённого пользователя {new_user_id}"
    )

    return True


async def get_referral_stats(user_id: int) -> dict:
    db = await get_db()

    async with db.execute(
        "SELECT COUNT(*) as cnt FROM users WHERE referred_by = ?", (user_id,)
    ) as c:
        row = await c.fetchone()
        invited = row["cnt"] if row else 0

    async with db.execute(
        "SELECT COALESCE(SUM(amount), 0) as s FROM transactions WHERE user_id = ? AND type = 'referral'",
        (user_id,)
    ) as c:
        row = await c.fetchone()
        earned = row["s"] if row else 0

    return {"invited_count": invited, "earned": earned}


async def get_user_keys_count(user_id: int) -> int:
    db = await get_db()
    async with db.execute(
        "SELECT COUNT(*) as cnt FROM keys WHERE user_id = ? AND is_active = 1",
        (user_id,)
    ) as c:
        row = await c.fetchone()
        return row["cnt"] if row else 0


async def create_key(
    user_id: int,
    tariff: str,
    days: int = 0,
    hours: int = 0,
    max_users: int = 0,
    source: str = "purchased",
    price_paid: int = 0,
) -> str:
    from xui_api import create_vpn_user, delete_vpn_user

    async with _get_key_creation_lock(user_id):
        if days > 0:
            total_hours = days * 24
        elif hours > 0:
            total_hours = hours
        else:
            raise ValueError("days or hours required")

        keys_count = await get_user_keys_count(user_id)
        admin_check = await is_admin(user_id)
        if not admin_check and keys_count >= MAX_KEYS_PER_USER:
            raise ValueError(f"Лимит ключей ({MAX_KEYS_PER_USER}). Дождитесь истечения старых.")

        # Ссылка подписки (содержит обе локации) + email клиента в панели
        sub_link, client_ref = await create_vpn_user(user_id, total_hours, tariff)

        now = datetime.now()
        expires = now + timedelta(hours=total_hours)
        db = await get_db()

        try:
            await db.execute(
                "INSERT INTO keys "
                "(user_id, key_value, tariff, proxy_address, created_at, expires_at, is_duo, max_users, is_active, auto_renew, key_source, price_paid) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?, ?)",
                (
                    user_id, sub_link, tariff, client_ref,
                    now.strftime("%Y-%m-%d %H:%M"),
                    expires.strftime("%Y-%m-%d %H:%M"),
                    1 if max_users >= 2 else 0,
                    max_users,
                    source,
                    price_paid,
                )
            )
            await db.commit()
        except Exception:
            logger.exception("create_key: db error, rolling back vpn client")
            try:
                await delete_vpn_user(client_ref)
            except Exception:
                logger.exception(f"create_key: failed to rollback {client_ref}")
            raise

        _cache_del(f"user_keys:{user_id}")
        return sub_link


async def set_auto_renew(key_id: int, enabled: bool) -> None:
    db = await get_db()
    await db.execute("UPDATE keys SET auto_renew = ? WHERE id = ?", (1 if enabled else 0, key_id))
    await db.commit()


async def set_user_auto_renew_all(user_id: int, enabled: bool) -> int:
    db = await get_db()
    cur = await db.execute(
        "UPDATE keys SET auto_renew = ? WHERE user_id = ? AND is_active = 1",
        (1 if enabled else 0, user_id)
    )
    await db.commit()
    _cache_del(f"user_keys:{user_id}")
    return cur.rowcount


async def deactivate_key(key_id: int) -> None:
    from xui_api import delete_vpn_user

    db = await get_db()
    async with db.execute("SELECT proxy_address, user_id FROM keys WHERE id = ?", (key_id,)) as c:
        row = await c.fetchone()

    if row and row["proxy_address"]:
        try:
            await delete_vpn_user(row["proxy_address"])
        except Exception:
            logger.exception(f"deactivate_key: failed {row['proxy_address']}")

    await db.execute("UPDATE keys SET is_active = 0 WHERE id = ?", (key_id,))
    await db.commit()

    if row:
        _cache_del(f"user_keys:{row['user_id']}")


async def get_user_active_keys(user_id: int) -> list:
    key = f"user_keys:{user_id}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    db = await get_db()
    async with db.execute(
        "SELECT id, key_value, tariff, created_at, expires_at, is_duo, max_users, proxy_address, auto_renew, key_source, price_paid "
        "FROM keys WHERE user_id = ? AND is_active = 1 ORDER BY id DESC",
        (user_id,)
    ) as c:
        result = await c.fetchall()
    _cache_set(key, result, CACHE_TTL_SHORT)
    return result


async def get_user_active_keys_with_id(user_id: int) -> list:
    db = await get_db()
    async with db.execute(
        "SELECT id, key_value, tariff, created_at, expires_at, is_duo, max_users, key_source, price_paid, auto_renew "
        "FROM keys WHERE user_id = ? AND is_active = 1 ORDER BY id DESC",
        (user_id,)
    ) as c:
        return await c.fetchall()


async def get_key_by_id(key_id: int):
    db = await get_db()
    async with db.execute("SELECT * FROM keys WHERE id = ?", (key_id,)) as c:
        return await c.fetchone()


async def get_all_keys_count() -> int:
    db = await get_db()
    async with db.execute("SELECT COUNT(*) as cnt FROM keys WHERE is_active = 1") as c:
        row = await c.fetchone()
        return row["cnt"] if row else 0


async def extend_key(key_id: int, days: int) -> str:
    from xui_api import update_vpn_user_expiry

    db = await get_db()
    async with db.execute("SELECT expires_at, user_id, proxy_address FROM keys WHERE id = ?", (key_id,)) as c:
        row = await c.fetchone()
    if not row:
        raise ValueError("Key not found")

    try:
        exp = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M")
    except ValueError:
        exp = datetime.now()

    if exp < datetime.now():
        exp = datetime.now()

    new_exp = exp + timedelta(days=days)
    new_exp_str = new_exp.strftime("%Y-%m-%d %H:%M")

    if row["proxy_address"]:
        try:
            expiry_ms = int(new_exp.timestamp() * 1000)
            await update_vpn_user_expiry(row["proxy_address"], expiry_ms)
        except Exception as e:
            logger.exception(f"extend_key: sync 3x-ui failed {row['proxy_address']}: {e}")

    await db.execute(
        "UPDATE keys SET expires_at = ?, notified_expiry = 0, is_active = 1 WHERE id = ?",
        (new_exp_str, key_id)
    )
    await db.commit()
    _cache_del(f"user_keys:{row['user_id']}")
    return new_exp_str


async def get_keys_for_auto_renew() -> list:
    db = await get_db()
    now = datetime.now()
    threshold = (now + timedelta(hours=24)).strftime("%Y-%m-%d %H:%M")
    now_str = now.strftime("%Y-%m-%d %H:%M")
    async with db.execute(
        "SELECT id, user_id, tariff, expires_at FROM keys "
        "WHERE is_active = 1 AND auto_renew = 1 AND expires_at > ? AND expires_at <= ?",
        (now_str, threshold)
    ) as c:
        return await c.fetchall()


async def get_expired_active_keys() -> list:
    db = await get_db()
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    async with db.execute(
        "SELECT id, user_id, proxy_address FROM keys WHERE is_active = 1 AND expires_at <= ?",
        (now,)
    ) as c:
        return await c.fetchall()


async def get_keys_expiring_soon(hours: int = 24) -> list:
    db = await get_db()
    now = datetime.now()
    threshold = (now + timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M")
    now_str = now.strftime("%Y-%m-%d %H:%M")
    async with db.execute(
        "SELECT id, user_id, tariff, expires_at FROM keys "
        "WHERE is_active = 1 AND expires_at > ? AND expires_at <= ? AND notified_expiry = 0",
        (now_str, threshold)
    ) as c:
        return await c.fetchall()


async def mark_key_notified(key_id: int) -> None:
    db = await get_db()
    await db.execute("UPDATE keys SET notified_expiry = 1 WHERE id = ?", (key_id,))
    await db.commit()


async def cleanup_old_inactive_keys(days: int = 2) -> int:
    db = await get_db()
    threshold = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M")

    async with db.execute(
        "SELECT id, user_id FROM keys WHERE is_active = 0 AND expires_at <= ?",
        (threshold,)
    ) as c:
        rows = await c.fetchall()

    if not rows:
        return 0

    ids = [r["id"] for r in rows]
    user_ids = {r["user_id"] for r in rows}
    placeholders = ",".join("?" * len(ids))

    await db.execute(f"DELETE FROM keys WHERE id IN ({placeholders})", ids)
    await db.commit()

    for uid in user_ids:
        _cache_del(f"user_keys:{uid}")

    return len(ids)


async def create_promo(
    code: str, discount: int = 0, bonus_days: int = 0,
    discount_percent: int = 0, max_uses: int = -1,
    created_by: int = 0, expires_at: str = ""
) -> None:
    db = await get_db()
    await db.execute(
        "INSERT INTO promos "
        "(code, discount, bonus_days, discount_percent, max_uses, created_by, created_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            code.upper(), discount, bonus_days, discount_percent,
            max_uses, created_by,
            datetime.now().strftime("%Y-%m-%d %H:%M"), expires_at
        )
    )
    await db.commit()
    _cache_del(f"promo:{code.upper()}")


async def get_promo(code: str):
    key = f"promo:{code.upper()}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    db = await get_db()
    async with db.execute("SELECT * FROM promos WHERE code = ?", (code.upper(),)) as c:
        row = await c.fetchone()
    if row:
        _cache_set(key, row, CACHE_TTL_SHORT)
    return row


async def use_promo(user_id: int, code: str):
    code = code.upper()
    now = datetime.now()
    db = await get_db()

    async with db.execute("SELECT * FROM promos WHERE code = ?", (code,)) as c:
        promo = await c.fetchone()
    if not promo:
        return None

    if promo["expires_at"]:
        try:
            exp = datetime.strptime(promo["expires_at"], "%Y-%m-%d %H:%M")
            if now > exp:
                return None
        except ValueError:
            pass

    try:
        await db.execute(
            "INSERT INTO promo_uses (user_id, promo_code, used_at) VALUES (?, ?, ?)",
            (user_id, code, now.strftime("%Y-%m-%d %H:%M"))
        )
    except aiosqlite.IntegrityError:
        return None

    cur = await db.execute(
        "UPDATE promos SET used_count = used_count + 1 "
        "WHERE code = ? AND (max_uses = -1 OR used_count < max_uses)",
        (code,)
    )
    if cur.rowcount == 0:
        await db.rollback()
        return None

    await db.commit()
    _cache_del(f"promo:{code}")
    return promo


async def apply_promo_bonus_days(user_id: int, days: int):
    if days <= 0:
        return None
    db = await get_db()
    async with db.execute(
        "SELECT id, expires_at FROM keys WHERE user_id = ? AND is_active = 1 ORDER BY id DESC LIMIT 1",
        (user_id,)
    ) as c:
        row = await c.fetchone()

    if row:
        new_exp_str = await extend_key(row["id"], days)
        return "extended", new_exp_str

    key = await create_key(user_id, "Бонус по промокоду", hours=days * 24, source="promo")
    return "created", key


async def get_all_promos() -> list:
    db = await get_db()
    async with db.execute("SELECT * FROM promos ORDER BY id DESC") as c:
        return await c.fetchall()


async def delete_promo(code: str) -> bool:
    code = code.upper()
    db = await get_db()
    cur = await db.execute("DELETE FROM promos WHERE code = ?", (code,))
    await db.execute("DELETE FROM promo_uses WHERE promo_code = ?", (code,))
    await db.execute("DELETE FROM promo_posts WHERE promo_code = ?", (code,))
    await db.commit()
    _cache_del(f"promo:{code}")
    return cur.rowcount > 0


async def add_promo_post(promo_code: str, chat_id: int, message_id: int) -> None:
    db = await get_db()
    await db.execute(
        "INSERT INTO promo_posts (promo_code, chat_id, message_id, created_at) VALUES (?, ?, ?, ?)",
        (promo_code.upper(), chat_id, message_id, datetime.now().strftime("%Y-%m-%d %H:%M"))
    )
    await db.commit()


async def get_promo_posts(promo_code: str) -> list:
    db = await get_db()
    async with db.execute(
        "SELECT chat_id, message_id FROM promo_posts WHERE promo_code = ?",
        (promo_code.upper(),)
    ) as c:
        return await c.fetchall()


async def delete_promo_posts(promo_code: str) -> None:
    db = await get_db()
    await db.execute("DELETE FROM promo_posts WHERE promo_code = ?", (promo_code.upper(),))
    await db.commit()


async def get_exhausted_promos() -> list:
    db = await get_db()
    async with db.execute("""
        SELECT DISTINCT p.code, p.discount, p.bonus_days, p.discount_percent, p.max_uses, p.used_count
        FROM promos p INNER JOIN promo_posts pp ON pp.promo_code = p.code
        WHERE p.max_uses != -1 AND p.used_count >= p.max_uses
    """) as c:
        return await c.fetchall()


async def add_transaction(user_id: int, amount: int, tx_type: str, desc: str) -> None:
    db = await get_db()
    await db.execute(
        "INSERT INTO transactions (user_id, amount, type, description, created_at) VALUES (?, ?, ?, ?, ?)",
        (user_id, amount, tx_type, desc, datetime.now().strftime("%Y-%m-%d %H:%M"))
    )
    await db.commit()


async def get_user_transactions(user_id: int, limit: int = 5, offset: int = 0) -> list:
    db = await get_db()
    async with db.execute(
        "SELECT amount, type, description, created_at FROM transactions "
        "WHERE user_id = ? ORDER BY id DESC LIMIT ? OFFSET ?",
        (user_id, limit, offset)
    ) as c:
        return await c.fetchall()


async def get_user_transactions_count(user_id: int) -> int:
    db = await get_db()
    async with db.execute("SELECT COUNT(*) as cnt FROM transactions WHERE user_id = ?", (user_id,)) as c:
        row = await c.fetchone()
        return row["cnt"] if row else 0


async def create_broadcast(
    photo_id: str, text: str, duration_days: int,
    interval_hours: int, created_by: int
) -> int:
    now = datetime.now()
    db = await get_db()
    cur = await db.execute(
        "INSERT INTO broadcasts "
        "(photo_id, text, duration_days, interval_hours, started_at, next_send, is_active, created_by) "
        "VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
        (photo_id, text, duration_days, interval_hours,
         now.strftime("%Y-%m-%d %H:%M"), now.strftime("%Y-%m-%d %H:%M"), created_by)
    )
    await db.commit()
    return cur.lastrowid


async def get_active_broadcasts() -> list:
    db = await get_db()
    async with db.execute("SELECT * FROM broadcasts WHERE is_active = 1 ORDER BY id DESC") as c:
        return await c.fetchall()


async def update_broadcast_next(broadcast_id: int, next_send: str) -> None:
    db = await get_db()
    await db.execute("UPDATE broadcasts SET next_send = ? WHERE id = ?", (next_send, broadcast_id))
    await db.commit()


async def stop_broadcast(broadcast_id: int) -> bool:
    db = await get_db()
    cur = await db.execute("UPDATE broadcasts SET is_active = 0 WHERE id = ?", (broadcast_id,))
    await db.commit()
    return cur.rowcount > 0


async def is_feature_enabled(feature: str) -> bool:
    if feature not in _FEATURE_DEFAULTS:
        return True
    key = f"feature:{feature}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    db = await get_db()
    async with db.execute("SELECT value FROM settings WHERE key = ?", (feature,)) as c:
        row = await c.fetchone()
        result = bool(row["value"]) if row else _FEATURE_DEFAULTS.get(feature, True)
    _cache_set(key, result, CACHE_TTL_LONG)
    return result


async def set_feature(feature: str, enabled: bool) -> None:
    if feature not in _FEATURE_DEFAULTS:
        return
    db = await get_db()
    await db.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (feature, 1 if enabled else 0)
    )
    await db.commit()
    _cache_del(f"feature:{feature}")


async def get_all_features() -> dict:
    db = await get_db()
    result = {}
    async with db.execute("SELECT key, value FROM settings") as c:
        rows = await c.fetchall()
        for row in rows:
            if row["key"] in _FEATURE_DEFAULTS:
                result[row["key"]] = bool(row["value"])
    for feature, default in _FEATURE_DEFAULTS.items():
        if feature not in result:
            result[feature] = default
    return result


async def is_section_enabled(section: str) -> bool:
    if section == "topup":
        return await is_feature_enabled("profile") and await is_feature_enabled("topup")
    return await is_feature_enabled(section)


async def get_revenue_stats() -> dict:
    db = await get_db()
    now = datetime.now()
    today = now.strftime("%Y-%m-%d")
    week_ago = (now - timedelta(days=7)).strftime("%Y-%m-%d %H:%M")
    month_ago = (now - timedelta(days=30)).strftime("%Y-%m-%d %H:%M")

    async with db.execute(
        "SELECT COALESCE(SUM(amount), 0) as s FROM transactions WHERE type = 'topup' AND created_at LIKE ?",
        (f"{today}%",)
    ) as c:
        row = await c.fetchone()
        today_rev = row["s"] if row else 0

    async with db.execute(
        "SELECT COALESCE(SUM(amount), 0) as s FROM transactions WHERE type = 'topup' AND created_at >= ?",
        (week_ago,)
    ) as c:
        row = await c.fetchone()
        week_rev = row["s"] if row else 0

    async with db.execute(
        "SELECT COALESCE(SUM(amount), 0) as s FROM transactions WHERE type = 'topup' AND created_at >= ?",
        (month_ago,)
    ) as c:
        row = await c.fetchone()
        month_rev = row["s"] if row else 0

    async with db.execute(
        "SELECT COALESCE(SUM(amount), 0) as s FROM transactions WHERE type = 'topup'"
    ) as c:
        row = await c.fetchone()
        total_rev = row["s"] if row else 0

    return {"today": today_rev, "week": week_rev, "month": month_rev, "total": total_rev}


async def get_tariff_stats() -> list:
    db = await get_db()
    async with db.execute("""
        SELECT tariff, COUNT(*) as cnt FROM keys
        WHERE tariff NOT LIKE '%Подарок%' AND tariff NOT LIKE '%Бонус%'
        AND tariff NOT LIKE '%Реф%' AND tariff NOT LIKE '%Пробный%'
        GROUP BY tariff ORDER BY cnt DESC LIMIT 5
    """) as c:
        return await c.fetchall()


async def get_funnel_stats() -> dict:
    db = await get_db()

    async with db.execute("SELECT COUNT(*) as cnt FROM users") as c:
        row = await c.fetchone()
        total = row["cnt"] if row else 0

    async with db.execute("SELECT COUNT(*) as cnt FROM users WHERE trial_used = 1") as c:
        row = await c.fetchone()
        trial = row["cnt"] if row else 0

    async with db.execute(
        "SELECT COUNT(DISTINCT user_id) as cnt FROM transactions WHERE type IN ('purchase', 'purchase_multi')"
    ) as c:
        row = await c.fetchone()
        paid = row["cnt"] if row else 0

    conversion = round(paid / total * 100, 1) if total > 0 else 0
    return {"total": total, "trial": trial, "paid": paid, "conversion": conversion}


async def get_user_purchase_summary(user_id: int) -> dict:
    db = await get_db()
    async with db.execute(
        "SELECT COUNT(*) as cnt, COALESCE(SUM(amount), 0) as s FROM transactions "
        "WHERE user_id = ? AND amount < 0",
        (user_id,)
    ) as c:
        row = await c.fetchone()
        return {"count": row["cnt"] if row else 0, "spent": abs(row["s"]) if row else 0}


async def create_payment_record(
    payment_id: str, user_id: int, amount: int,
    chat_id: int = 0, message_id: int = 0
) -> None:
    db = await get_db()
    await db.execute(
        "INSERT INTO payments (payment_id, user_id, amount, status, created_at, chat_id, message_id) "
        "VALUES (?, ?, ?, 'pending', ?, ?, ?)",
        (payment_id, user_id, amount, datetime.now().strftime("%Y-%m-%d %H:%M"), chat_id, message_id)
    )
    await db.commit()


async def get_payment_by_id(payment_id: str):
    db = await get_db()
    async with db.execute("SELECT * FROM payments WHERE payment_id = ?", (payment_id,)) as c:
        return await c.fetchone()


async def get_pending_payments(limit: int = 100) -> list:
    db = await get_db()
    threshold = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M")
    async with db.execute(
        "SELECT * FROM payments WHERE status IN ('pending', 'expired') AND created_at >= ? "
        "ORDER BY id DESC LIMIT ?",
        (threshold, limit)
    ) as c:
        return await c.fetchall()


async def get_stale_pending_payments(minutes: int = 10, limit: int = 100) -> list:
    db = await get_db()
    threshold = (datetime.now() - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M")
    async with db.execute(
        "SELECT * FROM payments WHERE status = 'pending' AND created_at <= ? "
        "ORDER BY id DESC LIMIT ?",
        (threshold, limit)
    ) as c:
        return await c.fetchall()


async def mark_payment_expired(payment_id: str) -> bool:
    db = await get_db()
    cur = await db.execute(
        "UPDATE payments SET status = 'expired' WHERE payment_id = ? AND status = 'pending'",
        (payment_id,)
    )
    await db.commit()
    return cur.rowcount > 0


async def mark_payment_completed(payment_id: str) -> bool:
    db = await get_db()
    cur = await db.execute(
        "UPDATE payments SET status = 'succeeded', completed_at = ? "
        "WHERE payment_id = ? AND status IN ('pending', 'expired')",
        (datetime.now().strftime("%Y-%m-%d %H:%M"), payment_id)
    )
    await db.commit()
    return cur.rowcount > 0


async def mark_payment_canceled(payment_id: str) -> None:
    db = await get_db()
    await db.execute(
        "UPDATE payments SET status = 'canceled' WHERE payment_id = ? AND status = 'pending'",
        (payment_id,)
    )
    await db.commit()


async def cleanup_old_pending_payments(hours: int = 48) -> int:
    db = await get_db()
    threshold = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M")
    cur = await db.execute(
        "UPDATE payments SET status = 'canceled' WHERE status IN ('pending', 'expired') AND created_at < ?",
        (threshold,)
    )
    await db.commit()
    return cur.rowcount


async def optimize_db() -> dict:
    db = await get_db()
    result = {"checkpointed": 0, "vacuumed": False}

    try:
        cur = await db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        row = await cur.fetchone()
        result["checkpointed"] = row[0] if row else 0
    except Exception:
        logger.exception("optimize_db: wal_checkpoint failed")

    try:
        await db.execute("PRAGMA optimize")
    except Exception:
        logger.exception("optimize_db: PRAGMA optimize failed")

    try:
        cur = await db.execute("PRAGMA freelist_count")
        row = await cur.fetchone()
        freelist = row[0] if row else 0
        if freelist > 5000:
            await db.execute("VACUUM")
            result["vacuumed"] = True
    except Exception:
        logger.exception("optimize_db: VACUUM failed")

    return result