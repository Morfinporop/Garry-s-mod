import asyncio
import logging
import re
import time
from pathlib import Path
from datetime import datetime, timedelta

import aiosqlite
from config import DB_PATH as MAIN_DB_PATH

logger = logging.getLogger(__name__)

DATA_DIR = Path(MAIN_DB_PATH).resolve().parent
try:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    logger.exception("extra_store: mkdir error %s", DATA_DIR)
DB_PATH = DATA_DIR / "extra.db"

_lock = asyncio.Lock()
_db: aiosqlite.Connection | None = None
_db_lock = asyncio.Lock()

_cache: dict = {}
_cache_ttl: dict = {}
CACHE_TTL_SHORT = 15
CACHE_TTL_LONG = 120

NOTIFICATIONS_MAX_AGE_DAYS = 30
NOTIFICATIONS_READ_MAX_AGE_DAYS = 7


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


def _cache_del_prefix(prefix: str):
    to_del = [k for k in list(_cache.keys()) if k.startswith(prefix)]
    for k in to_del:
        _cache.pop(k, None)
        _cache_ttl.pop(k, None)


async def cleanup_expired_cache() -> int:
    now = time.monotonic()
    expired = [k for k, exp in _cache_ttl.items() if now > exp]
    for k in expired:
        _cache.pop(k, None)
        _cache_ttl.pop(k, None)
    return len(expired)


async def _get_db() -> aiosqlite.Connection:
    global _db
    if _db is not None:
        return _db
    async with _db_lock:
        if _db is not None:
            return _db
        conn = await aiosqlite.connect(DB_PATH)
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA journal_mode=WAL")
        await conn.execute("PRAGMA busy_timeout=5000")
        await conn.execute("PRAGMA synchronous=NORMAL")
        _db = conn
        return _db


async def close() -> None:
    global _db
    async with _db_lock:
        if _db is not None:
            await _db.close()
            _db = None


async def init() -> None:
    db = await _get_db()

    await db.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            text TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)
    await db.execute("CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, id DESC)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(is_read, created_at)")

    await db.execute("""
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT,
            rating INTEGER NOT NULL,
            comment TEXT,
            is_anonymous INTEGER NOT NULL DEFAULT 0,
            is_hearted INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)
    await db.execute("CREATE INDEX IF NOT EXISTS idx_reviews_created ON reviews(created_at)")

    cur = await db.execute("PRAGMA table_info(reviews)")
    cols = [r[1] for r in await cur.fetchall()]
    if "is_hearted" not in cols:
        await db.execute("ALTER TABLE reviews ADD COLUMN is_hearted INTEGER NOT NULL DEFAULT 0")

    cur = await db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='banners'")
    row = await cur.fetchone()
    if row and "PRIMARY KEY" in (row[0] or "") and "placement TEXT PRIMARY KEY" in (row[0] or ""):
        await db.execute("ALTER TABLE banners RENAME TO banners_old")
        await db.execute("""
            CREATE TABLE banners (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                placement TEXT NOT NULL,
                image_url TEXT NOT NULL,
                link_url TEXT DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                expires_at TEXT
            )
        """)
        await db.execute("""
            INSERT INTO banners (placement, image_url, link_url, enabled, expires_at)
            SELECT placement, image_url, link_url, enabled, expires_at FROM banners_old
            WHERE image_url != ''
        """)
        await db.execute("DROP TABLE banners_old")
    else:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS banners (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                placement TEXT NOT NULL,
                image_url TEXT NOT NULL,
                link_url TEXT DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                expires_at TEXT
            )
        """)

    await db.execute("CREATE INDEX IF NOT EXISTS idx_banners_placement ON banners(placement, enabled)")
    await db.commit()


_HTML_TAG_RE = re.compile(r"<[^>]+>")


async def push_notification(user_id: int, text: str) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    plain = _HTML_TAG_RE.sub("", str(text)).strip()
    async with _lock:
        db = await _get_db()
        await db.execute(
            "INSERT INTO notifications (user_id, text, is_read, created_at) VALUES (?, ?, 0, ?)",
            (user_id, plain, now),
        )
        await db.commit()
    _cache_del_prefix(f"notif:{user_id}:")


async def get_notifications(user_id: int, limit: int = 30) -> list[dict]:
    key = f"notif:{user_id}:{limit}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    db = await _get_db()
    async with db.execute(
        "SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT ?",
        (user_id, limit),
    ) as c:
        rows = await c.fetchall()
    result = [dict(r) for r in rows]
    _cache_set(key, result, CACHE_TTL_SHORT)
    return result


async def get_unread_count(user_id: int) -> int:
    db = await _get_db()
    async with db.execute(
        "SELECT COUNT(*) as cnt FROM notifications WHERE user_id = ? AND is_read = 0",
        (user_id,),
    ) as c:
        row = await c.fetchone()
        return row["cnt"] if row else 0


async def mark_all_read(user_id: int) -> None:
    async with _lock:
        db = await _get_db()
        await db.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ?", (user_id,))
        await db.commit()
    _cache_del_prefix(f"notif:{user_id}:")


async def cleanup_old_notifications(
    max_age_days: int = NOTIFICATIONS_MAX_AGE_DAYS,
    read_max_age_days: int = NOTIFICATIONS_READ_MAX_AGE_DAYS,
) -> int:
    now = datetime.now()
    read_threshold = (now - timedelta(days=read_max_age_days)).strftime("%Y-%m-%d %H:%M")
    all_threshold = (now - timedelta(days=max_age_days)).strftime("%Y-%m-%d %H:%M")

    async with _lock:
        db = await _get_db()
        cur = await db.execute(
            "DELETE FROM notifications WHERE (is_read = 1 AND created_at <= ?) OR created_at <= ?",
            (read_threshold, all_threshold),
        )
        await db.commit()
        deleted = cur.rowcount

    if deleted:
        _cache_del_prefix("notif:")
    return deleted


async def add_review(user_id: int, username: str, rating: int, comment: str, is_anonymous: bool) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    async with _lock:
        db = await _get_db()
        await db.execute(
            "INSERT INTO reviews (user_id, username, rating, comment, is_anonymous, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, username, rating, comment, 1 if is_anonymous else 0, now),
        )
        await db.commit()
    _cache_del_prefix("reviews:")
    _cache_del("review_summary")
    _cache_del(f"has_reviewed:{user_id}")


async def has_reviewed(user_id: int) -> bool:
    key = f"has_reviewed:{user_id}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    db = await _get_db()
    async with db.execute("SELECT 1 FROM reviews WHERE user_id = ? LIMIT 1", (user_id,)) as c:
        row = await c.fetchone()
        result = row is not None
    _cache_set(key, result, CACHE_TTL_LONG)
    return result


async def list_reviews(limit: int = 200) -> list[dict]:
    key = f"reviews:{limit}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    db = await _get_db()
    async with db.execute("SELECT * FROM reviews ORDER BY id DESC LIMIT ?", (limit,)) as c:
        rows = await c.fetchall()
    result = [dict(r) for r in rows]
    _cache_set(key, result, CACHE_TTL_LONG)
    return result


async def review_summary() -> dict:
    key = "review_summary"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    db = await _get_db()
    async with db.execute("SELECT COUNT(*), AVG(rating) FROM reviews") as c:
        row = await c.fetchone()
        count = row[0] or 0
        avg = round(row[1], 1) if row[1] else 0.0
        result = {"count": count, "average": avg}
    _cache_set(key, result, CACHE_TTL_LONG)
    return result


async def delete_review(review_id: int) -> bool:
    async with _lock:
        db = await _get_db()
        async with db.execute("SELECT user_id FROM reviews WHERE id = ?", (review_id,)) as c:
            row = await c.fetchone()
        if not row:
            return False
        author_id = row["user_id"]
        await db.execute("DELETE FROM reviews WHERE id = ?", (review_id,))
        await db.commit()

    _cache_del_prefix("reviews:")
    _cache_del("review_summary")
    _cache_del(f"has_reviewed:{author_id}")
    return True


async def set_review_heart(review_id: int, hearted: bool) -> bool:
    async with _lock:
        db = await _get_db()
        cur = await db.execute(
            "UPDATE reviews SET is_hearted = ? WHERE id = ?",
            (1 if hearted else 0, review_id),
        )
        await db.commit()
        updated = cur.rowcount > 0

    if updated:
        _cache_del_prefix("reviews:")
    return updated


def _parse_banner_expiry(expires_at: str | None) -> datetime | None:
    if not expires_at:
        return None
    expires_at = expires_at.strip()
    if not expires_at:
        return None

    try:
        return datetime.strptime(expires_at, "%Y-%m-%d %H:%M")
    except ValueError:
        pass

    try:
        d = datetime.strptime(expires_at, "%Y-%m-%d")
        return d.replace(hour=23, minute=59, second=59)
    except ValueError:
        return None


def _banner_expired(banner: dict | None) -> bool:
    if not banner:
        return False
    exp = _parse_banner_expiry(banner.get("expires_at"))
    if exp is None:
        return False
    return datetime.now() > exp


async def get_banners_for_placement(placement: str) -> list[dict]:
    key = f"banners:{placement}"
    cached = _cache_get(key)
    if cached is not None:
        return cached

    db = await _get_db()
    async with db.execute(
        "SELECT * FROM banners WHERE placement = ? AND enabled = 1 ORDER BY id DESC",
        (placement,)
    ) as c:
        rows = await c.fetchall()

    result = []
    for r in rows:
        d = dict(r)
        if not _banner_expired(d):
            result.append(d)

    _cache_set(key, result, CACHE_TTL_SHORT)
    return result


async def list_all_banners() -> list[dict]:
    db = await _get_db()
    async with db.execute("SELECT * FROM banners ORDER BY placement ASC, id DESC") as c:
        rows = await c.fetchall()
    return [dict(r) for r in rows]


async def add_banner(placement: str, image_url: str, link_url: str, enabled: bool, expires_at: str | None) -> int:
    async with _lock:
        db = await _get_db()
        cur = await db.execute("""
            INSERT INTO banners (placement, image_url, link_url, enabled, expires_at)
            VALUES (?, ?, ?, ?, ?)
        """, (placement, image_url, link_url, 1 if enabled else 0, expires_at))
        await db.commit()
    _cache_del(f"banners:{placement}")
    return cur.lastrowid


async def delete_banner_by_id(banner_id: int) -> bool:
    async with _lock:
        db = await _get_db()
        async with db.execute("SELECT placement FROM banners WHERE id = ?", (banner_id,)) as c:
            row = await c.fetchone()
        if not row:
            return False
        placement = row["placement"]
        await db.execute("DELETE FROM banners WHERE id = ?", (banner_id,))
        await db.commit()
    _cache_del(f"banners:{placement}")
    return True


async def toggle_banner_by_id(banner_id: int) -> dict | None:
    async with _lock:
        db = await _get_db()
        async with db.execute("SELECT * FROM banners WHERE id = ?", (banner_id,)) as c:
            row = await c.fetchone()
        if not row:
            return None
        new_state = 0 if row["enabled"] else 1
        await db.execute("UPDATE banners SET enabled = ? WHERE id = ?", (new_state, banner_id))
        await db.commit()
    placement = row["placement"]
    _cache_del(f"banners:{placement}")
    return {"id": banner_id, "enabled": bool(new_state)}


async def cleanup_expired_banners() -> int:
    db = await _get_db()
    async with db.execute(
        "SELECT id, placement, expires_at FROM banners WHERE expires_at IS NOT NULL AND expires_at != ''"
    ) as c:
        rows = await c.fetchall()

    now = datetime.now()
    to_delete = []
    affected_placements = set()
    for r in rows:
        exp = _parse_banner_expiry(r["expires_at"])
        if exp is not None and now > exp:
            to_delete.append(r["id"])
            affected_placements.add(r["placement"])

    if to_delete:
        async with _lock:
            db = await _get_db()
            placeholders = ",".join("?" * len(to_delete))
            await db.execute(f"DELETE FROM banners WHERE id IN ({placeholders})", to_delete)
            await db.commit()

        for p in affected_placements:
            _cache_del(f"banners:{p}")

    return len(to_delete)


async def run_maintenance() -> dict:
    expired_cache = await cleanup_expired_cache()
    old_notifications = await cleanup_old_notifications()
    expired_banners = await cleanup_expired_banners()

    optimize_ok = False
    try:
        db = await _get_db()
        await db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        await db.execute("PRAGMA optimize")
        optimize_ok = True
    except Exception:
        logger.exception("extra_store: opt failed")

    return {
        "expired_cache": expired_cache,
        "old_notifications": old_notifications,
        "expired_banners": expired_banners,
        "optimized": optimize_ok,
    }