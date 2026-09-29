import hashlib
import hmac
import json
import logging
import time
from urllib.parse import parse_qsl

logger = logging.getLogger(__name__)

INIT_DATA_MAX_AGE = 24 * 3600  # initData считаем валидным 24 часа


def validate_init_data(init_data: str, bot_token: str) -> tuple[dict | None, str | None]:
    """
    Проверяет подпись initData по алгоритму Telegram.
    Возвращает (data, None) при успехе или (None, reason) при отказе.
    """
    if not init_data or not bot_token:
        return None, "empty"

    bot_token = bot_token.strip()

    try:
        # keep_blank_values=True и strict_parsing=False — критично для ПК-версии Telegram!
        pairs = dict(parse_qsl(init_data, keep_blank_values=True, strict_parsing=False))
    except Exception:
        logger.exception("validate_init_data: ошибка разбора query-строки")
        return None, "parse_error"

    received_hash = pairs.pop("hash", None)
    if not received_hash:
        return None, "no_hash"

    data_check_string = "\n".join(
        f"{k}={v}" for k, v in sorted(pairs.items())
    )

    secret_key = hmac.new(
        b"WebAppData", bot_token.encode(), hashlib.sha256
    ).digest()
    computed_hash = hmac.new(
        secret_key, data_check_string.encode(), hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(computed_hash, received_hash):
        return None, "bad_signature"

    auth_date = pairs.get("auth_date")
    if auth_date:
        try:
            age = time.time() - int(auth_date)
            if age > INIT_DATA_MAX_AGE:
                return None, "expired"
        except ValueError:
            pass

    result = dict(pairs)
    if "user" in result:
        try:
            result["user"] = json.loads(result["user"])
        except json.JSONDecodeError:
            logger.warning("validate_init_data: не удалось распарсить поле user как JSON")
            return None, "bad_json"

    return result, None


def extract_user_id(validated: dict) -> int | None:
    user = validated.get("user")
    if isinstance(user, dict):
        return user.get("id")
    return None
