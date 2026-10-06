import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

YOOKASSA_SHOP_ID    = os.getenv("YOOKASSA_SHOP_ID", "")
YOOKASSA_SECRET_KEY = os.getenv("YOOKASSA_SECRET_KEY", "")
YOOKASSA_RETURN_URL = "https://t.me/flowvpntelegram_bot"

MIN_TOPUP = 1
MAX_TOPUP = 100_000

PAYMENT_LINK_TTL_MINUTES = 10
INACTIVE_KEY_TTL_DAYS = 2

TARIFFS = {
    "1_month":   {"name": "Старт (1мес)",  "price": 50,  "days": 30},
    "12_months": {"name": "Профи (1год)",  "price": 990, "days": 365},
}

MULTI_TARIFFS = {
    "duo":  {"name": "DUO подписка",  "title": "DUO",  "price": 75,  "days": 30, "max_users": 2},
    "trio": {"name": "TRIO подписка", "title": "TRIO", "price": 125, "days": 30, "max_users": 3},
    "mix":  {"name": "MIX подписка",  "title": "MIX",  "price": 175, "days": 30, "max_users": 4},
}
MULTI_ORDER = ("duo", "trio", "mix")

TRIAL_DAYS        = 5
TRIAL_TARIFF      = "Пробный период"
TRIAL_CHANNEL_ID  = -1004431387303
TRIAL_CHANNEL_URL = "https://t.me/flowvpntelegram"

REFERRAL_BONUS = 2

ADMIN_IDS: list[int] = [
    7745681987,
    944385018,
]

DB_PATH = os.getenv("DB_PATH", "")

# ──────────────────────────────────────────────────────────────
# 3x-UI панель (новая версия с несколькими серверами/локациями)
# ──────────────────────────────────────────────────────────────
XUI_HOST       = os.getenv("XUI_HOST", "").strip()
XUI_USERNAME   = os.getenv("XUI_USERNAME", "")
XUI_PASSWORD   = os.getenv("XUI_PASSWORD", "")

# API-токен панели (Settings → Security → API Token).
# Если задан — логин/пароль не нужны.
XUI_TOKEN      = os.getenv("XUI_TOKEN", "").strip()

# Проверять TLS-сертификат панели (0 = не проверять, удобно для self-signed)
XUI_TLS_VERIFY = os.getenv("XUI_TLS_VERIFY", "0").strip().lower() in ("1", "true", "yes")


def _parse_inbound_ids(raw: str) -> list[int]:
    ids: list[int] = []
    for part in raw.replace(" ", "").split(","):
        if not part:
            continue
        try:
            value = int(part)
        except ValueError:
            continue
        if value > 0 and value not in ids:
            ids.append(value)
    return ids


# Локации (inbounds), в которые бот добавляет клиента при покупке.
# Обе сразу: например "1,2".
# Если оставить пустым — бот сам возьмёт ВСЕ inbound из панели
# (то есть все локации, которые там подключены).
XUI_INBOUND_IDS = _parse_inbound_ids(os.getenv("XUI_INBOUND_IDS", ""))

# ──────────────────────────────────────────────────────────────
# Ссылка подписки (sub-сервер 3x-ui)
# Итоговая ссылка: https://XUI_SUB_HOST:XUI_SUB_PORT/XUI_SUB_PATH/<subId клиента>
# ──────────────────────────────────────────────────────────────
XUI_SUB_HOST   = os.getenv("XUI_SUB_HOST", "sub.flowvpn.su").strip()
XUI_SUB_PATH   = os.getenv("XUI_SUB_PATH", "3o3ntto7rlvdmgtv").strip().strip("/")
XUI_SUB_SECURE = os.getenv("XUI_SUB_SECURE", "1").strip().lower() in ("1", "true", "yes")

try:
    XUI_SUB_PORT = int(os.getenv("XUI_SUB_PORT", "2053") or 2053)
except ValueError:
    XUI_SUB_PORT = 2053

SUSPICIOUS_NEW_IP_THRESHOLD = 5

try:
    WEBAPP_PORT = int(os.getenv("PORT", os.getenv("WEBAPP_PORT", "")) or 8000)
except ValueError:
    WEBAPP_PORT = 8000
MINIAPP_URL = os.getenv("MINIAPP_URL", "")

BOT_STATUS_ON_MESSAGE  = "Бот снова активен и готов к работе! Приятного использования FlowVPN."
BOT_STATUS_OFF_MESSAGE = "Бот временно отключён на технические работы. Мы скоро вернёмся, приносим извинения за неудобства."