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

DB_PATH = os.getenv("DB_PATH", "").strip() or "data/flowvpn.db"

XUI_HOST     = os.getenv("XUI_HOST", "")
XUI_USERNAME = os.getenv("XUI_USERNAME", "")
XUI_PASSWORD = os.getenv("XUI_PASSWORD", "")
XUI_SUB_URL  = os.getenv("XUI_SUB_URL", "https://sub.flowvpn.su:2053/3o3ntto7rlvdmgtv")

SUSPICIOUS_NEW_IP_THRESHOLD = 5

WEBAPP_PORT = int(os.getenv("PORT") or os.getenv("WEBAPP_PORT") or "3000")
_raw_miniapp = os.getenv("MINIAPP_URL", "")
MINIAPP_URL = _raw_miniapp if _raw_miniapp.startswith("https://") else f"https://{_raw_miniapp}" if _raw_miniapp else ""

BOT_STATUS_ON_MESSAGE  = "Бот снова активен и готов к работе! Приятного использования FlowVPN."
BOT_STATUS_OFF_MESSAGE = "Бот временно отключён на технические работы. Мы скоро вернёмся, приносим извинения за неудобства."