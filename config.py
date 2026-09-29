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

XUI_HOST       = os.getenv("XUI_HOST", "")
XUI_USERNAME   = os.getenv("XUI_USERNAME", "")
XUI_PASSWORD   = os.getenv("XUI_PASSWORD", "")
XUI_INBOUND_ID = int(os.getenv("XUI_INBOUND_ID", ""))

XUI_SERVER_ADDRESS = os.getenv("XUI_SERVER_ADDRESS", "")
XUI_SERVER_PORT    = int(os.getenv("XUI_SERVER_PORT", ""))
XUI_PUBLIC_KEY     = os.getenv("XUI_PUBLIC_KEY", "")
XUI_SHORT_ID       = os.getenv("XUI_SHORT_ID", "")
XUI_SNI            = os.getenv("XUI_SNI", "")
XUI_FINGERPRINT    = os.getenv("XUI_FINGERPRINT", "")

XUI_ENCRYPTION        = os.getenv("XUI_ENCRYPTION", "")
XUI_GRPC_SERVICE_NAME = os.getenv("XUI_GRPC_SERVICE_NAME", "")

SUSPICIOUS_NEW_IP_THRESHOLD = 5

WEBAPP_PORT = int(os.getenv("PORT", os.getenv("WEBAPP_PORT", "")))
MINIAPP_URL = os.getenv("MINIAPP_URL", "")

BOT_STATUS_ON_MESSAGE  = "Бот снова активен и готов к работе! Приятного использования FlowVPN."
BOT_STATUS_OFF_MESSAGE = "Бот временно отключён на технические работы. Мы скоро вернёмся, приносим извинения за неудобства."